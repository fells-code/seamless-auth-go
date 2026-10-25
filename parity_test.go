package seamlessauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpstreamRedirectsAreNotFollowed(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
	}))
	t.Cleanup(elsewhere.Close)

	api := newFakeAPI(t)
	api.on("POST", "/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	})

	supplied := &http.Client{}
	for name, a := range map[string]*Adapter{
		"default client":  newTestAdapter(t, api),
		"supplied client": newTestAdapter(t, api, func(o *Options) { o.HTTPClient = supplied }),
	} {
		t.Run(name, func(t *testing.T) {
			r := do(t, a, "POST", "/login", `{"identifier":"a@b.test"}`)
			if r.status != http.StatusTemporaryRedirect || r.body["error"] != "upstream_error" {
				t.Fatalf("status %d body %v", r.status, r.body)
			}
			if reached.Load() != 0 {
				t.Fatal("followed the auth API's redirect")
			}
		})
	}
	if supplied.CheckRedirect != nil || supplied.Timeout != 0 {
		t.Fatal("changed the caller's own client")
	}
}

func TestUpstreamErrorsAreLoggedWithoutTheURL(t *testing.T) {
	api := newFakeAPI(t)
	var mu sync.Mutex
	var logs []string
	a := newTestAdapter(t, api, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logs = append(logs, fmt.Sprintf(format, args...))
		}
	})
	api.server.Close()

	r := do(t, a, "GET", "/magic-link/verify/secret-link-token?code=secret-code", "")

	if r.status != http.StatusBadGateway || r.body["error"] != "upstream_unavailable" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 {
		t.Fatal("the failure was not logged")
	}
	for _, line := range logs {
		if strings.Contains(line, "secret-link-token") || strings.Contains(line, "secret-code") || strings.Contains(line, api.server.URL) {
			t.Fatalf("logged the upstream URL: %s", line)
		}
	}
}

func jwksCalls(api *fakeAPI) int {
	return len(api.callsTo("GET", "/.well-known/jwks.json"))
}

func TestTheKeySetIsFetchedAgainOnceStale(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := apiToken(t, api, "u1", "access")
	verify := func() {
		t.Helper()
		if _, err := a.jwks.verifyAuthToken(context.Background(), token, api.server.URL, api.server.URL); err != nil {
			t.Fatal(err)
		}
	}

	verify()
	verify()
	if n := jwksCalls(api); n != 1 {
		t.Fatalf("%d fetches for a fresh key set", n)
	}

	a.jwks.mu.Lock()
	a.jwks.fetchedAt = time.Now().Add(-jwksMaxAge - time.Second)
	a.jwks.attemptedAt = a.jwks.fetchedAt
	a.jwks.mu.Unlock()
	verify()
	if n := jwksCalls(api); n != 2 {
		t.Fatalf("%d fetches after the key set went stale", n)
	}
}

func TestAStaleKeySetKeepsVerifyingWhileTheAPIIsDown(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := apiToken(t, api, "u1", "access")
	if _, err := a.jwks.verifyAuthToken(context.Background(), token, api.server.URL, api.server.URL); err != nil {
		t.Fatal(err)
	}

	api.server.Close()
	a.jwks.mu.Lock()
	a.jwks.fetchedAt = time.Now().Add(-jwksMaxAge - time.Second)
	a.jwks.attemptedAt = a.jwks.fetchedAt
	a.jwks.mu.Unlock()

	if _, err := a.jwks.verifyAuthToken(context.Background(), token, api.server.URL, api.server.URL); err != nil {
		t.Fatalf("a stale key set stopped verifying: %v", err)
	}
}

func TestAFailedKeySetFetchBacksOff(t *testing.T) {
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	cache := newJWKSCache(server.URL, server.Client(), func(string, ...any) {})

	for i := 0; i < 3; i++ {
		if _, err := cache.key(context.Background(), "k1"); err == nil {
			t.Fatal("found a key in a key set that failed to load")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d fetches inside the backoff", n)
	}

	cache.mu.Lock()
	cache.attemptedAt = time.Now().Add(-jwksFailureBackoff - time.Second)
	cache.mu.Unlock()
	_, _ = cache.key(context.Background(), "k1")
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d fetches after the backoff", n)
	}
}

func TestAnOversizedKeySetIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[],"padding":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSBytes)))
		_, _ = w.Write([]byte(`"}`))
	}))
	t.Cleanup(server.Close)
	cache := newJWKSCache(server.URL, server.Client(), func(string, ...any) {})

	if _, err := cache.key(context.Background(), "k1"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err %v", err)
	}
}

func TestATokenWithoutExpIsRefused(t *testing.T) {
	if err := checkTimes(map[string]any{"iat": json.Number("1")}, time.Now()); err == nil {
		t.Fatal("accepted a token with no exp")
	}
	token, err := signHS256(map[string]any{"sub": "u1"}, testSecret, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyHS256(token, testSecret); err == nil {
		t.Fatal("accepted a cookie with no exp")
	}
}

func TestLogoutClearsTheCookiesWhenTheCredentialIsRejected(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)

	for name, setup := range map[string]func(*http.Request){
		"altered access cookie": withCookie(&http.Cookie{Name: "seamless-access", Value: "a.b.c"}),
		"no cookie":             func(*http.Request) {},
	} {
		t.Run(name, func(t *testing.T) {
			r := do(t, a, "DELETE", "/logout", "", setup)
			if r.status != http.StatusUnauthorized {
				t.Fatalf("status %d", r.status)
			}
			for _, cookie := range []string{"seamless-access", "seamless-ephemeral", "seamless-refresh"} {
				if c := r.cookies[cookie]; c == nil || c.MaxAge >= 0 {
					t.Fatalf("%s not cleared", cookie)
				}
			}
		})
	}
	if len(api.callsTo("DELETE", "/logout")) != 0 {
		t.Fatal("logged out upstream without a credential")
	}
}

func TestACookieTransportPickNeverCarriesTokens(t *testing.T) {
	route := ManifestRoute{Body: &struct {
		Pick []string `json:"pick"`
	}{Pick: []string{"message", "token", "refreshToken"}}}

	body := cookieTransportBody(route, map[string]any{"message": "ok", "token": "t", "refreshToken": "r", "sub": "u1"})

	if got, _ := json.Marshal(body); string(got) != `{"message":"ok"}` {
		t.Fatalf("body %s", got)
	}
}

func TestCookieLifetimesAreCappedAt400Days(t *testing.T) {
	ttl, err := ttlSeconds(json.Number("99999999999"))
	if err != nil || ttl != maxCookieAge {
		t.Fatalf("ttl %d %v", ttl, err)
	}

	api := newFakeAPI(t)
	long := session(t, api, "u1")
	long["refreshTtl"] = "999999999"
	api.on("POST", "/totp/verify-login", respond(200, long))

	r := do(t, newTestAdapter(t, api), "POST", "/totp/verify-login", `{"code":"123456"}`,
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if c := r.cookies["seamless-refresh"]; c == nil || c.MaxAge != maxCookieAge {
		t.Fatalf("refresh cookie %+v", c)
	}
}

func TestNewRefusesAnAuthServerURLThatIsNotHTTP(t *testing.T) {
	for _, u := range []string{"ftp://auth.test", "auth.test", "javascript:alert(1)", "https://", "file:///etc/passwd"} {
		if _, err := New(Options{AuthServerURL: u, CookieSecret: testSecret, ServiceSecret: testService, JWKSKid: "k"}); err == nil {
			t.Fatalf("accepted %q", u)
		}
	}
	for _, u := range []string{"http://localhost:5312", " https://auth.test/base/ "} {
		if _, err := New(Options{AuthServerURL: u, CookieSecret: testSecret, ServiceSecret: testService, JWKSKid: "k"}); err != nil {
			t.Fatalf("refused %q: %v", u, err)
		}
	}
}

func TestNewRefusesPlaceholderSecrets(t *testing.T) {
	placeholders := []string{
		"dev-only-cookie-signing-key-replace-me",
		"GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV",
		"my-own-service-token-REPLACE-ME-before-prod",
	}
	for _, p := range placeholders {
		for _, opts := range []Options{
			{CookieSecret: p, ServiceSecret: testService},
			{CookieSecret: testSecret, ServiceSecret: p},
		} {
			opts.AuthServerURL, opts.JWKSKid = "https://auth.test", "k"
			if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "placeholder") {
				t.Fatalf("accepted %+v: %v", opts, err)
			}

			var warned bool
			opts.InsecureCookies = true
			opts.Logf = func(string, ...any) { warned = true }
			if _, err := New(opts); err != nil {
				t.Fatalf("refused a placeholder in insecure local mode: %v", err)
			}
			if !warned {
				t.Fatal("a placeholder in insecure local mode was not logged")
			}
		}
	}
}
