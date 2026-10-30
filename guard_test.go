package seamlessauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func guarded(a *Adapter) http.Handler {
	return a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := UserFromContext(r.Context())
		writeJSON(w, 200, map[string]any{"id": user.ID})
	}))
}

func call(h http.Handler, setup ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/api/me", nil)
	for _, s := range setup {
		s(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequireAuth(t *testing.T) {
	api := newFakeAPI(t)
	h := guarded(newTestAdapter(t, api))
	token := func(typ string) string {
		return signRS256(t, map[string]any{"sub": "u1", "typ": typ, "iss": api.server.URL, "aud": api.server.URL})
	}

	cases := []struct {
		name   string
		setup  func(*http.Request)
		status int
	}{
		{"no credential", func(*http.Request) {}, 401},
		{"session cookie", withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token("access")})), 200},
		// Every cookie is signed with the same secret. The pre-auth cookie /login
		// issues for any existing account must not pass for a session, in the access
		// slot or out of it.
		{"pre-auth cookie in the access slot", withCookie(rawCookie(t, "seamless-access", kindEphemeral, map[string]any{"sub": "u1", "token": token("ephemeral")})), 401},
		{"refresh cookie in the access slot", withCookie(rawCookie(t, "seamless-access", kindRefresh, map[string]any{"sub": "u1", "refreshToken": "r1"})), 401},
		{"access-kind cookie holding an ephemeral token", withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token("ephemeral")})), 401},
		{"access-kind cookie with no token", withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1"})), 401},
		{"forged cookie", withCookie(&http.Cookie{Name: "seamless-access", Value: "a.b.c"}), 401},
		{"access token", withHeader("Authorization", "Bearer "+token("access")), 200},
		// An ephemeral sign-in token is signed by the same key and must not pass.
		{"ephemeral token", withHeader("Authorization", "Bearer "+token("ephemeral")), 401},
		{"token for another audience", withHeader("Authorization", "Bearer "+signRS256(t, map[string]any{
			"sub": "u1", "typ": "access", "iss": api.server.URL, "aud": "https://elsewhere",
		})), 401},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec := call(h, c.setup); rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
		})
	}
}

func TestACookieSessionIsRefusedForCrossSiteStateChanges(t *testing.T) {
	api := newFakeAPI(t)
	h := guarded(newTestAdapter(t, api))
	token := signRS256(t, map[string]any{"sub": "u1", "typ": "access", "iss": api.server.URL, "aud": api.server.URL})
	cookie := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token}))
	post := func(r *http.Request) { r.Method = http.MethodPost }

	cases := []struct {
		name   string
		setup  []func(*http.Request)
		status int
	}{
		{"cookie, cross-site", []func(*http.Request){post, cookie, withHeader("Sec-Fetch-Site", "cross-site")}, 403},
		{"cookie, same-origin", []func(*http.Request){post, cookie, withHeader("Sec-Fetch-Site", "same-origin")}, 200},
		{"cookie, cross-site read", []func(*http.Request){cookie, withHeader("Sec-Fetch-Site", "cross-site")}, 200},
		// A bearer token is never attached by a browser, so it needs no such check.
		{"bearer, cross-site", []func(*http.Request){post, withHeader("Authorization", "Bearer "+token), withHeader("Sec-Fetch-Site", "cross-site")}, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(h, c.setup...)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			if c.status == 403 && !strings.Contains(rec.Body.String(), "cross_site_request_blocked") {
				t.Fatalf("body %s", rec.Body.String())
			}
		})
	}
}

// signWith is signRS256 under any key, as a forger holding only the cookie
// secret would have to.
func signWith(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body := map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		body[k] = v
	}
	payload, _ := json.Marshal(body)
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func TestTheCookiesInnerTokenIsVerified(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	iss := api.server.URL
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]any{"sub": "u1", "typ": "access", "iss": iss, "aud": iss}
	with := func(k string, v any) map[string]any {
		out := map[string]any{}
		for key, val := range valid {
			out[key] = val
		}
		out[k] = v
		return out
	}
	unsigned := func() string {
		header, _ := json.Marshal(map[string]string{"alg": "none", "kid": "k1"})
		payload, _ := json.Marshal(with("exp", time.Now().Add(time.Hour).Unix()))
		return b64.EncodeToString(header) + "." + b64.EncodeToString(payload) + "."
	}

	cases := []struct {
		name   string
		token  string
		status int
	}{
		{"valid", signRS256(t, valid), 200},
		{"signed by another key", signWith(t, other, valid), 401},
		{"unsigned", unsigned(), 401},
		{"wrong audience", signRS256(t, with("aud", "https://elsewhere")), 401},
		{"wrong issuer", signRS256(t, with("iss", "https://elsewhere")), 401},
		{"expired", signRS256(t, with("exp", time.Now().Add(-time.Hour).Unix())), 401},
		{"another subject", signRS256(t, with("sub", "u2")), 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cookie := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": c.token}))
			if rec := call(guarded(a), cookie); rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
		})
	}
}

func TestACookiesRolesComeFromItsVerifiedToken(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := signRS256(t, map[string]any{"sub": "u1", "typ": "access", "roles": []string{"user"}, "iss": api.server.URL, "aud": api.server.URL})
	cookie := signedCookie(t, "seamless-access", map[string]any{
		"sub": "u1", "token": token, "roles": []string{"admin"}, "email": "u1@example.com",
	})

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(cookie)
	user, err := a.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(user.Roles, []string{"user"}) || user.Email != "u1@example.com" {
		t.Fatalf("user %+v", user)
	}

	adminOnly := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := UserFromContext(r.Context())
		if !slices.Contains(user.Roles, "admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	if rec := call(adminOnly, withCookie(cookie)); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestACookieSessionFailsClosedWhenTheKeySetIsUnreachable(t *testing.T) {
	api := newFakeAPI(t)
	token := apiToken(t, api, "u1", "access")
	a := newTestAdapter(t, api)
	api.server.Close()

	cookie := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token}))
	if rec := call(guarded(a), cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
