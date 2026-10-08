package seamlessauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLoginStoresThePreAuthTokenAndPicksTheBody(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/login", respond(200, map[string]any{
		"message": "Success", "identifierType": "email", "loginMethods": []string{"email_otp"},
		"sub": "u1", "ttl": 300,
		"token": apiToken(t, api, "u1", "ephemeral"),
	}))

	r := do(t, newTestAdapter(t, api), "POST", "/login", `{"identifier":"a@b.test"}`)

	if r.status != 200 {
		t.Fatalf("status %d", r.status)
	}
	if _, ok := r.body["token"]; ok || r.body["sub"] != nil {
		t.Fatalf("body passed more than the pick: %v", r.body)
	}
	if r.body["identifierType"] != "email" {
		t.Fatalf("picked field missing: %v", r.body)
	}
	c := r.cookies["seamless-ephemeral"]
	if c == nil || c.MaxAge != 300 || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteNoneMode || c.Path != "/" {
		t.Fatalf("pre-auth cookie: %+v", c)
	}
}

func TestSessionRouteSetsCookiesAndStripsTokens(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/totp/verify-login", respond(200, session(t, api, "u1")))
	a := newTestAdapter(t, api)

	r := do(t, a, "POST", "/totp/verify-login", `{"code":"123456"}`,
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != 200 {
		t.Fatalf("status %d %v", r.status, r.body)
	}
	if got := api.callsTo("POST", "/totp/verify-login")[0].header.Get("Authorization"); got != "Bearer pre-auth" {
		t.Fatalf("upstream authorization %q", got)
	}
	if _, ok := r.body["token"]; ok {
		t.Fatal("access token in a cookie-transport body")
	}
	if _, ok := r.body["refreshToken"]; ok {
		t.Fatal("refresh token in a cookie-transport body")
	}
	if r.cookies["seamless-access"].MaxAge != 900 || r.cookies["seamless-refresh"].MaxAge != 3600 {
		t.Fatalf("cookie lifetimes: %+v %+v", r.cookies["seamless-access"], r.cookies["seamless-refresh"])
	}

	claims, err := verifyHS256(r.cookies["seamless-access"].Value, testSecret)
	if err != nil || claims["sessionId"] != "s-1" || claims["sub"] != "u1" {
		t.Fatalf("access cookie payload %v %v", claims, err)
	}
}

func TestASessionThatDoesNotVerifyIsRefused(t *testing.T) {
	api := newFakeAPI(t)
	forged := session(t, api, "u1")
	forged["sub"] = "someone-else"
	api.on("POST", "/totp/verify-login", respond(200, forged))

	r := do(t, newTestAdapter(t, api), "POST", "/totp/verify-login", `{}`,
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != http.StatusBadGateway || len(r.cookies) != 0 {
		t.Fatalf("status %d cookies %v", r.status, r.cookies)
	}
}

func TestBearerTransportReturnsTheWholeBodyAndNoCookies(t *testing.T) {
	api := newFakeAPI(t)
	s := session(t, api, "u1")
	api.on("POST", "/totp/verify-login", respond(200, s))

	r := do(t, newTestAdapter(t, api), "POST", "/totp/verify-login", `{}`,
		withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer client-token"))

	if r.status != 200 || r.body["token"] != s["token"] || r.body["refreshToken"] != "refresh-u1" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if len(r.cookies) != 0 {
		t.Fatalf("bearer transport set cookies: %v", r.cookies)
	}
	if got := api.callsTo("POST", "/totp/verify-login")[0].header.Get("Authorization"); got != "Bearer client-token" {
		t.Fatalf("upstream authorization %q", got)
	}
}

func TestAMissingAccessCookieIsRestoredFromTheRefreshCookieOnce(t *testing.T) {
	api := newFakeAPI(t)
	var refreshes atomic.Int32
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		refreshes.Add(1)
		writeJSON(w, 200, session(t, api, "u1"))
	})
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	refresh := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	var wg sync.WaitGroup
	statuses := make([]int, 3)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = do(t, a, "GET", "/users/me", "", withCookie(refresh)).status
		}(i)
	}
	wg.Wait()

	for _, s := range statuses {
		if s != 200 {
			t.Fatalf("statuses %v", statuses)
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshed %d times", refreshes.Load())
	}

	call := api.callsTo("POST", "/refresh")[0]
	if call.header.Get("Authorization") != "Bearer r1" {
		t.Fatalf("refresh authorization %q", call.header.Get("Authorization"))
	}
	service, err := verifyHS256(strings.TrimPrefix(call.header.Get("X-Seamless-Service-Token"), "Bearer "), testService)
	if err != nil || service["sub"] != "u1" || service["refreshToken"] != "r1" || service["aud"] != "seamless-auth" {
		t.Fatalf("service token %v %v", service, err)
	}
}

func TestAFailedRefreshClearsTheSession(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/refresh", respond(401, map[string]any{"error": "refresh_token_reused"}))

	r := do(t, newTestAdapter(t, api), "GET", "/users/me", "",
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})))

	if r.status != 401 {
		t.Fatalf("status %d", r.status)
	}
	for _, name := range []string{"seamless-access", "seamless-refresh"} {
		if c := r.cookies[name]; c == nil || c.MaxAge >= 0 {
			t.Fatalf("%s not cleared: %+v", name, c)
		}
	}
}

func TestAnAlteredAccessCookieIsRefusedWithoutRefreshing(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	access := signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"})
	access.Value += "x"

	r := do(t, a, "GET", "/users/me", "", withCookie(access),
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})))

	if r.status != 401 || len(api.callsTo("POST", "/refresh")) != 0 {
		t.Fatalf("status %d refreshes %d", r.status, len(api.callsTo("POST", "/refresh")))
	}
}

func TestLogoutAnswers204AndClearsEvenWhenTheAPIRefuses(t *testing.T) {
	api := newFakeAPI(t)
	api.on("DELETE", "/logout", respond(500, map[string]any{"error": "boom"}))
	a := newTestAdapter(t, api)
	access := signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"})

	r := do(t, a, "DELETE", "/logout", "", withCookie(access))
	if r.status != 500 {
		t.Fatalf("status %d", r.status)
	}
	for _, name := range []string{"seamless-access", "seamless-ephemeral", "seamless-refresh"} {
		if c := r.cookies[name]; c == nil || c.MaxAge >= 0 {
			t.Fatalf("%s not cleared", name)
		}
	}

	api.on("DELETE", "/logout", respond(200, map[string]any{"message": "ok"}))
	if r := do(t, a, "DELETE", "/logout", "", withCookie(access)); r.status != 204 {
		t.Fatalf("status %d", r.status)
	}
}

func TestDeliveryRoutesHandTheMessageToTheApplication(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/otp/generate-login-email-otp", respond(200, map[string]any{
		"message": "success", "token": "re-minted",
		"delivery": map[string]any{"kind": "otp_email", "to": "a@b.test", "token": "123456"},
	}))
	var got Delivery
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(_ context.Context, d Delivery) error { got = d; return nil }
	})

	r := do(t, a, "POST", "/otp/generate-login-email-otp", "",
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != 200 || len(r.body) != 1 || r.body["message"] != "success" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if got.Token != "123456" || got.To != "a@b.test" || got.Kind != "otp_email" {
		t.Fatalf("delivery %+v", got)
	}

	call := api.callsTo("POST", "/otp/generate-login-email-otp")[0]
	if call.header.Get(deliveryModeHeader) != "external" {
		t.Fatal("did not ask for external delivery")
	}
	service, _ := verifyHS256(strings.TrimPrefix(call.header.Get("X-Seamless-Service-Token"), "Bearer "), testService)
	if service["sub"] != deliveryTokenSubject {
		t.Fatalf("delivery service token %v", service)
	}
}

func TestAFailedDeliveryIsReported(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/magic-link", respond(200, map[string]any{
		"message":  "sent",
		"delivery": map[string]any{"kind": "magic_link_email", "to": "a@b.test", "magicLinkUrl": "https://x"},
	}))
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(context.Context, Delivery) error { return errors.New("smtp down") }
	})

	r := do(t, a, "POST", "/magic-link", "",
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != http.StatusBadGateway || r.body["error"] != "delivery_failed" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
}

func TestWithoutDeliverTheAPISendsTheMessage(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/magic-link", respond(200, map[string]any{"message": "sent"}))

	do(t, newTestAdapter(t, api), "POST", "/magic-link", "",
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if api.callsTo("POST", "/magic-link")[0].header.Get(deliveryModeHeader) != "" {
		t.Fatal("asked for external delivery with nothing to deliver it")
	}
}

func TestUpstreamFailuresPassThrough(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/login", respond(400, map[string]any{"error": "invalid_request", "details": map[string]any{"issues": []any{}}}))

	r := do(t, newTestAdapter(t, api), "POST", "/login", `{}`)
	if r.status != 400 || r.body["error"] != "invalid_request" || r.body["details"] == nil {
		t.Fatalf("status %d body %v", r.status, r.body)
	}

	api.on("POST", "/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte("Too many requests"))
	})
	r = do(t, newTestAdapter(t, api), "POST", "/login", `{}`)
	if r.status != 429 || r.body["error"] != "upstream_error" {
		t.Fatalf("non-JSON failure: status %d body %v", r.status, r.body)
	}
}

func TestDownloadsStreamUnparsed(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/admin/auth-events/export", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="events.ndjson"`)
		_, _ = w.Write([]byte("{\"a\":1}\n{\"b\":2}\n"))
	})

	r := do(t, newTestAdapter(t, api), "GET", "/admin/auth-events/export?from=x", "",
		withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"})))

	if r.status != 200 || r.raw.Body.String() != "{\"a\":1}\n{\"b\":2}\n" ||
		r.raw.Header().Get("Content-Disposition") == "" {
		t.Fatalf("status %d body %q", r.status, r.raw.Body.String())
	}
	if api.callsTo("GET", "/admin/auth-events/export")[0].query != "from=x" {
		t.Fatal("query not forwarded")
	}
}

func TestUnknownRoutesAndDotSegmentsAre404(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	access := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"}))

	for _, target := range []string{"/no-such-route", "/admin/users/..", "/admin/users/%2E%2E"} {
		if r := do(t, a, "GET", target, "", access); r.status != 404 {
			t.Fatalf("%s: status %d", target, r.status)
		}
	}
}

func TestCrossSiteStateChangesAreBlocked(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api, func(o *Options) { o.AllowedOrigins = []string{"https://app.example"} })

	if r := do(t, a, "POST", "/login", `{}`, withHeader("Sec-Fetch-Site", "cross-site")); r.status != 403 {
		t.Fatalf("sec-fetch-site cross-site: %d", r.status)
	}
	if r := do(t, a, "POST", "/login", `{}`, withHeader("Origin", "https://evil.example")); r.status != 403 {
		t.Fatalf("foreign origin: %d", r.status)
	}
	api.on("POST", "/login", respond(400, map[string]any{"error": "invalid_request"}))
	if r := do(t, a, "POST", "/login", `{}`, withHeader("Origin", "https://app.example")); r.status != 400 {
		t.Fatalf("allowed origin: %d", r.status)
	}
}

func TestABodyThatIsNotJSONIsRefusedBeforeAnythingIsSpent(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api, func(o *Options) { o.InsecureCookies = true })
	refresh := withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"}))
	// What a cross-site form with enctype="text/plain" sends.
	forged := `{"code":"attacker","state":"attacker","x":"="}`

	for _, c := range []struct {
		target string
		setup  []func(*http.Request)
	}{
		{"/oauth/mock/callback", []func(*http.Request){withHeader("Content-Type", "text/plain")}},
		{"/oauth/mock/callback", []func(*http.Request){withoutHeader("Content-Type")}},
		{"/oauth/mock/callback", []func(*http.Request){withHeader("Content-Type", "application/x-www-form-urlencoded")}},
		{"/users/credentials", []func(*http.Request){withHeader("Content-Type", "text/plain"), refresh}},
	} {
		if r := do(t, a, "POST", c.target, forged, c.setup...); r.status != http.StatusUnsupportedMediaType || r.body["error"] != "unsupported_media_type" {
			t.Fatalf("%s: status %d body %v", c.target, r.status, r.body)
		}
	}
	if n := len(api.callsTo("POST", "/oauth/mock/callback")); n != 0 {
		t.Fatalf("forwarded %d forged callbacks", n)
	}
	if n := len(api.callsTo("POST", "/refresh")); n != 0 {
		t.Fatalf("a refused body spent the refresh token %d times", n)
	}

	api.on("POST", "/oauth/mock/callback", respond(400, map[string]any{"error": "invalid_request"}))
	if r := do(t, a, "POST", "/oauth/mock/callback", `{}`, withHeader("Content-Type", "application/json; charset=utf-8")); r.status != 400 {
		t.Fatalf("JSON body: status %d", r.status)
	}
	// No body needs no content type.
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{}}))
	access := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"}))
	if r := do(t, a, "GET", "/users/me", "", access); r.status != 200 {
		t.Fatalf("no body: status %d", r.status)
	}
}

func TestTheLiveManifestAddsRoutes(t *testing.T) {
	api := newFakeAPI(t)
	api.manifest = &Manifest{SchemaVersion: 1, Routes: []ManifestRoute{{Method: "GET", Path: "/brand-new/{id}", Credential: "access"}}}
	api.on("GET", "/brand-new/a b", respond(200, map[string]any{"fresh": true}))
	a := newTestAdapter(t, api, func(o *Options) { o.DisableManifestFetch = false })
	access := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"}))

	for i := 0; i < 2; i++ {
		if r := do(t, a, "GET", "/brand-new/a%20b", "", access); r.status != 200 || r.body["fresh"] != true {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
	}
	if n := len(api.callsTo("GET", ManifestPath)); n != 1 {
		t.Fatalf("fetched the manifest %d times", n)
	}
}

func TestForwardsTheClientAddressAndUserAgent(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/login", respond(400, map[string]any{"error": "x"}))
	a := newTestAdapter(t, api, func(o *Options) { o.ResolveClientIP = TrustedProxies("192.0.2.1") })

	do(t, a, "POST", "/login", `{}`,
		func(r *http.Request) { r.RemoteAddr = "192.0.2.1:5000" },
		withHeader("X-Forwarded-For", "6.6.6.6, 203.0.113.50"),
		withHeader("User-Agent", "browser/1"))

	call := api.callsTo("POST", "/login")[0]
	if call.header.Get("X-Seamless-Client-Ip") != "203.0.113.50" || call.header.Get("X-Seamless-Client-User-Agent") != "browser/1" {
		t.Fatalf("forwarded %q %q", call.header.Get("X-Seamless-Client-Ip"), call.header.Get("X-Seamless-Client-User-Agent"))
	}
	service, err := verifyHS256(strings.TrimPrefix(call.header.Get("X-Seamless-Service-Token"), "Bearer "), testService)
	if err != nil || service["sub"] != proxyTokenSubject || service["iss"] != "seamless-portal-api" {
		t.Fatalf("proxy service token %v %v", service, err)
	}
}

func TestNewRefusesWeakSecrets(t *testing.T) {
	for _, opts := range []Options{
		{AuthServerURL: "https://a", CookieSecret: "short", ServiceSecret: testService},
		{AuthServerURL: "https://a", CookieSecret: testSecret, ServiceSecret: "short"},
		{CookieSecret: testSecret, ServiceSecret: testService},
	} {
		if _, err := New(opts); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
}

func TestIsJSONContentType(t *testing.T) {
	for contentType, want := range map[string]bool{
		"":                                true,
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"application/problem+json":        true,
		"application/x-ndjson":            false,
		"text/csv":                        false,
		"text/plain":                      false,
	} {
		if got := isJSONContentType(contentType); got != want {
			t.Errorf("%q: got %v, want %v", contentType, got, want)
		}
	}
}

func TestAnIssuedSessionMustCarryTheExpectedTokenType(t *testing.T) {
	api := newFakeAPI(t)
	preAuth := withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"}))

	// A session route answering with an ephemeral token.
	wrong := session(t, api, "u1")
	wrong["token"] = apiToken(t, api, "u1", "ephemeral")
	api.on("POST", "/totp/verify-login", respond(200, wrong))
	if r := do(t, newTestAdapter(t, api), "POST", "/totp/verify-login", `{}`, preAuth); r.status != http.StatusBadGateway || len(r.cookies) != 0 {
		t.Fatalf("session from an ephemeral token: status %d cookies %v", r.status, r.cookies)
	}

	// The pre-auth route answering with an access token.
	api.on("POST", "/login", respond(200, map[string]any{"message": "ok", "sub": "u1", "ttl": 300, "token": apiToken(t, api, "u1", "access")}))
	if r := do(t, newTestAdapter(t, api), "POST", "/login", `{}`); r.status != http.StatusBadGateway || len(r.cookies) != 0 {
		t.Fatalf("pre-auth from an access token: status %d cookies %v", r.status, r.cookies)
	}
}

func TestCookiesOnlyCountInTheirOwnSlot(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)

	// A pre-auth cookie in the access slot is not a session for the auth routes.
	r := do(t, a, "GET", "/users/me", "",
		withCookie(rawCookie(t, "seamless-access", kindEphemeral, map[string]any{"sub": "u1", "token": "pre-auth"})))
	if r.status != 401 || len(api.callsTo("GET", "/users/me")) != 0 {
		t.Fatalf("status %d, upstream calls %d", r.status, len(api.callsTo("GET", "/users/me")))
	}

	// An access cookie in the refresh slot does not refresh anything.
	r = do(t, a, "GET", "/users/me", "",
		withCookie(rawCookie(t, "seamless-refresh", kindAccess, map[string]any{"sub": "u1", "refreshToken": "r1"})))
	if r.status != 401 || len(api.callsTo("POST", "/refresh")) != 0 {
		t.Fatalf("status %d, refreshes %d", r.status, len(api.callsTo("POST", "/refresh")))
	}
}
