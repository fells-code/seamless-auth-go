package seamlessauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestTheOriginGuard(t *testing.T) {
	api := newFakeAPI(t)
	open := newTestAdapter(t, api)
	listed := newTestAdapter(t, api, func(o *Options) { o.AllowedOrigins = []string{"https://app.example.com"} })
	lax := newTestAdapter(t, api, func(o *Options) {
		o.CookieSameSite = http.SameSiteLaxMode
		o.AllowedOrigins = []string{"https://app.example.com"}
	})
	site := func(v string) func(*http.Request) { return withHeader("Sec-Fetch-Site", v) }
	origin := func(v string) func(*http.Request) { return withHeader("Origin", v) }

	cases := []struct {
		name    string
		a       *Adapter
		method  string
		setup   []func(*http.Request)
		blocked bool
	}{
		{"cross-site", open, "POST", []func(*http.Request){site("cross-site")}, true},
		{"cross-site, any case", open, "POST", []func(*http.Request){site("Cross-Site")}, true},
		{"same-origin", open, "POST", []func(*http.Request){site("same-origin")}, false},
		{"same-site without an allowlist", open, "POST", []func(*http.Request){site("same-site")}, false},
		{"server to server", open, "POST", nil, false},
		{"null origin", open, "POST", []func(*http.Request){origin("null")}, true},
		{"cross-site read", open, "GET", []func(*http.Request){site("cross-site")}, false},
		{"cross-site preflight", open, "OPTIONS", []func(*http.Request){site("cross-site")}, false},

		{"no Sec-Fetch-Site, listed origin", listed, "POST", []func(*http.Request){origin("https://app.example.com")}, false},
		{"no Sec-Fetch-Site, other origin", listed, "POST", []func(*http.Request){origin("https://evil.example.com")}, true},
		{"no Sec-Fetch-Site, any origin without an allowlist", open, "POST", []func(*http.Request){origin("https://evil.example.com")}, false},

		// A sibling subdomain is same-site, so the header alone cannot tell it from the app.
		{"same-site, other origin", listed, "POST", []func(*http.Request){site("same-site"), origin("https://evil.example.com")}, true},
		{"same-site, no origin", listed, "POST", []func(*http.Request){site("same-site")}, true},
		{"same-site, listed origin", listed, "POST", []func(*http.Request){site("same-site"), origin("https://APP.example.com")}, false},
		{"same-site, any case", listed, "POST", []func(*http.Request){site("Same-Site"), origin("https://evil.example.com")}, true},
		{"same-origin, unlisted origin", listed, "POST", []func(*http.Request){site("same-origin"), origin("https://auth-adapter.example.com")}, false},
		{"cross-site, listed origin", listed, "POST", []func(*http.Request){site("cross-site"), origin("https://app.example.com")}, true},

		{"lax cookies, cross-site", lax, "POST", []func(*http.Request){site("cross-site")}, false},
		{"lax cookies, same-site other origin", lax, "POST", []func(*http.Request){site("same-site"), origin("https://evil.example.com")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := do(t, c.a, c.method, "/magic-link", "", c.setup...)
			isBlocked := r.status == http.StatusForbidden && r.body["error"] == "cross_site_request_blocked"
			if isBlocked != c.blocked {
				t.Fatalf("status %d body %v, want blocked=%v", r.status, r.body, c.blocked)
			}
		})
	}
}

// An origin that does not parse normalizes to nothing, and must not match an
// allowlist entry that does not parse either.
func TestAnUnparseableOriginMatchesNothing(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api, func(o *Options) { o.AllowedOrigins = []string{"not an origin"} })

	for _, setup := range [][]func(*http.Request){
		{withHeader("Origin", "also not an origin")},
		{withHeader("Sec-Fetch-Site", "same-site"), withHeader("Origin", "also not an origin")},
		{withHeader("Sec-Fetch-Site", "same-site")},
	} {
		if r := do(t, a, "POST", "/magic-link", "", setup...); r.status != http.StatusForbidden {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
	}
}

func TestACookieSessionGetsTheSameSiteAllowlistCheck(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api, func(o *Options) { o.AllowedOrigins = []string{"https://app.example.com"} })
	cookie := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": apiToken(t, api, "u1", "access")}))
	post := func(r *http.Request) { r.Method = http.MethodPost }
	sameSite := withHeader("Sec-Fetch-Site", "same-site")

	if rec := call(guarded(a), post, cookie, sameSite, withHeader("Origin", "https://evil.example.com")); rec.Code != 403 ||
		!strings.Contains(rec.Body.String(), "cross_site_request_blocked") {
		t.Fatalf("other origin: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec := call(guarded(a), post, cookie, sameSite, withHeader("Origin", "https://app.example.com")); rec.Code != 200 {
		t.Fatalf("listed origin: status %d body %s", rec.Code, rec.Body.String())
	}
}
