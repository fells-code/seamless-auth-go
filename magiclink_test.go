package seamlessauth

import (
	"net/http"
	"testing"
)

func TestMagicLinkVerifyForwardsTheClientBearer(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/magic-link/verify/abc", respond(200, map[string]any{"message": "Success"}))

	r := do(t, newTestAdapter(t, api), "GET", "/magic-link/verify/abc", "",
		withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer pre-auth"))

	if r.status != 200 {
		t.Fatalf("status %d %v", r.status, r.body)
	}
	if got := api.callsTo("GET", "/magic-link/verify/abc")[0].header.Get("Authorization"); got != "Bearer pre-auth" {
		t.Fatalf("upstream authorization %q", got)
	}
}

func TestMagicLinkVerifyForwardsAValidPreAuthCookieAsBearer(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/magic-link/verify/abc", respond(200, map[string]any{"message": "Success"}))

	r := do(t, newTestAdapter(t, api), "GET", "/magic-link/verify/abc", "",
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != 200 {
		t.Fatalf("status %d %v", r.status, r.body)
	}
	if got := api.callsTo("GET", "/magic-link/verify/abc")[0].header.Get("Authorization"); got != "Bearer pre-auth" {
		t.Fatalf("upstream authorization %q", got)
	}
}

func TestMagicLinkVerifyWithoutAUsablePreAuthSendsNoAuthorization(t *testing.T) {
	cases := map[string][]func(*http.Request){
		"no cookie":       nil,
		"altered cookie":  {withCookie(&http.Cookie{Name: "seamless-ephemeral", Value: "not-a-signed-cookie"})},
		"wrong kind":      {withCookie(rawCookie(t, "seamless-ephemeral", kindAccess, map[string]any{"sub": "u1", "token": "access"}))},
		"bearer, no auth": {withHeader(transportHeader, "bearer")},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.on("GET", "/magic-link/verify/abc", respond(200, map[string]any{"message": "Success"}))

			r := do(t, newTestAdapter(t, api), "GET", "/magic-link/verify/abc", "", setup...)

			if r.status != 200 {
				t.Fatalf("status %d %v", r.status, r.body)
			}
			calls := api.callsTo("GET", "/magic-link/verify/abc")
			if len(calls) != 1 {
				t.Fatalf("calls %d", len(calls))
			}
			if got := calls[0].header.Get("Authorization"); got != "" {
				t.Fatalf("upstream authorization %q", got)
			}
		})
	}
}

func TestMagicLinkConfirmationRequiredPassesThrough(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/magic-link/verify/abc", respond(http.StatusConflict, map[string]any{
		"error":         "confirmation_required",
		"message":       "Confirm this sign-in",
		"requestedFrom": map[string]any{"deviceClass": "desktop", "requestedAt": "2026-10-16T12:00:00.000Z"},
	}))

	r := do(t, newTestAdapter(t, api), "GET", "/magic-link/verify/abc", "")

	requested, _ := r.body["requestedFrom"].(map[string]any)
	if r.status != http.StatusConflict || r.body["error"] != "confirmation_required" ||
		requested["deviceClass"] != "desktop" || requested["requestedAt"] != "2026-10-16T12:00:00.000Z" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
}

func TestMagicLinkConfirmIsProxiedWithoutACredential(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/magic-link/verify/abc/confirm", respond(200, map[string]any{"message": "Success"}))

	r := do(t, newTestAdapter(t, api), "POST", "/magic-link/verify/abc/confirm", "")

	if r.status != 200 || r.body["message"] != "Success" {
		t.Fatalf("status %d %v", r.status, r.body)
	}
	calls := api.callsTo("POST", "/magic-link/verify/abc/confirm")
	if len(calls) != 1 || calls[0].header.Get("Authorization") != "" {
		t.Fatalf("calls %d", len(calls))
	}
}

func TestMagicLinkCheckWithoutTokensSetsNoCookies(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/magic-link/check", respond(200, map[string]any{"message": "Success"}))

	r := do(t, newTestAdapter(t, api), "GET", "/magic-link/check", "",
		withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"})))

	if r.status != 200 || r.body["message"] != "Success" || len(r.cookies) != 0 {
		t.Fatalf("status %d body %v cookies %v", r.status, r.body, r.cookies)
	}
}
