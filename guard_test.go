package seamlessauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
