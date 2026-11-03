package seamlessauth

import (
	"net/http"
	"sync/atomic"
	"testing"
)

// rotatingOnceAPI rotates a refresh token the first time it is presented and
// answers refresh_token_reused after that, as the auth API's reuse detection does.
func rotatingOnceAPI(t *testing.T, api *fakeAPI) *atomic.Int32 {
	var n atomic.Int32
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) > 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "refresh_token_reused"})
			return
		}
		writeJSON(w, http.StatusOK, session(t, api, "u1"))
	})
	return &n
}

// A refresh token replayed after its rotation finished must reach the auth API,
// so its reuse detection sees the replay, rather than be handed the new session.
func TestACompletedCookieRotationIsNotReplayedToALaterCaller(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	stolen := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	if r := do(t, a, "GET", "/users/me", "", withCookie(stolen)); r.status != 200 {
		t.Fatalf("first caller: status %d body %v", r.status, r.body)
	}

	r := do(t, a, "GET", "/users/me", "", withCookie(stolen))
	if refreshes.Load() != 2 {
		t.Fatalf("the replay did not reach the auth API: %d refresh calls, replay got status %d, new access cookie issued %v",
			refreshes.Load(), r.status, r.cookies["seamless-access"] != nil && r.cookies["seamless-access"].MaxAge > 0)
	}
	if r.status != 401 || r.cookies["seamless-access"] == nil || r.cookies["seamless-access"].MaxAge >= 0 {
		t.Fatalf("replay: status %d cookies %v", r.status, r.cookies)
	}
}

func TestACompletedBearerRotationIsNotReplayedToALaterCaller(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	a := newTestAdapter(t, api)
	refresh := func() reply {
		return do(t, a, "POST", "/refresh", "",
			withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer r1"))
	}

	if r := refresh(); r.status != 200 || r.body["refreshToken"] == nil {
		t.Fatalf("first caller: status %d body %v", r.status, r.body)
	}

	r := refresh()
	if refreshes.Load() != 2 {
		t.Fatalf("the replay did not reach the auth API: %d refresh calls, replay got status %d, refreshToken %v",
			refreshes.Load(), r.status, r.body["refreshToken"])
	}
	if r.status != 401 || r.body["error"] != "refresh_token_reused" {
		t.Fatalf("replay: status %d body %v", r.status, r.body)
	}
}
