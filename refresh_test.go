package seamlessauth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func cookieClaims(t *testing.T, c *http.Cookie) map[string]any {
	t.Helper()
	if c == nil || c.MaxAge <= 0 {
		t.Fatalf("cookie not set: %+v", c)
	}
	parsed, err := parseJWT(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.claims
}

// Several tabs can hold one refresh cookie, and one finishing its rotation a
// moment before another presents the cookie must not sign the others out. A
// cookie replayed within the window gets the rotated session without a call.
func TestACookieReplayInsideTheWindowSharesTheCompletedRotation(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	held := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	first := do(t, a, "GET", "/users/me", "", withCookie(held))
	if first.status != 200 {
		t.Fatalf("first caller: status %d body %v", first.status, first.body)
	}

	r := do(t, a, "GET", "/users/me", "", withCookie(held))
	if refreshes.Load() != 1 {
		t.Fatalf("the replay reached the auth API: %d refresh calls, status %d", refreshes.Load(), r.status)
	}
	if r.status != 200 {
		t.Fatalf("replay: status %d body %v", r.status, r.body)
	}
	for _, name := range []string{"seamless-access", "seamless-refresh"} {
		want, got := cookieClaims(t, first.cookies[name]), cookieClaims(t, r.cookies[name])
		for _, claim := range []string{"sub", "token", "refreshToken", "sessionId"} {
			if want[claim] != got[claim] {
				t.Fatalf("%s %s: first %v, replay %v", name, claim, want[claim], got[claim])
			}
		}
	}
}

func TestACookieReplayInsideTheWindowSharesTheCompletedRotationOnPOSTRefresh(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	a := newTestAdapter(t, api)
	held := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	first := do(t, a, "POST", "/refresh", "", withCookie(held))
	r := do(t, a, "POST", "/refresh", "", withCookie(held))
	if first.status != 200 || r.status != 200 || refreshes.Load() != 1 {
		t.Fatalf("first %d, replay %d body %v, %d refresh calls", first.status, r.status, r.body, refreshes.Load())
	}
	if want, got := cookieClaims(t, first.cookies["seamless-refresh"]), cookieClaims(t, r.cookies["seamless-refresh"]); want["refreshToken"] != got["refreshToken"] {
		t.Fatalf("refreshToken: first %v, replay %v", want["refreshToken"], got["refreshToken"])
	}
}

// testClock is a clock a test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func withTestClock(a *Adapter) *testClock {
	clock := &testClock{t: time.Unix(1_700_000_000, 0)}
	a.refreshes.now = clock.now
	return clock
}

// Once the window has passed, a replayed refresh cookie reaches the auth API,
// so its reuse detection sees the replay.
func TestACookieReplayAfterTheWindowReachesTheAuthAPI(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	clock := withTestClock(a)
	stolen := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	if r := do(t, a, "GET", "/users/me", "", withCookie(stolen)); r.status != 200 {
		t.Fatalf("first caller: status %d body %v", r.status, r.body)
	}
	clock.advance(refreshKeepWindow - time.Millisecond)
	if r := do(t, a, "GET", "/users/me", "", withCookie(stolen)); r.status != 200 || refreshes.Load() != 1 {
		t.Fatalf("inside the window: status %d, %d refresh calls", r.status, refreshes.Load())
	}
	clock.advance(time.Millisecond)

	r := do(t, a, "GET", "/users/me", "", withCookie(stolen))
	if refreshes.Load() != 2 {
		t.Fatalf("the replay did not reach the auth API: %d refresh calls, replay got status %d, new access cookie issued %v",
			refreshes.Load(), r.status, r.cookies["seamless-access"] != nil && r.cookies["seamless-access"].MaxAge > 0)
	}
	if r.status != 401 || r.cookies["seamless-access"] == nil || r.cookies["seamless-access"].MaxAge >= 0 {
		t.Fatalf("replay: status %d cookies %v", r.status, r.cookies)
	}
}

// Kept rotations are dropped once they expire, so the map holds at most the
// rotations of the last window.
func TestKeptRotationsArePruned(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, session(t, api, "u1"))
	})
	a := newTestAdapter(t, api)
	clock := withTestClock(a)
	refresh := func(token string) {
		r := do(t, a, "POST", "/refresh", "",
			withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": token})))
		if r.status != 200 {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
	}
	kept := func() (int, int) {
		a.refreshes.mu.Lock()
		defer a.refreshes.mu.Unlock()
		return len(a.refreshes.kept), len(a.refreshes.order)
	}

	for i := 0; i < 50; i++ {
		refresh(fmt.Sprintf("r%d", i))
	}
	if n, o := kept(); n != 50 || o != 50 {
		t.Fatalf("kept %d, order %d", n, o)
	}
	clock.advance(refreshKeepWindow)
	refresh("fresh")
	if n, o := kept(); n != 1 || o != 1 {
		t.Fatalf("after the window: kept %d, order %d", n, o)
	}
}

// The completed window is for cookie transport only: the same refresh token
// presented as a bearer goes to the auth API, whose reuse detection sees it.
func TestABearerReplayInsideTheCookieWindowStillReachesTheAuthAPI(t *testing.T) {
	api := newFakeAPI(t)
	refreshes := rotatingOnceAPI(t, api)
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	held := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	if r := do(t, a, "GET", "/users/me", "", withCookie(held)); r.status != 200 {
		t.Fatalf("cookie caller: status %d body %v", r.status, r.body)
	}

	r := do(t, a, "POST", "/refresh", "",
		withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer r1"))
	if refreshes.Load() != 2 {
		t.Fatalf("the bearer replay did not reach the auth API: %d refresh calls, status %d body %v",
			refreshes.Load(), r.status, r.body)
	}
	if r.status != 401 || r.body["error"] != "refresh_token_reused" {
		t.Fatalf("bearer replay: status %d body %v", r.status, r.body)
	}
}

// A rotation that failed is never kept: the next caller gets a fresh attempt.
func TestAFailedCookieRotationIsNotKept(t *testing.T) {
	api := newFakeAPI(t)
	var n atomic.Int32
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, session(t, api, "u1"))
	})
	api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
	a := newTestAdapter(t, api)
	held := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})

	if r := do(t, a, "GET", "/users/me", "", withCookie(held)); r.status == 200 {
		t.Fatalf("first caller: status %d", r.status)
	}
	if r := do(t, a, "GET", "/users/me", "", withCookie(held)); r.status != 200 || n.Load() != 2 {
		t.Fatalf("retry: status %d body %v, %d refresh calls", r.status, r.body, n.Load())
	}
}

// A bearer refresh token replayed after its rotation finished must reach the
// auth API, so its reuse detection sees the replay, rather than be handed the
// new session.
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

// heldRotationAPI holds the first refresh open until release is closed, so a
// test can act while the rotation is in flight, then rotates it.
func heldRotationAPI(t *testing.T, api *fakeAPI) (started, release chan struct{}, refreshes *atomic.Int32) {
	started, release = make(chan struct{}), make(chan struct{})
	refreshes = &atomic.Int32{}
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		if refreshes.Add(1) > 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "refresh_token_reused"})
			return
		}
		close(started)
		<-release
		writeJSON(w, http.StatusOK, session(t, api, "u1"))
	})
	return started, release, refreshes
}

func withContext(ctx context.Context) func(*http.Request) {
	return func(r *http.Request) { *r = *r.WithContext(ctx) }
}

// The caller that starts a rotation can go away (a closed tab) while others wait
// on it. The rotation must finish for them, or the token the auth API already
// spent leaves every tab signed out.
func TestALeadingCallerGoingAwayDoesNotCancelTheSharedRotation(t *testing.T) {
	cases := map[string]func(t *testing.T, a *Adapter, setup ...func(*http.Request)) reply{
		"cookie": func(t *testing.T, a *Adapter, setup ...func(*http.Request)) reply {
			refresh := signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})
			return do(t, a, "GET", "/users/me", "", append(setup, withCookie(refresh))...)
		},
		"bearer": func(t *testing.T, a *Adapter, setup ...func(*http.Request)) reply {
			return do(t, a, "POST", "/refresh", "", append(setup,
				withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer r1"))...)
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			started, release, refreshes := heldRotationAPI(t, api)
			api.on("GET", "/users/me", respond(200, map[string]any{"user": map[string]any{"id": "u1"}}))
			a := newTestAdapter(t, api)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			leader := make(chan reply, 1)
			go func() { leader <- call(t, a, withContext(ctx)) }()
			<-started

			waiter := make(chan reply, 1)
			go func() { waiter <- call(t, a) }()
			// Let the waiter join the flight before the leader goes away.
			time.Sleep(100 * time.Millisecond)
			cancel()
			time.Sleep(100 * time.Millisecond)
			close(release)

			<-leader
			r := <-waiter
			if r.status != 200 {
				t.Fatalf("waiter: status %d body %v cookies %v (%d refresh calls)", r.status, r.body, r.cookies, refreshes.Load())
			}
			if refreshes.Load() != 1 {
				t.Fatalf("refreshed %d times", refreshes.Load())
			}
		})
	}
}

// Only the auth API answering 401 says a refresh token is dead. A network
// failure or an API error leaves it as it was (or rotated with the answer lost),
// so the cookies are kept for the next attempt.
func TestARefreshThatNeverGotAnAnswerKeepsTheCookies(t *testing.T) {
	failures := map[string]http.HandlerFunc{
		"transport error": func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
		},
		"server error": respond(http.StatusServiceUnavailable, map[string]any{"error": "unavailable"}),
	}
	routes := map[string]func(t *testing.T, a *Adapter) reply{
		"silent refresh": func(t *testing.T, a *Adapter) reply {
			return do(t, a, "GET", "/users/me", "",
				withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})))
		},
		"POST /refresh": func(t *testing.T, a *Adapter) reply {
			return do(t, a, "POST", "/refresh", "",
				withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})))
		},
	}
	for failure, handler := range failures {
		for route, call := range routes {
			t.Run(failure+"/"+route, func(t *testing.T) {
				api := newFakeAPI(t)
				api.on("POST", "/refresh", handler)
				r := call(t, newTestAdapter(t, api))

				if r.status == 200 || r.status == 401 {
					t.Fatalf("status %d body %v", r.status, r.body)
				}
				for _, name := range []string{"seamless-access", "seamless-refresh", "seamless-ephemeral"} {
					if c := r.cookies[name]; c != nil {
						t.Fatalf("%s written: %+v (status %d body %v)", name, c, r.status, r.body)
					}
				}
			})
		}
	}
}

func TestARefreshTheAuthAPIRefusesClearsTheCookies(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/refresh", respond(401, map[string]any{"error": "invalid_refresh_token"}))

	r := do(t, newTestAdapter(t, api), "POST", "/refresh", "",
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "r1"})))

	if r.status != 401 {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	for _, name := range []string{"seamless-access", "seamless-refresh"} {
		if c := r.cookies[name]; c == nil || c.MaxAge >= 0 {
			t.Fatalf("%s not cleared: %+v", name, c)
		}
	}
}
