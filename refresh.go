package seamlessauth

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// A refresh token presented again within this window gets the rotation it already
// got, so parallel requests from several tabs with one expired session all succeed
// instead of tripping the auth API's reuse detection.
const refreshReuseWindow = 5 * time.Second

var errNoRefreshCookie = errors.New("no refresh cookie")

type refreshOutcome struct {
	session map[string]any
	status  int
	body    any
	isJSON  bool
	err     error
}

type refreshFlight struct {
	done     chan struct{}
	outcome  refreshOutcome
	finished time.Time
}

type refresher struct {
	mu      sync.Mutex
	flights map[string]*refreshFlight
}

func newRefresher() *refresher {
	return &refresher{flights: map[string]*refreshFlight{}}
}

// do runs fn once per key at a time, and hands a successful outcome to every
// caller with the same key for refreshReuseWindow afterwards. A failure is not
// kept, so each caller sees it from the auth API itself.
func (f *refresher) do(key string, fn func() refreshOutcome) refreshOutcome {
	f.mu.Lock()
	now := time.Now()
	for k, flight := range f.flights {
		if !flight.finished.IsZero() && now.Sub(flight.finished) > refreshReuseWindow {
			delete(f.flights, k)
		}
	}
	if flight, ok := f.flights[key]; ok {
		f.mu.Unlock()
		<-flight.done
		return flight.outcome
	}
	flight := &refreshFlight{done: make(chan struct{})}
	f.flights[key] = flight
	f.mu.Unlock()

	outcome := fn()

	f.mu.Lock()
	flight.outcome = outcome
	if outcome.session != nil {
		flight.finished = time.Now()
	} else {
		delete(f.flights, key)
	}
	f.mu.Unlock()
	close(flight.done)

	return outcome
}

// silentRefresh rotates the session held in the refresh cookie.
func (a *Adapter) silentRefresh(r *http.Request) (map[string]any, []cookieWrite, error) {
	c, err := r.Cookie(a.opts.RefreshCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, errNoRefreshCookie
	}

	outcome := a.refreshes.do("cookie:"+c.Value, func() refreshOutcome {
		payload, ok := a.readCookie(r, a.opts.RefreshCookieName, kindRefresh)
		refreshToken := stringClaim(payload, "refreshToken")
		if !ok || refreshToken == "" {
			return refreshOutcome{err: errors.New("invalid refresh cookie")}
		}

		service, err := a.tokens.sign(stringClaim(payload, "sub"), map[string]any{"refreshToken": refreshToken})
		if err != nil {
			return refreshOutcome{err: err}
		}
		return a.rotate(r, refreshToken, "Bearer "+service)
	})
	if outcome.session == nil {
		if outcome.err == nil {
			outcome.err = fmt.Errorf("refresh answered %d", outcome.status)
		}
		return nil, nil, outcome.err
	}

	sessionID, err := a.verifySession(r.Context(), outcome.session, "access")
	if err != nil {
		return nil, nil, err
	}
	cookies, err := a.sessionCookies(outcome.session, sessionID, true)
	if err != nil {
		return nil, nil, err
	}
	return outcome.session, cookies, nil
}

func (a *Adapter) rotate(r *http.Request, refreshToken, service string) refreshOutcome {
	res, err := a.call(r.Context(), r, upstreamCall{
		method:        http.MethodPost,
		path:          "/refresh",
		authorization: "Bearer " + refreshToken,
		service:       service,
	})
	if err != nil {
		return refreshOutcome{err: err}
	}

	data, isJSON := readJSON(res)
	if res.StatusCode != http.StatusOK {
		return refreshOutcome{status: res.StatusCode, body: data, isJSON: isJSON}
	}
	session, ok := carriesSession(data)
	if !ok {
		return refreshOutcome{err: errors.New("refresh returned no session")}
	}
	return refreshOutcome{session: session, status: http.StatusOK}
}

func (a *Adapter) refreshRoute(r *http.Request, bearer bool) result {
	if bearer {
		token := bearerToken(r)
		if token == "" {
			return errorResult(http.StatusUnauthorized, "refresh token required")
		}

		outcome := a.refreshes.do("bearer:"+token, func() refreshOutcome {
			return a.rotate(r, token, a.tokens.proxyAuthorization())
		})
		if outcome.session == nil {
			if outcome.err != nil {
				return errorResult(http.StatusBadGateway, "upstream_unavailable")
			}
			return failure(outcome.status, outcome.body, outcome.isJSON)
		}
		if _, err := a.verifySession(r.Context(), outcome.session, "access"); err != nil {
			return errorResult(http.StatusBadGateway, "invalid_upstream_session")
		}
		return result{status: http.StatusOK, body: outcome.session}
	}

	session, cookies, err := a.silentRefresh(r)
	if errors.Is(err, errNoRefreshCookie) {
		return errorResult(http.StatusUnauthorized, "refresh token required")
	}
	if err != nil {
		res := errorResult(http.StatusUnauthorized, "invalid_refresh_token")
		res.clear = []string{a.opts.AccessCookieName, a.opts.RefreshCookieName}
		return res
	}

	return result{
		status: http.StatusOK,
		body:   cookieTransportBody(ManifestRoute{}, session),
		set:    cookies,
	}
}

// logoutRoute answers 204 and clears every held cookie, even when the auth API
// refuses, so a browser is never left holding a session it asked to end.
func (a *Adapter) logoutRoute(r *http.Request, bearer bool, path string) result {
	clears := []string{a.opts.AccessCookieName, a.opts.RegistrationCookieName, a.opts.RefreshCookieName}

	cred, rejected := a.credentialFor(r, "access", bearer)
	if rejected != nil {
		return *rejected
	}

	res, err := a.call(r.Context(), r, upstreamCall{
		method:        http.MethodDelete,
		path:          path,
		authorization: cred.authorization,
		service:       a.tokens.proxyAuthorization(),
	})
	if err != nil {
		return result{status: http.StatusBadGateway, body: map[string]any{"error": "upstream_unavailable"}, clear: clears}
	}
	res.Body.Close()

	status := http.StatusNoContent
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		status = res.StatusCode
	}
	return result{status: status, clear: clears}
}
