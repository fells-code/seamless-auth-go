package seamlessauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func console(t *testing.T, a *Adapter, method, target string, setup ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for _, s := range setup {
		s(req)
	}
	rec := httptest.NewRecorder()
	http.StripPrefix("/console", a.ConsoleHandler()).ServeHTTP(rec, req)
	return rec
}

func TestTheConsoleIsProxiedFromTheAuthAPI(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/console/assets/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Set-Cookie", "upstream=1")
		_, _ = w.Write([]byte("console();"))
	})
	a := newTestAdapter(t, api)

	rec := console(t, a, "GET", "/console/assets/app.js?v=2",
		withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "t"})))

	if rec.Code != 200 || rec.Body.String() != "console();" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/javascript" || rec.Header().Get("Cache-Control") != "max-age=60" {
		t.Fatalf("headers %v", rec.Header())
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("an upstream Set-Cookie reached the browser")
	}
	call := api.callsTo("GET", "/console/assets/app.js")[0]
	if call.query != "v=2" {
		t.Fatalf("query %q", call.query)
	}
	if call.header.Get("Cookie") != "" || call.header.Get("Authorization") != "" {
		t.Fatal("the browser's credentials reached the upstream")
	}
}

func TestTheConsoleRootAndHead(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/console", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>"))
	})
	api.on("HEAD", "/console", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	})
	a := newTestAdapter(t, api)

	if rec := console(t, a, "GET", "/console/"); rec.Code != 200 || rec.Body.String() != "<html>" {
		t.Fatalf("root: %d %q", rec.Code, rec.Body.String())
	}
	if rec := console(t, a, "HEAD", "/console/"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("head: %d %q", rec.Code, rec.Body.String())
	}
}

func TestTheConsoleRefusesOtherMethods(t *testing.T) {
	api := newFakeAPI(t)
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if rec := console(t, newTestAdapter(t, api), method, "/console/x"); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", method, rec.Code)
		}
	}
}

func TestTheConsoleNeverLeavesItsSubtree(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	for _, target := range []string{
		"/console/../admin/users",
		"/console/%2e%2e/admin/users",
		"/console/assets/%2E%2E/%2e%2e/jwks.json",
		"/console/..%2fadmin",
		"/console/..%2Fadmin",
		"/console/..%5cadmin",
		"/console/a/./b",
	} {
		if rec := console(t, a, "GET", target); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", target, rec.Code)
		}
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.calls) != 0 {
		t.Fatalf("upstream was called: %+v", api.calls)
	}
}

func TestTheConsoleFollowsRedirectsOnlyWithinItself(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/console/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/new", http.StatusFound)
	})
	api.on("GET", "/console/new", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("moved"))
	})
	api.on("GET", "/console/escape", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/.well-known/jwks.json", http.StatusFound)
	})
	a := newTestAdapter(t, api)

	if rec := console(t, a, "GET", "/console/old"); rec.Code != 200 || rec.Body.String() != "moved" {
		t.Fatalf("within: %d %q", rec.Code, rec.Body.String())
	}
	if rec := console(t, a, "GET", "/console/escape"); rec.Code != http.StatusBadGateway {
		t.Fatalf("escape: %d", rec.Code)
	}
	if len(api.callsTo("GET", "/.well-known/jwks.json")) != 0 {
		t.Fatal("followed a redirect out of the console")
	}
}

func TestTheConsoleUnderAnAuthServerPath(t *testing.T) {
	api := newFakeAPI(t)
	api.on("GET", "/base/console/x", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	a := newTestAdapter(t, api, func(o *Options) { o.AuthServerURL = api.server.URL + "/base" })

	if rec := console(t, a, "GET", "/console/x"); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("status %d %q", rec.Code, rec.Body.String())
	}
}

func TestTheConsoleReportsAnUnreachableUpstream(t *testing.T) {
	a := newTestAdapter(t, newFakeAPI(t), func(o *Options) { o.AuthServerURL = "http://127.0.0.1:9" })
	rec := console(t, a, "GET", "/console/x")
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "unreachable") {
		t.Fatalf("status %d %q", rec.Code, rec.Body.String())
	}
}
