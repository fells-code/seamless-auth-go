package seamlessauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const insufficientPermission = `{"error":"insufficient_permission"}`

// permissionMatchCases are shared by the adapter and the verifier, which must
// agree. claims are the token's, and path is matched against /orgs/{org} or /plain.
type permissionMatchCase struct {
	name        string
	claims      map[string]any
	permissions []string
	opts        []PermissionOption
	path        string
	allowed     bool
}

func permissionMatchCases() []permissionMatchCase {
	all := []PermissionOption{AllPermissions()}
	org := []PermissionOption{InOrganization()}
	orgAll := []PermissionOption{InOrganization(), AllPermissions()}
	route := []PermissionOption{InRouteOrganization("org")}
	routeAll := []PermissionOption{InRouteOrganization("org"), AllPermissions()}
	wrongParam := []PermissionOption{InRouteOrganization("nope")}
	read := []string{"invoices:read"}
	both := []string{"invoices:read", "invoices:write"}
	inOrg := func(perms ...any) map[string]any {
		return map[string]any{"org_id": "org-a", "org_permissions": perms}
	}

	return []permissionMatchCase{
		{name: "any, none held", claims: map[string]any{}, permissions: both},
		{name: "any, first held", claims: map[string]any{"permissions": []any{"invoices:read"}}, permissions: both, allowed: true},
		{name: "any, last held", claims: map[string]any{"permissions": []any{"invoices:write"}}, permissions: both, allowed: true},
		{name: "any, from org_permissions", claims: inOrg("invoices:read"), permissions: both, allowed: true},
		{name: "default scope counts org_permissions on any route", claims: inOrg("invoices:read"), permissions: read, path: "/orgs/org-b", allowed: true},

		{name: "all, one of two", claims: map[string]any{"permissions": []any{"invoices:read"}}, permissions: both, opts: all},
		{name: "all, both in permissions", claims: map[string]any{"permissions": []any{"invoices:read", "invoices:write"}}, permissions: both, opts: all, allowed: true},
		{name: "all, one from each claim", claims: map[string]any{"permissions": []any{"invoices:read"}, "org_id": "org-a", "org_permissions": []any{"invoices:write"}}, permissions: both, opts: all, allowed: true},

		{name: "exact, write does not imply read", claims: map[string]any{"permissions": []any{"invoices:write"}}, permissions: read},
		{name: "exact, no wildcard", claims: map[string]any{"permissions": []any{"invoices:*", "*"}}, permissions: read},
		{name: "exact, no prefix grant", claims: map[string]any{"permissions": []any{"invoices"}}, permissions: read},
		{name: "exact, case-sensitive", claims: map[string]any{"permissions": []any{"INVOICES:READ"}}, permissions: read},
		{name: "exact, no trimming of a grant", claims: map[string]any{"permissions": []any{" invoices:read "}}, permissions: read},
		{name: "exact, no trimming of a requirement", claims: map[string]any{"permissions": []any{"invoices:read"}}, permissions: []string{" invoices:read"}},
		{name: "roles do not count", claims: map[string]any{"roles": []any{"invoices:read", "admin"}}, permissions: read},
		{name: "organization roles do not count", claims: map[string]any{"org_id": "org-a", "org_roles": []any{"invoices:read"}}, permissions: read},

		{name: "empty, any", claims: map[string]any{"permissions": []any{"invoices:read"}}},
		{name: "empty, all", claims: map[string]any{"permissions": []any{"invoices:read"}}, opts: all},
		{name: "empty, organization", claims: inOrg("invoices:read"), opts: org},
		{name: "empty, organization all", claims: inOrg("invoices:read"), opts: orgAll},
		{name: "empty, route", claims: inOrg("invoices:read"), opts: route, path: "/orgs/org-a"},
		{name: "empty, route all", claims: inOrg("invoices:read"), opts: routeAll, path: "/orgs/org-a"},
		{name: "empty non-nil, any", claims: map[string]any{"permissions": []any{"invoices:read"}}, permissions: []string{}},

		{name: "organization, held", claims: inOrg("invoices:read"), permissions: read, opts: org, allowed: true},
		{name: "organization, permissions claim does not count", claims: map[string]any{"org_id": "org-a", "permissions": []any{"invoices:read"}}, permissions: read, opts: org},
		{name: "organization, no org_id", claims: map[string]any{"org_permissions": []any{"invoices:read"}}, permissions: read, opts: org},
		{name: "organization, empty org_id", claims: map[string]any{"org_id": "", "org_permissions": []any{"invoices:read"}}, permissions: read, opts: org},
		{name: "organization all, one held", claims: inOrg("invoices:read"), permissions: both, opts: orgAll},
		{name: "organization all, one from each claim", claims: map[string]any{"org_id": "org-a", "permissions": []any{"invoices:read"}, "org_permissions": []any{"invoices:write"}}, permissions: both, opts: orgAll},
		{name: "organization all, both held", claims: inOrg("invoices:read", "invoices:write"), permissions: both, opts: orgAll, allowed: true},

		{name: "route, match", claims: inOrg("invoices:read"), permissions: read, opts: route, path: "/orgs/org-a", allowed: true},
		{name: "route, other organization", claims: inOrg("invoices:read"), permissions: read, opts: route, path: "/orgs/org-b"},
		{name: "route, case differs", claims: inOrg("invoices:read"), permissions: read, opts: route, path: "/orgs/ORG-A"},
		{name: "route, parameter missing", claims: inOrg("invoices:read"), permissions: read, opts: route},
		{name: "route, parameter misnamed", claims: inOrg("invoices:read"), permissions: read, opts: wrongParam, path: "/orgs/org-a"},
		{name: "route, permissions claim does not count", claims: map[string]any{"org_id": "org-a", "permissions": []any{"invoices:read"}}, permissions: read, opts: route, path: "/orgs/org-a"},
		{name: "route, no org_id", claims: map[string]any{"org_permissions": []any{"invoices:read"}}, permissions: read, opts: route, path: "/orgs/org-a"},
		{name: "route all, one held", claims: inOrg("invoices:read"), permissions: both, opts: routeAll, path: "/orgs/org-a"},
		{name: "route all, both held", claims: inOrg("invoices:read", "invoices:write"), permissions: both, opts: routeAll, path: "/orgs/org-a", allowed: true},

		{name: "malformed, permissions a string", claims: map[string]any{"permissions": "invoices:read"}, permissions: read},
		{name: "malformed, permissions an object", claims: map[string]any{"permissions": map[string]any{"invoices:read": true}}, permissions: read},
		{name: "malformed, permissions null", claims: map[string]any{"permissions": nil}, permissions: read},
		{name: "malformed, permissions a number", claims: map[string]any{"permissions": 1}, permissions: read},
		{name: "malformed, org_permissions a string", claims: map[string]any{"org_id": "org-a", "org_permissions": "invoices:read"}, permissions: read, opts: org},
		{name: "malformed, non-string entries are skipped", claims: map[string]any{"permissions": []any{1, nil, true, map[string]any{}, "invoices:read"}}, permissions: read, allowed: true},
		{name: "malformed, only non-string entries", claims: map[string]any{"permissions": []any{1, nil}}, permissions: read},
		{name: "malformed, a false marker is no marker", claims: map[string]any{"permissions_omitted": false, "permissions": []any{"invoices:read"}}, permissions: read, allowed: true},
		{name: "malformed, a string marker is no marker", claims: map[string]any{"permissions_omitted": "true", "permissions": []any{"invoices:read"}}, permissions: read, allowed: true},
	}
}

// permissionMux routes the guard at /plain and /orgs/{org}, as an app would.
func permissionMux(guard func(http.Handler) http.Handler) http.Handler {
	ok := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	mux := http.NewServeMux()
	mux.Handle("/plain", ok)
	mux.Handle("/orgs/{org}", ok)
	return mux
}

func getWith(h http.Handler, path string, setup ...func(*http.Request)) *httptest.ResponseRecorder {
	if path == "" {
		path = "/plain"
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, s := range setup {
		s(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func wantBody(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != body {
		t.Fatalf("body %s, want %s", got, body)
	}
}

// permissionToken is an access token's claims for the fake API, with extra on top.
func permissionToken(t *testing.T, api *fakeAPI, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"sub": "u1", "typ": "access", "iss": api.server.URL, "aud": api.server.URL}
	for k, v := range extra {
		claims[k] = v
	}
	return signRS256(t, claims)
}

func cookieHolding(t *testing.T, token string) func(*http.Request) {
	return withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token}))
}

func bearerHolding(token string) func(*http.Request) {
	return withHeader("Authorization", "Bearer "+token)
}

func TestRequirePermissionMatching(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	for _, c := range permissionMatchCases() {
		token := permissionToken(t, api, c.claims)
		h := permissionMux(a.RequirePermissionWith(c.permissions, c.opts...))
		for transport, credential := range map[string]func(*http.Request){
			"bearer": bearerHolding(token),
			"cookie": cookieHolding(t, token),
		} {
			t.Run(c.name+"/"+transport, func(t *testing.T) {
				rec := getWith(h, c.path, credential)
				if c.allowed {
					wantBody(t, rec, http.StatusOK, `{"ok":true}`)
				} else {
					wantBody(t, rec, http.StatusForbidden, insufficientPermission)
				}
			})
		}
	}
	if calls := api.callsTo(http.MethodGet, livePermissionsPath); len(calls) != 0 {
		t.Fatalf("%d live reads without the marker", len(calls))
	}
}

func TestRequirePermissionVariadicIsAny(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions": []any{"b"}})

	wantBody(t, getWith(permissionMux(a.RequirePermission("a", "b")), "", bearerHolding(token)), 200, `{"ok":true}`)
	wantBody(t, getWith(permissionMux(a.RequirePermission("a")), "", bearerHolding(token)), 403, insufficientPermission)
	wantBody(t, getWith(permissionMux(a.RequirePermission()), "", bearerHolding(token)), 403, insufficientPermission)
}

func TestRequirePermissionCopiesItsList(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions": []any{"b"}})
	list := []string{"a"}
	h := permissionMux(a.RequirePermissionWith(list))
	list[0] = "b"
	wantBody(t, getWith(h, "", bearerHolding(token)), 403, insufficientPermission)
}

func TestRequirePermissionKeepsTheExistingAnswers(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	held := map[string]any{"permissions": []any{"p"}}
	valid := permissionToken(t, api, held)
	recovery := permissionToken(t, api, map[string]any{"permissions": []any{"p"}, "recovery": true})
	omittedRecovery := permissionToken(t, api, map[string]any{"permissions_omitted": true, "recovery": true})
	ephemeral := signRS256(t, map[string]any{"sub": "u1", "typ": "ephemeral", "iss": api.server.URL, "aud": api.server.URL, "permissions": []any{"p"}})

	guards := map[string]func(http.Handler) http.Handler{
		"any":   a.RequirePermission("p"),
		"all":   a.RequirePermissionWith([]string{"p"}, AllPermissions()),
		"org":   a.RequirePermissionWith([]string{"p"}, InOrganization()),
		"route": a.RequirePermissionWith([]string{"p"}, InRouteOrganization("org")),
		"empty": a.RequirePermission(),
	}
	for name, guard := range guards {
		h := permissionMux(guard)
		t.Run(name, func(t *testing.T) {
			wantBody(t, getWith(h, ""), 401, `{"error":"unauthenticated"}`)
			wantBody(t, getWith(h, "", bearerHolding("not-a-token")), 401, `{"error":"unauthenticated"}`)
			wantBody(t, getWith(h, "", bearerHolding(ephemeral)), 401, `{"error":"unauthenticated"}`)
			wantBody(t, getWith(h, "", bearerHolding(recovery)), 403, `{"error":"enrollment_required"}`)
			wantBody(t, getWith(h, "", cookieHolding(t, recovery)), 403, `{"error":"enrollment_required"}`)
			wantBody(t, getWith(h, "", bearerHolding(omittedRecovery)), 403, `{"error":"enrollment_required"}`)
		})
	}
	if calls := api.callsTo(http.MethodGet, livePermissionsPath); len(calls) != 0 {
		t.Fatalf("%d live reads for sessions already refused", len(calls))
	}

	allowed := newTestAdapter(t, api, func(o *Options) { o.AllowRecoverySessions = true })
	wantBody(t, getWith(permissionMux(allowed.RequirePermission("p")), "", bearerHolding(recovery)), 200, `{"ok":true}`)
	wantBody(t, getWith(permissionMux(allowed.RequirePermission("q")), "", bearerHolding(recovery)), 403, insufficientPermission)

	post := func(r *http.Request) { r.Method = http.MethodPost }
	h := permissionMux(a.RequirePermission("p"))
	rec := getWith(h, "", post, cookieHolding(t, valid), withHeader("Sec-Fetch-Site", "cross-site"))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "cross_site_request_blocked") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestRequireRoleIgnoresPermissionsAndOrganizationRoles(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{
		"org_id": "org-a", "org_roles": []any{"admin"}, "permissions": []any{"admin"}, "org_permissions": []any{"admin"},
	})
	wantBody(t, getWith(permissionMux(a.RequireRole("admin")), "", bearerHolding(token)), 403, `{"error":"insufficient_role"}`)
}

func TestPermissionClaimsOnTheUser(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	full := permissionToken(t, api, map[string]any{
		"permissions": []any{"reports:read", 7}, "org_id": "org-a", "org_roles": []any{"admin"}, "org_permissions": []any{"projects:write"},
	})
	omitted := permissionToken(t, api, map[string]any{"org_id": "org-a", "permissions_omitted": true})

	for name, setup := range map[string]func(*http.Request){
		"bearer": bearerHolding(full),
		"cookie": cookieHolding(t, full),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			setup(req)
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(user.Permissions, []string{"reports:read"}) ||
				!slices.Equal(user.OrganizationRoles, []string{"admin"}) ||
				!slices.Equal(user.OrganizationPermissions, []string{"projects:write"}) ||
				user.OrganizationID != "org-a" || user.PermissionsOmitted {
				t.Fatalf("%+v", user)
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	bearerHolding(omitted)(req)
	user, err := a.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !user.PermissionsOmitted || user.OrganizationID != "org-a" || user.Permissions != nil {
		t.Fatalf("%+v", user)
	}
}

func TestPermissionsAreNeverReadFromTheCookie(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	inner := permissionToken(t, api, nil)
	cookie := withCookie(signedCookie(t, "seamless-access", map[string]any{
		"sub": "u1", "token": inner,
		"permissions": []any{"p"}, "org_id": "org-a", "org_permissions": []any{"p"}, "permissions_omitted": true,
	}))

	wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", cookie), 403, insufficientPermission)
	if calls := api.callsTo(http.MethodGet, livePermissionsPath); len(calls) != 0 {
		t.Fatal("the cookie's marker started a live read")
	}
}

func liveAnswer(permissions, organizationPermissions []string, organizationID any) map[string]any {
	return map[string]any{
		"roles": []string{"user"}, "permissions": permissions, "organizationId": organizationID,
		"organizationRoles": []string{}, "organizationPermissions": organizationPermissions,
	}
}

func TestLiveReadSuccess(t *testing.T) {
	read := []string{"invoices:read"}
	both := []string{"invoices:read", "invoices:write"}
	org := []PermissionOption{InOrganization()}
	route := []PermissionOption{InRouteOrganization("org")}
	none := []string{}

	cases := []struct {
		name        string
		live        map[string]any
		permissions []string
		opts        []PermissionOption
		path        string
		allowed     bool
	}{
		{name: "any, held", live: liveAnswer(read, none, nil), permissions: both, allowed: true},
		{name: "any, not held", live: liveAnswer(none, none, nil), permissions: both},
		{name: "any, from the organization", live: liveAnswer(none, read, "org-a"), permissions: read, allowed: true},
		{name: "all, one held", live: liveAnswer(read, none, nil), permissions: both, opts: []PermissionOption{AllPermissions()}},
		{name: "all, one from each", live: liveAnswer(read, []string{"invoices:write"}, "org-a"), permissions: both, opts: []PermissionOption{AllPermissions()}, allowed: true},
		{name: "exact", live: liveAnswer([]string{"invoices:write", "invoices:*"}, none, nil), permissions: read},
		{name: "organization, held", live: liveAnswer(none, read, "org-a"), permissions: read, opts: org, allowed: true},
		{name: "organization, permissions do not count", live: liveAnswer(read, none, "org-a"), permissions: read, opts: org},
		{name: "organization, none active now", live: liveAnswer(none, read, nil), permissions: read, opts: org},
		{name: "route, match", live: liveAnswer(none, read, "org-a"), permissions: read, opts: route, path: "/orgs/org-a", allowed: true},
		{name: "route, mismatch", live: liveAnswer(none, read, "org-a"), permissions: read, opts: route, path: "/orgs/org-b"},
		{name: "route, the live organization decides, not the token's", live: liveAnswer(none, read, "org-b"), permissions: read, opts: route, path: "/orgs/org-a"},
		{name: "non-string entries are skipped", live: map[string]any{"permissions": []any{1, "invoices:read"}, "organizationPermissions": []any{}, "organizationId": nil}, permissions: read, allowed: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.on(http.MethodGet, livePermissionsPath, respond(200, c.live))
			a := newTestAdapter(t, api)
			token := permissionToken(t, api, map[string]any{"org_id": "org-a", "permissions_omitted": true})
			h := permissionMux(a.RequirePermissionWith(c.permissions, c.opts...))

			for _, credential := range []func(*http.Request){bearerHolding(token), cookieHolding(t, token)} {
				rec := getWith(h, c.path, credential)
				if c.allowed {
					wantBody(t, rec, 200, `{"ok":true}`)
				} else {
					wantBody(t, rec, 403, insufficientPermission)
				}
			}
			calls := api.callsTo(http.MethodGet, livePermissionsPath)
			if len(calls) != 2 {
				t.Fatalf("%d live reads, want 2", len(calls))
			}
			// The bearer's token and the cookie's inner token are the same token here.
			for _, call := range calls {
				if got := call.header.Get("Authorization"); got != "Bearer "+token {
					t.Fatalf("Authorization %q", got)
				}
				if call.header.Get("X-Seamless-Service-Token") != "" {
					t.Fatal("the live read must not carry the service token")
				}
			}
		})
	}
}

func TestLiveReadIgnoresClaimsTheMarkerReplaces(t *testing.T) {
	api := newFakeAPI(t)
	api.on(http.MethodGet, livePermissionsPath, respond(200, liveAnswer([]string{}, []string{}, nil)))
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions_omitted": true, "permissions": []any{"p"}})
	wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", bearerHolding(token)), 403, insufficientPermission)
}

func TestLiveReadUsesOnlyTheConfiguredServer(t *testing.T) {
	api := newFakeAPI(t)
	api.on(http.MethodGet, livePermissionsPath, respond(200, liveAnswer([]string{"p"}, []string{}, nil)))
	a := newTestAdapter(t, api)
	elsewhere := newFakeAPI(t)
	token := permissionToken(t, api, map[string]any{
		"permissions_omitted": true, "authServerUrl": elsewhere.server.URL, "url": elsewhere.server.URL,
	})
	wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", bearerHolding(token)), 200, `{"ok":true}`)
	if len(api.callsTo(http.MethodGet, livePermissionsPath)) != 1 || len(elsewhere.callsTo(http.MethodGet, livePermissionsPath)) != 0 {
		t.Fatal("the live read went to the wrong server")
	}
}

func TestLiveReadNeitherCachesNorRetries(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
	h := permissionMux(a.RequirePermission("p"))

	api.on(http.MethodGet, livePermissionsPath, respond(200, liveAnswer([]string{"p"}, []string{}, nil)))
	wantBody(t, getWith(h, "", bearerHolding(token)), 200, `{"ok":true}`)
	api.on(http.MethodGet, livePermissionsPath, respond(200, liveAnswer([]string{}, []string{}, nil)))
	wantBody(t, getWith(h, "", bearerHolding(token)), 403, insufficientPermission)
	if got := len(api.callsTo(http.MethodGet, livePermissionsPath)); got != 2 {
		t.Fatalf("%d live reads, want 2", got)
	}

	api.on(http.MethodGet, livePermissionsPath, respond(500, map[string]any{}))
	before := len(api.callsTo(http.MethodGet, livePermissionsPath))
	wantBody(t, getWith(h, "", bearerHolding(token)), 503, `{"error":"permissions_unavailable"}`)
	if got := len(api.callsTo(http.MethodGet, livePermissionsPath)) - before; got != 1 {
		t.Fatalf("%d live reads for one failure, want 1", got)
	}
}

func TestLiveReadFailuresFailClosed(t *testing.T) {
	raw := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	valid := `{"roles":[],"permissions":["p"],"organizationId":null,"organizationRoles":[],"organizationPermissions":[]}`
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"500", respond(500, map[string]any{"permissions": []string{"p"}})},
		{"502", raw(502, "bad gateway")},
		{"503", raw(503, "")},
		{"404", respond(404, map[string]any{"error": "not_found"})},
		{"403", respond(403, map[string]any{"error": "forbidden"})},
		{"429", raw(429, valid)},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}},
		{"not modified", raw(304, "")},
		{"empty body", raw(200, "")},
		{"not JSON", raw(200, "<html>")},
		{"truncated JSON", raw(200, valid[:20])},
		{"JSON array", raw(200, `["p"]`)},
		{"JSON string", raw(200, `"p"`)},
		{"JSON null", raw(200, `null`)},
		{"empty object", raw(200, `{}`)},
		{"permissions a string", raw(200, `{"permissions":"p","organizationPermissions":[]}`)},
		{"permissions null", raw(200, `{"permissions":null,"organizationPermissions":[]}`)},
		{"organizationPermissions missing", raw(200, `{"permissions":["p"]}`)},
		{"organizationPermissions a string", raw(200, `{"permissions":["p"],"organizationPermissions":"p"}`)},
		{"organizationId a number", raw(200, `{"permissions":["p"],"organizationPermissions":[],"organizationId":1}`)},
		{"larger than the limit", raw(200, `{"permissions":["p"],"organizationPermissions":[],"pad":"`+strings.Repeat("x", maxBodyBytes)+`"}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.on(http.MethodGet, livePermissionsPath, c.handler)
			var logged []string
			a := newTestAdapter(t, api, func(o *Options) {
				o.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			})
			token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
			for _, credential := range []func(*http.Request){bearerHolding(token), cookieHolding(t, token)} {
				wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", credential), 503, `{"error":"permissions_unavailable"}`)
			}
			if len(logged) == 0 {
				t.Fatal("no warning logged")
			}
			for _, line := range logged {
				if strings.Contains(line, token) {
					t.Fatalf("logged the token: %s", line)
				}
			}
		})
	}
}

func TestLiveReadTimeoutAndUnreachable(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		api := newFakeAPI(t)
		release := make(chan struct{})
		defer close(release)
		api.on(http.MethodGet, livePermissionsPath, func(http.ResponseWriter, *http.Request) { <-release })
		a := newTestAdapter(t, api, func(o *Options) {
			o.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
		})
		token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
		wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", bearerHolding(token)), 503, `{"error":"permissions_unavailable"}`)
	})

	t.Run("unreachable", func(t *testing.T) {
		api := newFakeAPI(t)
		a := newTestAdapter(t, api, func(o *Options) {
			o.HTTPClient = &http.Client{Transport: failLiveRead{http.DefaultTransport}}
		})
		token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
		wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", bearerHolding(token)), 503, `{"error":"permissions_unavailable"}`)
	})
}

// failLiveRead lets the key set through, so the token still verifies.
type failLiveRead struct{ next http.RoundTripper }

func (f failLiveRead) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == livePermissionsPath {
		return nil, errors.New("connection refused")
	}
	return f.next.RoundTrip(r)
}

func TestLiveReadAnswering401IsTheExisting401(t *testing.T) {
	api := newFakeAPI(t)
	api.on(http.MethodGet, livePermissionsPath, respond(401, map[string]any{"error": "invalid_token"}))
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
	for _, credential := range []func(*http.Request){bearerHolding(token), cookieHolding(t, token)} {
		wantBody(t, getWith(permissionMux(a.RequirePermission("p")), "", credential), 401, `{"error":"unauthenticated"}`)
	}
}

func TestEmptyListNeverStartsALiveRead(t *testing.T) {
	api := newFakeAPI(t)
	api.on(http.MethodGet, livePermissionsPath, respond(500, map[string]any{}))
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions_omitted": true})
	for _, opts := range [][]PermissionOption{nil, {AllPermissions()}, {InOrganization()}, {InRouteOrganization("org")}} {
		wantBody(t, getWith(permissionMux(a.RequirePermissionWith(nil, opts...)), "", bearerHolding(token)), 403, insufficientPermission)
	}
	if got := len(api.callsTo(http.MethodGet, livePermissionsPath)); got != 0 {
		t.Fatalf("%d live reads", got)
	}
}

func TestRequirePermissionPutsTheUserOnTheContext(t *testing.T) {
	api := newFakeAPI(t)
	a := newTestAdapter(t, api)
	token := permissionToken(t, api, map[string]any{"permissions": []any{"p"}})
	h := a.RequirePermission("p")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			t.Error("no user on the context")
			return
		}
		writeJSON(w, 200, map[string]any{"id": user.ID})
	}))
	rec := getWith(h, "", bearerHolding(token))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["id"] != "u1" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestVerifierRequirePermissionMatching(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	header := map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}
	for _, c := range permissionMatchCases() {
		t.Run(c.name, func(t *testing.T) {
			h := permissionMux(func(next http.Handler) http.Handler {
				return v.RequireToken(v.RequirePermissionWith(c.permissions, c.opts...)(next))
			})
			rec := getWith(h, c.path, bearerHolding(p.sign(t, header, c.claims, "")))
			if c.allowed {
				wantBody(t, rec, 200, `{"ok":true}`)
			} else {
				wantBody(t, rec, 403, insufficientPermission)
				if got := rec.Header().Get("WWW-Authenticate"); got != "" {
					t.Fatalf("WWW-Authenticate %q", got)
				}
			}
		})
	}
}

func TestVerifierDeniesATodaysProviderToken(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	h := permissionMux(func(next http.Handler) http.Handler {
		return v.RequireToken(v.RequirePermission("a", "orders:read")(next))
	})
	// Carries a scope and a role of the same name, and neither counts.
	token := p.sign(t, map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}, map[string]any{"scope": "a", "roles": []any{"a"}}, "")
	wantBody(t, getWith(h, "", bearerHolding(token)), 403, insufficientPermission)
}

func TestVerifierOmittedIsARefusalNotALiveRead(t *testing.T) {
	p := newFakeProvider(t, false)
	var outbound int
	v, err := NewVerifier(VerifierOptions{
		Issuer:   p.server.URL,
		Audience: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "permissions") {
				outbound++
			}
			return http.DefaultTransport.RoundTrip(r)
		})},
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := permissionMux(func(next http.Handler) http.Handler {
		return v.RequireToken(v.RequirePermission("p")(next))
	})
	token := p.sign(t, map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}, map[string]any{"permissions_omitted": true, "permissions": []any{"p"}}, "")
	wantBody(t, getWith(h, "", bearerHolding(token)), 403, insufficientPermission)
	if outbound != 0 {
		t.Fatalf("%d live reads", outbound)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifierExposesPermissionClaims(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	header := map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}

	user, err := v.Authenticate(bearerRequest(p.sign(t, header, map[string]any{
		"permissions": []any{"a", 1}, "org_id": "org-a", "org_roles": []any{"admin"}, "org_permissions": []any{"b"},
	}, "")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(user.Permissions, []string{"a"}) || !slices.Equal(user.OrganizationRoles, []string{"admin"}) ||
		!slices.Equal(user.OrganizationPermissions, []string{"b"}) || user.PermissionsOmitted || user.OrgID != "org-a" {
		t.Fatalf("%+v", user)
	}

	// A malformed permission claim reads as empty and does not fail verification,
	// unlike a malformed roles claim.
	user, err = v.Authenticate(bearerRequest(p.sign(t, header, map[string]any{
		"permissions": "a", "org_roles": 1, "org_permissions": map[string]any{}, "permissions_omitted": true,
	}, "")))
	if err != nil {
		t.Fatal(err)
	}
	if len(user.Permissions)+len(user.OrganizationRoles)+len(user.OrganizationPermissions) != 0 || !user.PermissionsOmitted {
		t.Fatalf("%+v", user)
	}
}

func TestVerifierPermissionGuardWithoutRequireTokenAnswersMissingToken(t *testing.T) {
	v, _ := NewVerifier(VerifierOptions{Issuer: "https://login.example", Audience: "a"})
	rec := httptest.NewRecorder()
	v.RequirePermission("x")(http.NotFoundHandler()).ServeHTTP(rec, bearerRequest("whatever"))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
