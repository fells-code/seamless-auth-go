package seamlessauth

import (
	"errors"
	"fmt"
	"net/http"
)

const livePermissionsPath = "/users/me/permissions"

// PermissionOption configures RequirePermissionWith.
type PermissionOption func(*permissionRule)

// AllPermissions requires every listed permission, rather than at least one. Each
// may come from either claim, unless an organization option narrows that.
func AllPermissions() PermissionOption {
	return func(rule *permissionRule) { rule.all = true }
}

// InOrganization counts only the active organization's permissions, and refuses a
// session with no active organization. It does not say which organization: on a
// route naming one, use InRouteOrganization, or a token for organization A passes
// on /orgs/B/...
func InOrganization() PermissionOption {
	return func(rule *permissionRule) { rule.organization = true }
}

// InRouteOrganization is InOrganization that also requires the route parameter
// param, read with r.PathValue, to equal the active organization exactly. A missing
// parameter is refused.
func InRouteOrganization(param string) PermissionOption {
	return func(rule *permissionRule) {
		rule.organization = true
		rule.bound = true
		rule.param = param
	}
}

type permissionRule struct {
	required     []string
	all          bool
	organization bool
	bound        bool
	param        string
}

func newPermissionRule(permissions []string, opts []PermissionOption) *permissionRule {
	rule := &permissionRule{required: append([]string(nil), permissions...)}
	for _, opt := range opts {
		opt(rule)
	}
	return rule
}

// heldPermissions is what a session holds, from its token or the live read.
type heldPermissions struct {
	permissions             []string
	organizationPermissions []string
	organizationID          string
}

// allows matches exactly, unlike RoleGrantsAccess: a permission implies nothing
// else, so a plain membership test against the token gives the same answer.
func (rule *permissionRule) allows(r *http.Request, held heldPermissions) bool {
	if len(rule.required) == 0 {
		return false
	}
	granted := append(append([]string(nil), held.permissions...), held.organizationPermissions...)
	if rule.organization {
		if held.organizationID == "" {
			return false
		}
		if rule.bound && r.PathValue(rule.param) != held.organizationID {
			return false
		}
		granted = held.organizationPermissions
	}
	if rule.all {
		for _, permission := range rule.required {
			if !contains(granted, permission) {
				return false
			}
		}
		return true
	}
	for _, permission := range rule.required {
		if contains(granted, permission) {
			return true
		}
	}
	return false
}

// RequirePermission is RequireAuth that also answers 403 insufficient_permission
// unless the session holds at least one of permissions, in the permissions or
// org_permissions claim of the verified access token. Matching is exact. No
// permissions means no one passes. A token with permissions_omitted is answered
// from the auth API, and 503 permissions_unavailable when that read fails.
func (a *Adapter) RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return a.RequirePermissionWith(permissions)
}

// RequirePermissionWith is RequirePermission with options.
func (a *Adapter) RequirePermissionWith(permissions []string, opts ...PermissionOption) func(http.Handler) http.Handler {
	rule := newPermissionRule(permissions, opts)
	check := func(w http.ResponseWriter, r *http.Request, user *User) bool {
		if len(rule.required) == 0 {
			writeInsufficientPermission(w)
			return false
		}
		held := heldPermissions{user.Permissions, user.OrganizationPermissions, user.OrganizationID}
		if user.PermissionsOmitted {
			var err error
			if held, err = a.livePermissions(r, user.Token); errors.Is(err, errUnauthenticated) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
				return false
			} else if err != nil {
				a.opts.Logf("[seamless-auth] Refusing a request: the live permission read failed (%v).", err)
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "permissions_unavailable"})
				return false
			}
		}
		if !rule.allows(r, held) {
			writeInsufficientPermission(w)
			return false
		}
		return true
	}
	return func(next http.Handler) http.Handler {
		return a.requireSession(check, next)
	}
}

func writeInsufficientPermission(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient_permission"})
}

// livePermissions asks the auth API what the caller holds now. It neither caches
// nor retries: it runs only for a token too large to carry the answer.
func (a *Adapter) livePermissions(r *http.Request, token string) (heldPermissions, error) {
	res, err := a.call(r.Context(), r, upstreamCall{
		method:        http.MethodGet,
		path:          livePermissionsPath,
		authorization: "Bearer " + token,
	})
	if err != nil {
		return heldPermissions{}, upstreamError(err)
	}
	body, isJSON := readJSON(res)
	if res.StatusCode == http.StatusUnauthorized {
		return heldPermissions{}, errUnauthenticated
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return heldPermissions{}, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if !isJSON {
		return heldPermissions{}, errors.New("response is not JSON")
	}
	return parseLivePermissions(body)
}

// parseLivePermissions treats a response of the wrong shape as a failed read, so
// it answers 503 rather than reading as holding nothing, as a malformed claim does.
// Entries that are not strings are still skipped, as in a claim.
func parseLivePermissions(body any) (heldPermissions, error) {
	object, ok := body.(map[string]any)
	if !ok {
		return heldPermissions{}, errors.New("response is not an object")
	}
	for _, member := range []string{"permissions", "organizationPermissions"} {
		if _, ok := object[member].([]any); !ok {
			return heldPermissions{}, fmt.Errorf("%s is not an array", member)
		}
	}
	var organizationID string
	if raw := object["organizationId"]; raw != nil {
		if organizationID, ok = raw.(string); !ok {
			return heldPermissions{}, errors.New("organizationId is not a string")
		}
	}
	return heldPermissions{
		permissions:             stringsClaim(object, "permissions"),
		organizationPermissions: stringsClaim(object, "organizationPermissions"),
		organizationID:          organizationID,
	}, nil
}
