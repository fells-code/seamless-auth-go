package seamlessauth

import (
	"context"
	"errors"
	"net/http"
)

// User is the session a request was authenticated with.
type User struct {
	ID    string
	Roles []string
	Email string
	Phone string
	// OrganizationID is the active organization, the org_id claim of the verified
	// access token. Empty when the session has none.
	OrganizationID string
	// Permissions, OrganizationRoles and OrganizationPermissions are the
	// permissions, org_roles and org_permissions claims of the verified access
	// token. Organization roles never count for RequireRole.
	Permissions             []string
	OrganizationRoles       []string
	OrganizationPermissions []string
	// PermissionsOmitted is a token whose permissions and organization roles did
	// not fit. The three lists above are then unknown rather than empty, and
	// RequirePermission reads them from the auth API.
	PermissionsOmitted bool
	// Token is the auth API access token, for calling the API on the user's behalf.
	Token string
	// Recovery is a session a recovery code issued, before the user enrolled a
	// new passkey or authenticator app. Only with AllowRecoverySessions.
	Recovery bool
}

type userKey struct{}

// UserFromContext returns the user RequireAuth authenticated.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userKey{}).(*User)
	return user, ok
}

var errUnauthenticated = errors.New("unauthenticated")

// ErrEnrollmentRequired is a valid session from a recovery code, refused until
// the user enrolls a new passkey or authenticator app (see AllowRecoverySessions).
var ErrEnrollmentRequired = errors.New("enrollment required")

// Authenticate verifies the request's session: the adapter's access cookie, or an
// auth API access token in Authorization: Bearer for clients with no cookie jar.
// The cookie wins when present. It reads the Cookie header itself, so it works on
// any route. A cookie's inner access token is verified as a bearer token is, and
// the session's roles come from it. It does not refresh: silent refresh belongs
// to the auth routes, and a bearer client refreshes through POST /refresh itself.
// A recovery session is ErrEnrollmentRequired unless AllowRecoverySessions is set.
func (a *Adapter) Authenticate(r *http.Request) (*User, error) {
	user, _, err := a.authenticate(r)
	return user, err
}

// authenticate is Authenticate, also reporting whether the session came from the
// cookie, which a browser attaches on its own.
func (a *Adapter) authenticate(r *http.Request) (*User, bool, error) {
	user, byCookie, err := a.session(r)
	if err == nil && user.Recovery && !a.opts.AllowRecoverySessions {
		return nil, byCookie, ErrEnrollmentRequired
	}
	return user, byCookie, err
}

func (a *Adapter) session(r *http.Request) (*User, bool, error) {
	if c, err := r.Cookie(a.opts.AccessCookieName); err == nil && c.Value != "" {
		claims, ok := a.readCookie(r, a.opts.AccessCookieName, kindAccess)
		sub := stringClaim(claims, "sub")
		if !ok || sub == "" {
			return nil, true, errUnauthenticated
		}
		// The cookie secret alone can sign a cookie, so the token inside it is held
		// to the auth API's key set, and the session's roles come from that token.
		token := stringClaim(claims, "token")
		inner, err := a.verifyAccessToken(r.Context(), token)
		if err != nil || stringClaim(inner, "sub") != sub {
			return nil, true, errUnauthenticated
		}
		user := userFrom(claims, token)
		user.Roles = rolesFrom(inner)
		user.OrganizationID = stringClaim(inner, "org_id")
		user.Recovery = inner["recovery"] == true
		user.readPermissionClaims(inner)
		return user, true, nil
	}

	token := bearerToken(r)
	if token == "" {
		return nil, false, errUnauthenticated
	}
	claims, err := a.verifyAccessToken(r.Context(), token)
	if err != nil {
		return nil, false, errUnauthenticated
	}
	user := userFrom(claims, token)
	user.OrganizationID = stringClaim(claims, "org_id")
	user.Recovery = claims["recovery"] == true
	user.readPermissionClaims(claims)
	return user, false, nil
}

// verifyAccessToken checks an auth API access token against the API's key set.
// An ephemeral sign-in token is signed by the same key, so the type is what
// keeps it from passing for a session.
func (a *Adapter) verifyAccessToken(ctx context.Context, token string) (map[string]any, error) {
	if token == "" {
		return nil, errUnauthenticated
	}
	claims, err := a.jwks.verifyAuthToken(ctx, token, a.opts.AuthServerIssuer, a.opts.Audience)
	if err != nil || stringClaim(claims, "typ") != "access" || stringClaim(claims, "sub") == "" {
		return nil, errUnauthenticated
	}
	return claims, nil
}

func userFrom(claims map[string]any, token string) *User {
	user := &User{
		ID:    stringClaim(claims, "sub"),
		Email: stringClaim(claims, "email"),
		Phone: stringClaim(claims, "phone"),
		Token: token,
	}
	user.Roles = rolesFrom(claims)
	return user
}

func rolesFrom(claims map[string]any) []string {
	return stringsClaim(claims, "roles")
}

// stringsClaim reads a claim that is not an array as empty, and skips entries that
// are not strings.
func stringsClaim(claims map[string]any, name string) []string {
	var out []string
	if list, ok := claims[name].([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (u *User) readPermissionClaims(claims map[string]any) {
	u.Permissions = stringsClaim(claims, "permissions")
	u.OrganizationRoles = stringsClaim(claims, "org_roles")
	u.OrganizationPermissions = stringsClaim(claims, "org_permissions")
	u.PermissionsOmitted = claims["permissions_omitted"] == true
}

// RequireAuth answers 401 unless the request carries a valid session, and puts
// the user on the request context for next. A cookie session is refused with 403
// for a cross-site state change, as on the auth routes, and a recovery session
// with 403 enrollment_required unless AllowRecoverySessions is set.
func (a *Adapter) RequireAuth(next http.Handler) http.Handler {
	return a.requireSession(nil, next)
}

// RequireRole is RequireAuth that also answers 403 insufficient_role unless the
// session's roles grant at least one of roles, matched as RoleGrantsAccess does.
// The roles are those of the verified access token. It panics when given no
// role, or an empty one.
func (a *Adapter) RequireRole(roles ...string) func(http.Handler) http.Handler {
	if len(roles) == 0 {
		panic("seamlessauth: RequireRole needs at least one role")
	}
	for _, role := range roles {
		if trimJS(role) == "" {
			panic("seamlessauth: RequireRole was given an empty role")
		}
	}
	roles = append([]string(nil), roles...)
	check := func(w http.ResponseWriter, _ *http.Request, user *User) bool {
		for _, required := range roles {
			for _, granted := range user.Roles {
				if RoleGrantsAccess(granted, required) {
					return true
				}
			}
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient_role"})
		return false
	}
	return func(next http.Handler) http.Handler {
		return a.requireSession(check, next)
	}
}

// requireSession runs check, when given, on the authenticated user. A check that
// returns false has answered the request.
func (a *Adapter) requireSession(check func(http.ResponseWriter, *http.Request, *User) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, byCookie, err := a.authenticate(r)
		if errors.Is(err, ErrEnrollmentRequired) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "enrollment_required"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			return
		}
		// A cookie session gets the same cross-site check as the auth routes, or a
		// form on another site could act as the user.
		if byCookie {
			if res, blocked := a.checkOrigin(r); blocked {
				a.write(w, res, false)
				return
			}
		}
		if check != nil && !check(w, r, user) {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}
