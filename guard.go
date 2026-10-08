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
	// Token is the auth API access token, for calling the API on the user's behalf.
	Token string
}

type userKey struct{}

// UserFromContext returns the user RequireAuth authenticated.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userKey{}).(*User)
	return user, ok
}

var errUnauthenticated = errors.New("unauthenticated")

// Authenticate verifies the request's session: the adapter's access cookie, or an
// auth API access token in Authorization: Bearer for clients with no cookie jar.
// The cookie wins when present. It reads the Cookie header itself, so it works on
// any route. It does not refresh: silent refresh belongs to the auth routes, and a
// bearer client refreshes through POST /refresh itself.
func (a *Adapter) Authenticate(r *http.Request) (*User, error) {
	user, _, err := a.authenticate(r)
	return user, err
}

// authenticate is Authenticate, also reporting whether the session came from the
// cookie, which a browser attaches on its own.
func (a *Adapter) authenticate(r *http.Request) (*User, bool, error) {
	if c, err := r.Cookie(a.opts.AccessCookieName); err == nil && c.Value != "" {
		claims, ok := a.readCookie(r, a.opts.AccessCookieName, kindAccess)
		token := stringClaim(claims, "token")
		if !ok || stringClaim(claims, "sub") == "" || !isAccessToken(token) {
			return nil, true, errUnauthenticated
		}
		return userFrom(claims, token), true, nil
	}

	token := bearerToken(r)
	if token == "" {
		return nil, false, errUnauthenticated
	}
	claims, err := a.jwks.verifyAuthToken(r.Context(), token, a.opts.AuthServerIssuer, a.opts.Audience)
	// An ephemeral sign-in token is signed by the same key, so the type is what
	// keeps it from passing for a session.
	if err != nil || stringClaim(claims, "typ") != "access" || stringClaim(claims, "sub") == "" {
		return nil, false, errUnauthenticated
	}
	return userFrom(claims, token), false, nil
}

// isAccessToken reads the type of the auth API token inside a session cookie. It
// was verified against the API's key set before the adapter signed it into the
// cookie, so its claims are read without verifying it again.
func isAccessToken(token string) bool {
	parsed, err := parseJWT(token)
	return err == nil && stringClaim(parsed.claims, "typ") == "access"
}

func userFrom(claims map[string]any, token string) *User {
	user := &User{
		ID:    stringClaim(claims, "sub"),
		Email: stringClaim(claims, "email"),
		Phone: stringClaim(claims, "phone"),
		Token: token,
	}
	if roles, ok := claims["roles"].([]any); ok {
		for _, role := range roles {
			if s, ok := role.(string); ok {
				user.Roles = append(user.Roles, s)
			}
		}
	}
	return user
}

// RequireAuth answers 401 unless the request carries a valid session, and puts
// the user on the request context for next. A cookie session is refused with 403
// for a cross-site state change, as on the auth routes.
func (a *Adapter) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, byCookie, err := a.authenticate(r)
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}
