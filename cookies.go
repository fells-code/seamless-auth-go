package seamlessauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Cookie kinds. Every cookie is signed with the same secret, so the kind is
// signed into the payload and checked on read: otherwise a cookie from one slot,
// such as the pre-auth cookie /login issues for any existing account, would pass
// in another.
const (
	kindAccess    = "access"
	kindRefresh   = "refresh"
	kindEphemeral = "ephemeral"
	kindClaim     = "kind"
)

type cookieWrite struct {
	name   string
	kind   string
	value  map[string]any
	maxAge int
}

func (a *Adapter) setCookie(w http.ResponseWriter, c cookieWrite) error {
	value := make(map[string]any, len(c.value)+1)
	for k, v := range c.value {
		value[k] = v
	}
	value[kindClaim] = c.kind

	signed, err := signHS256(value, a.opts.CookieSecret, time.Duration(c.maxAge)*time.Second, "")
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.name,
		Value:    signed,
		Path:     "/",
		Domain:   a.opts.CookieDomain,
		MaxAge:   c.maxAge,
		Expires:  time.Now().Add(time.Duration(c.maxAge) * time.Second),
		HttpOnly: true,
		Secure:   !a.opts.InsecureCookies,
		SameSite: a.opts.CookieSameSite,
	})
	return nil
}

func (a *Adapter) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   a.opts.CookieDomain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   !a.opts.InsecureCookies,
		SameSite: a.opts.CookieSameSite,
	})
}

// readCookie returns the verified payload of one of the adapter's cookies, if it
// is the kind expected in that slot.
func (a *Adapter) readCookie(r *http.Request, name, kind string) (map[string]any, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return nil, false
	}
	claims, err := verifyHS256(c.Value, a.opts.CookieSecret)
	if err != nil || stringClaim(claims, kindClaim) != kind {
		return nil, false
	}
	return claims, true
}

// cookieKind is the kind of cookie a held credential lives in.
func cookieKind(held string) string {
	switch held {
	case "access":
		return kindAccess
	case "refresh":
		return kindRefresh
	default:
		return kindEphemeral
	}
}

// ttlSeconds reads a lifetime the auth API sent, which may be a number or a
// numeric string. Anything that is not a positive whole number of seconds is
// refused: a cookie is the session, and one with a lifetime nobody can vouch for
// is worse than refusing the response.
func ttlSeconds(v any) (int, error) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err == nil && n > 0 {
			return int(n), nil
		}
	case string:
		n, err := strconv.Atoi(t)
		if err == nil && n > 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("unusable cookie ttl %v", v)
}

// sessionCookies builds the cookies for a verified session response: access, and
// refresh unless the response only reissues access.
func (a *Adapter) sessionCookies(session map[string]any, sessionID string, withRefresh bool) ([]cookieWrite, error) {
	ttl, err := ttlSeconds(session["ttl"])
	if err != nil {
		return nil, err
	}

	access := map[string]any{
		"sub":            session["sub"],
		"token":          session["token"],
		"roles":          session["roles"],
		"email":          session["email"],
		"phone":          session["phone"],
		"organizationId": session["organizationId"],
	}
	if sessionID != "" {
		access["sessionId"] = sessionID
	}
	cookies := []cookieWrite{{name: a.opts.AccessCookieName, kind: kindAccess, value: access, maxAge: ttl}}

	if withRefresh {
		refreshTTL, err := ttlSeconds(session["refreshTtl"])
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, cookieWrite{
			name:   a.opts.RefreshCookieName,
			kind:   kindRefresh,
			value:  map[string]any{"sub": session["sub"], "refreshToken": session["refreshToken"]},
			maxAge: refreshTTL,
		})
	}
	return cookies, nil
}
