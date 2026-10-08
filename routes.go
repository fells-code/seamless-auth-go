package seamlessauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// credential is what the adapter sends for a route, and any cookies a silent
// refresh produced on the way.
type credential struct {
	authorization string
	set           []cookieWrite
}

// credentialFor resolves the held token a route names. In cookie transport it
// reads the route's cookie, refreshing a missing access token from the refresh
// cookie; in bearer transport the client holds its own token.
func (a *Adapter) credentialFor(r *http.Request, kind string, bearer bool) (credential, *result) {
	if kind == "none" {
		return credential{}, nil
	}

	if bearer {
		token := bearerToken(r)
		if token == "" {
			res := errorResult(http.StatusUnauthorized, kind+" session required")
			return credential{}, &res
		}
		return credential{authorization: "Bearer " + token}, nil
	}

	name := a.opts.cookieName(kind)
	_, missing := r.Cookie(name)
	hasCookie := missing == nil
	payload, valid := a.readCookie(r, name, cookieKind(kind))
	token := stringClaim(payload, "token")

	if valid && token != "" {
		return credential{authorization: "Bearer " + token}, nil
	}

	// A refresh only ever yields an access token, so only the access cookie can be
	// restored from it. Spending it for a pre-auth or registration route would
	// store an access token under that route's cookie. A cookie that fails
	// verification is refused rather than refreshed past.
	if kind == "access" && (!hasCookie || valid) {
		session, cookies, err := a.silentRefresh(r)
		if err == nil {
			return credential{authorization: "Bearer " + stringClaim(session, "token"), set: cookies}, nil
		}
		if !errors.Is(err, errNoRefreshCookie) {
			res := errorResult(http.StatusUnauthorized, "Refresh failed")
			res.clear = []string{a.opts.AccessCookieName, a.opts.RegistrationCookieName, a.opts.RefreshCookieName}
			return credential{}, &res
		}
	}

	if hasCookie {
		res := errorResult(http.StatusUnauthorized, "Invalid or expired "+name+" cookie")
		return credential{}, &res
	}
	res := errorResult(http.StatusUnauthorized, `Missing required cookie "`+name+`"`)
	return credential{}, &res
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// verifySession checks the token in a session response: signed by the auth API,
// of the expected type, and belonging to the subject the body names. It returns
// the session id. A response that fails any of these is one this adapter cannot
// vouch for, so nothing is issued from it.
func (a *Adapter) verifySession(ctx context.Context, session map[string]any, typ string) (string, error) {
	claims, err := a.jwks.verifyAuthToken(ctx, stringClaim(session, "token"), a.opts.AuthServerIssuer, a.opts.Audience)
	if err != nil {
		return "", err
	}
	if stringClaim(claims, "typ") != typ {
		return "", errors.New("unexpected token type")
	}
	if stringClaim(claims, "sub") != stringClaim(session, "sub") {
		return "", errors.New("token subject does not match the response")
	}
	return stringClaim(claims, "sid"), nil
}

// issuedTokenType is the type of token a route that issues a session must return.
func issuedTokenType(issues string) string {
	if issues == "preAuth" || issues == "registration" {
		return "ephemeral"
	}
	return "access"
}

func carriesSession(body any) (map[string]any, bool) {
	obj, ok := body.(map[string]any)
	if !ok {
		return nil, false
	}
	return obj, stringClaim(obj, "token") != "" && stringClaim(obj, "sub") != ""
}

// cookieTransportBody is what a browser sees: a pick, or everything but tokens.
// The cookies carry every token, including the ephemeral one the auth API
// re-mints on an OTP send.
func cookieTransportBody(route ManifestRoute, body any) any {
	obj, ok := body.(map[string]any)
	if !ok {
		return body
	}

	out := map[string]any{}
	if route.Body != nil {
		for _, key := range route.Body.Pick {
			if v, ok := obj[key]; ok {
				out[key] = v
			}
		}
		return out
	}
	for k, v := range obj {
		if k != "token" && k != "refreshToken" {
			out[k] = v
		}
	}
	return out
}

func (a *Adapter) manifestRoute(r *http.Request, match routeMatch, bearer bool) result {
	route := match.route
	if route.Credential == "refresh" {
		return errorResult(http.StatusNotFound, "not_found")
	}

	cred, rejected := a.credentialFor(r, route.Credential, bearer)
	if rejected != nil {
		return *rejected
	}

	body, err := readRequestBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return errorResult(http.StatusRequestEntityTooLarge, "payload_too_large")
		}
		return errorResult(http.StatusBadRequest, "bad_request")
	}

	external := route.Delivery && a.opts.Deliver != nil
	call := upstreamCall{
		method:        route.Method,
		path:          route.upstreamPath(match.params),
		rawQuery:      r.URL.RawQuery,
		body:          body,
		authorization: cred.authorization,
		service:       a.tokens.proxyAuthorization(),
	}
	if external {
		call.service = a.tokens.deliveryAuthorization()
		call.headers = map[string]string{deliveryModeHeader: "external"}
	}

	res, err := a.call(r.Context(), r, call)
	if err != nil {
		a.opts.Logf("[seamless-auth] %s %s: %v", route.Method, route.Path, err)
		out := errorResult(http.StatusBadGateway, "upstream_unavailable")
		out.set = cred.set
		return out
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 && !isJSONContentType(res.Header.Get("Content-Type")) {
		return result{status: res.StatusCode, raw: res, set: cred.set}
	}

	data, isJSON := readJSON(res)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		out := failure(res.StatusCode, data, isJSON)
		out.set = cred.set
		return out
	}

	if external {
		if obj, ok := data.(map[string]any); ok && obj["delivery"] != nil {
			delivery, err := parseDelivery(obj["delivery"])
			if err == nil {
				err = a.opts.Deliver(r.Context(), delivery)
			}
			if err != nil {
				a.opts.Logf("[seamless-auth] Delivery for %s %s failed: %v", route.Method, route.Path, err)
				out := errorResult(http.StatusBadGateway, "delivery_failed")
				out.set = cred.set
				return out
			}
			delete(obj, "delivery")
		}
	}

	out := result{status: res.StatusCode, body: data, set: cred.set}
	for _, held := range route.Clears {
		out.clear = append(out.clear, a.opts.cookieName(held))
	}

	session, issued := carriesSession(data)
	if route.Issues != "" && issued {
		sessionID, err := a.verifySession(r.Context(), session, issuedTokenType(route.Issues))
		if err != nil {
			a.opts.Logf("[seamless-auth] Refusing an unverifiable session from %s %s: %v", route.Method, route.Path, err)
			return errorResult(http.StatusBadGateway, "invalid_upstream_session")
		}

		if !bearer {
			cookies, err := a.issuedCookies(route.Issues, session, sessionID)
			if err != nil {
				a.opts.Logf("[seamless-auth] %s %s: %v", route.Method, route.Path, err)
				return errorResult(http.StatusBadGateway, "invalid_upstream_session")
			}
			out.set = append(out.set, cookies...)
		}
	}

	if !bearer {
		out.body = cookieTransportBody(route, data)
	}
	return out
}

func (a *Adapter) issuedCookies(issues string, session map[string]any, sessionID string) ([]cookieWrite, error) {
	switch issues {
	case "preAuth", "registration":
		ttl, err := ttlSeconds(session["ttl"])
		if err != nil {
			return nil, err
		}
		return []cookieWrite{{
			name:   a.opts.cookieName(issues),
			kind:   kindEphemeral,
			value:  map[string]any{"sub": session["sub"], "token": session["token"]},
			maxAge: ttl,
		}}, nil
	case "session":
		return a.sessionCookies(session, sessionID, true)
	default:
		return a.sessionCookies(session, sessionID, false)
	}
}
