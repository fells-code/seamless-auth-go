package seamlessauth

import (
	"context"
	"encoding/json"
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

// The auth API consumes a magic link on the device that requested it, which it
// recognises by that flow's pre-auth token. The token is optional: without it
// the API asks for confirmation instead, so its absence is never a 401 here.
const magicLinkVerifyPath = "/magic-link/verify/{token}"

func isMagicLinkVerify(route ManifestRoute) bool {
	return route.Method == http.MethodGet && route.Path == magicLinkVerifyPath
}

func (a *Adapter) optionalPreAuth(r *http.Request, bearer bool) credential {
	if bearer {
		if token := bearerToken(r); token != "" {
			return credential{authorization: "Bearer " + token}
		}
		return credential{}
	}
	payload, valid := a.readCookie(r, a.opts.cookieName("preAuth"), cookieKind("preAuth"))
	if token := stringClaim(payload, "token"); valid && token != "" {
		return credential{authorization: "Bearer " + token}
	}
	return credential{}
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// isExplicitJSON is a JSON request content type. Unlike a response, a request
// with no content type is not taken as JSON.
func isExplicitJSON(contentType string) bool {
	return contentType != "" && isJSONContentType(contentType)
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

// cookieTransportBody is what a browser sees: a pick, or the whole body, never
// with tokens. The cookies carry every token, including the ephemeral one the
// auth API re-mints on an OTP send.
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
	} else {
		for k, v := range obj {
			out[k] = v
		}
	}
	delete(out, "token")
	delete(out, "refreshToken")
	return out
}

func (a *Adapter) manifestRoute(r *http.Request, match routeMatch, bearer bool) result {
	route := match.route
	if route.Credential == "refresh" {
		return errorResult(http.StatusNotFound, "not_found")
	}

	body, err := readRequestBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return errorResult(http.StatusRequestEntityTooLarge, "payload_too_large")
		}
		return errorResult(http.StatusBadRequest, "bad_request")
	}
	// The body goes upstream as JSON, so it has to be JSON. A cross-site form can
	// send a text/plain body shaped like JSON with no CORS preflight; read as JSON,
	// that would be a sign-in the victim never made.
	if body != nil && !isExplicitJSON(r.Header.Get("Content-Type")) {
		return errorResult(http.StatusUnsupportedMediaType, "unsupported_media_type")
	}

	var cred credential
	if isMagicLinkVerify(route) {
		cred = a.optionalPreAuth(r, bearer)
	} else {
		var rejected *result
		cred, rejected = a.credentialFor(r, route.Credential, bearer)
		if rejected != nil {
			return *rejected
		}
	}

	// A route that can hand back account notices is left to the auth API unless
	// Deliver sends them too: the API takes a notice it hands back as delivered.
	ownsDelivery := a.opts.Deliver != nil && (!route.Notices || a.opts.DeliverAccountNotices)
	external := (route.Delivery || route.Notices) && ownsDelivery
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
		if route.Notices {
			call.headers[deliveryKindsHeader] = DeliveryAccountNoticeEmail + "," + DeliveryAccountNoticeSMS
		}
	}

	res, err := a.call(r.Context(), r, call)
	if err != nil {
		a.opts.Logf("[seamless-auth] %s %s: %v", route.Method, route.Path, upstreamError(err))
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

	// A message is the application's to send, and holds a one-time credential, so
	// it never goes back to the caller in either transport.
	if obj, ok := data.(map[string]any); ok && (route.Delivery || route.Notices) {
		single := obj["delivery"]
		notices, _ := obj["deliveries"].([]any)
		delete(obj, "delivery")
		delete(obj, "deliveries")

		if external && single != nil {
			if _, err := a.deliverAll(r.Context(), route, []any{single}); err != nil {
				out := errorResult(http.StatusBadGateway, "delivery_failed")
				out.set = cred.set
				return out
			}
		}
		// The auth API opened the request and counted the owner as told when it
		// handed the notices back. If none reached the owner, the request must not
		// stay open behind their back.
		if external && route.Notices && len(notices) > 0 {
			if delivered, _ := a.deliverAll(r.Context(), route, notices); delivered == 0 {
				a.cancelRecovery(r, notices)
				out := errorResult(http.StatusServiceUnavailable, "recovery_notice_failed")
				out.set = cred.set
				return out
			}
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

	if !bearer && enrollmentRoutes[route.Method+" "+route.Path] && isRecoveryToken(cred.authorization) {
		cookies, err := a.refreshAfterEnrollment(r, cred)
		if err != nil {
			a.opts.Logf("[seamless-auth] Could not refresh a recovery session after enrollment: %v", err)
		} else {
			out.set = cookies
		}
	}

	if !bearer {
		out.body = cookieTransportBody(route, data)
	}
	return out
}

// deliverAll hands every message to Deliver, even after one fails, so that as
// many notices as possible reach the owner, and reports how many were sent. A
// kind this adapter does not send is logged and skipped.
func (a *Adapter) deliverAll(ctx context.Context, route ManifestRoute, messages []any) (int, error) {
	var failed error
	delivered := 0
	for _, raw := range messages {
		d, err := parseDelivery(raw)
		if err == nil && !a.sends(d.Kind) {
			a.opts.Logf("[seamless-auth] Unsupported delivery kind %q from %s %s, so no message was sent.", d.Kind, route.Method, route.Path)
			continue
		}
		if err == nil {
			err = a.opts.Deliver(ctx, d)
		}
		if err != nil {
			a.opts.Logf("[seamless-auth] Delivery for %s %s failed: %v", route.Method, route.Path, err)
			if failed == nil {
				failed = err
			}
			continue
		}
		delivered++
	}
	return delivered, failed
}

// cancelRecovery voids the recovery request the notices are about, with the
// cancel token in the fragment of their cancel link. Neither is ever logged.
func (a *Adapter) cancelRecovery(r *http.Request, notices []any) {
	var token string
	for _, raw := range notices {
		obj, _ := raw.(map[string]any)
		if _, fragment, ok := strings.Cut(stringClaim(obj, "cancelUrl"), "#"); ok && fragment != "" {
			token = fragment
			break
		}
	}
	if token == "" {
		a.opts.Logf("[seamless-auth] No account notice was delivered and none carried a cancel link, so the recovery request stays open.")
		return
	}

	body, err := json.Marshal(map[string]string{"cancelToken": token})
	if err != nil {
		return
	}
	res, err := a.call(r.Context(), r, upstreamCall{
		method:  http.MethodPost,
		path:    "/recovery/cancel",
		body:    body,
		service: a.tokens.proxyAuthorization(),
	})
	if err != nil {
		a.opts.Logf("[seamless-auth] Could not cancel a recovery request no notice reached: %v", upstreamError(err))
		return
	}
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		a.opts.Logf("[seamless-auth] Cancelling a recovery request no notice reached answered %d.", res.StatusCode)
	}
}

func (a *Adapter) sends(kind string) bool {
	if kind == DeliveryAccountNoticeEmail || kind == DeliveryAccountNoticeSMS {
		return a.opts.DeliverAccountNotices
	}
	return knownDeliveryKinds[kind]
}

// Enrolling a passkey or authenticator app lifts a recovery session's
// restriction, but the access token keeps its recovery claim until it is
// refreshed.
var enrollmentRoutes = set("POST /webauthn/register/finish", "POST /totp/enroll/verify")

// isRecoveryToken reads the recovery claim of a token the adapter already
// verified, before signing it into a cookie or on a refresh.
func isRecoveryToken(authorization string) bool {
	parsed, err := parseJWT(strings.TrimPrefix(authorization, "Bearer "))
	return err == nil && parsed.claims["recovery"] == true
}

// refreshAfterEnrollment rotates the session the request ended on: the refresh
// token a silent refresh just issued, or else the refresh cookie.
func (a *Adapter) refreshAfterEnrollment(r *http.Request, cred credential) ([]cookieWrite, error) {
	for _, c := range cred.set {
		if c.name == a.opts.RefreshCookieName {
			sub, token := stringClaim(c.value, "sub"), stringClaim(c.value, "refreshToken")
			_, cookies, err := a.refreshSession(r, "token:"+token, func() (string, string) { return sub, token })
			return cookies, err
		}
	}
	_, cookies, err := a.silentRefresh(r)
	return cookies, err
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
