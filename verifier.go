package seamlessauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	discoveryTimeout  = 5 * time.Second
	discoveryBackoff  = 5 * time.Second
	maxDiscoveryBytes = 256 << 10
)

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	// Issuer is the OpenID Provider's issuer (the auth API's oidc_issuer), an
	// absolute http or https URL. A token's iss must equal it exactly.
	Issuer string
	// Audience is this API's resource identifier. A token's aud must name it.
	Audience string
	// JWKSURI fetches the provider's keys from here instead of discovering them
	// from Issuer's /.well-known/openid-configuration.
	JWKSURI string
	// Confirm accepts a token bound to a key by a cnf claim (RFC 7800), for
	// example a DPoP proof's jkt. It is called only for a token that otherwise
	// verifies. Without it, any token carrying a cnf claim is refused.
	Confirm func(r *http.Request, cnf map[string]any) bool
	// HTTPClient fetches discovery and the key set. It never follows a redirect:
	// a supplied client is copied with a CheckRedirect that refuses them.
	HTTPClient *http.Client
	Logf       func(format string, args ...any)
}

// Verifier is the verify-only mode for a resource server: an API that receives
// the OpenID Provider's access tokens (RFC 9068) as Authorization: Bearer and
// only has to check them. It holds no cookie or service secret and serves no
// auth routes.
type Verifier struct {
	issuer      string
	issuerHTTPS bool
	audience    string
	confirm     func(*http.Request, map[string]any) bool
	client      *http.Client
	logf        func(string, ...any)
	now         func() time.Time

	mu          sync.Mutex
	jwks        *jwksCache
	attemptedAt time.Time
}

// TokenUser is the subject of a verified access token. For a client credentials
// token Subject is the client, and the user claims are empty.
type TokenUser struct {
	Subject  string
	ClientID string
	// Scopes is the scope claim split on spaces, in order.
	Scopes []string
	Roles  []string
	// SID is the provider's session id.
	SID   string
	OrgID string
	ACR   string
	AMR   []string
	// AuthTime is when the user last authenticated. Zero when the token has no
	// auth_time.
	AuthTime  time.Time
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Confirmation is the cnf claim of a token Confirm accepted.
	Confirmation map[string]any
	Token        string
	Claims       map[string]any

	authTime    float64
	hasAuthTime bool
}

var (
	// ErrMissingToken is a request with no bearer token, or an Authorization
	// header that is not exactly one.
	ErrMissingToken = errors.New("missing token")
	// ErrInvalidToken is a bearer token that does not verify, including when the
	// provider's keys cannot be fetched.
	ErrInvalidToken = errors.New("invalid token")
)

// NewVerifier validates opts and returns a Verifier.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	issuer, err := url.Parse(opts.Issuer)
	if err != nil || (issuer.Scheme != "http" && issuer.Scheme != "https") || issuer.Host == "" {
		return nil, errors.New("seamlessauth: Issuer must be an absolute http or https URL")
	}
	if opts.Audience == "" {
		return nil, errors.New("seamlessauth: Audience is required")
	}
	if opts.JWKSURI != "" && !isHTTPURL(opts.JWKSURI) {
		return nil, errors.New("seamlessauth: JWKSURI must be an absolute http or https URL")
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	var client http.Client
	if opts.HTTPClient != nil {
		client = *opts.HTTPClient
	}
	client.CheckRedirect = noRedirects
	if client.Timeout == 0 {
		client.Timeout = upstreamTimeout
	}

	v := &Verifier{
		issuer:      opts.Issuer,
		issuerHTTPS: issuer.Scheme == "https",
		audience:    opts.Audience,
		confirm:     opts.Confirm,
		client:      &client,
		logf:        opts.Logf,
		now:         time.Now,
	}
	if opts.JWKSURI != "" {
		v.jwks = newJWKSCache(opts.JWKSURI, v.client, v.logf)
	}
	return v, nil
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Authenticate verifies the request's bearer token. The error is ErrMissingToken
// or wraps ErrInvalidToken.
func (v *Verifier) Authenticate(r *http.Request) (*TokenUser, error) {
	token, ok := soleBearerToken(r)
	if !ok {
		return nil, ErrMissingToken
	}
	user, err := v.verify(r, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return user, nil
}

func soleBearerToken(r *http.Request) (string, bool) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return "", false
	}
	return fields[1], true
}

func (v *Verifier) keySet(ctx context.Context) (*jwksCache, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.jwks != nil {
		return v.jwks, nil
	}
	now := time.Now()
	if !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < discoveryBackoff {
		return nil, errors.New("discovery failed recently")
	}
	v.attemptedAt = now
	uri, err := v.discover(ctx)
	if err != nil {
		v.logf("[seamless-auth] OpenID discovery for %s failed (%v).", v.issuer, err)
		return nil, err
	}
	v.jwks = newJWKSCache(uri, v.client, v.logf)
	return v.jwks, nil
}

func (v *Verifier) discover(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	endpoint := strings.TrimRight(v.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", upstreamError(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxDiscoveryBytes {
		return "", errors.New("discovery: response too large")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxDiscoveryBytes+1))
	if err != nil {
		return "", fmt.Errorf("discovery: %w", upstreamError(err))
	}
	if len(data) > maxDiscoveryBytes {
		return "", errors.New("discovery: response too large")
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return "", errors.New("discovery: not a JSON object")
	}
	if iss, _ := doc["issuer"].(string); iss != v.issuer {
		return "", errors.New("discovery: issuer does not match")
	}
	uri, _ := doc["jwks_uri"].(string)
	if !isHTTPURL(uri) {
		return "", errors.New("discovery: jwks_uri is not an http or https URL")
	}
	if u, _ := url.Parse(uri); v.issuerHTTPS && u.Scheme != "https" {
		return "", errors.New("discovery: jwks_uri must be https for an https issuer")
	}
	return uri, nil
}

func (v *Verifier) verify(r *http.Request, token string) (*TokenUser, error) {
	parsed, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	kid, err := checkAccessTokenHeader(parsed)
	if err != nil {
		return nil, err
	}

	keys, err := v.keySet(r.Context())
	if err != nil {
		return nil, err
	}
	key, err := keys.key(r.Context(), kid)
	if err != nil {
		return nil, err
	}
	if !jwkMemberIs(key.use, "sig") || !jwkMemberIs(key.alg, "RS256") {
		return nil, errors.New("key is not for RS256 signatures")
	}
	if err := verifyRS256(parsed, key.pub); err != nil {
		return nil, err
	}

	claims := parsed.claims
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, errors.New("unexpected issuer")
	}
	if !audienceMatches(claims, v.audience) {
		return nil, errors.New("unexpected audience")
	}
	now := unixSeconds(v.now())
	exp, ok := numberClaim(claims, "exp")
	if !ok || !(now < exp+clockSkew.Seconds()) {
		return nil, errors.New("token expired or has no exp")
	}
	if _, present := claims["nbf"]; present {
		nbf, ok := numberClaim(claims, "nbf")
		if !ok || !(now+clockSkew.Seconds() >= nbf) {
			return nil, errors.New("token not yet valid")
		}
	}

	user, err := tokenUserFrom(claims)
	if err != nil {
		return nil, err
	}
	user.Token = token

	// The provider's own session tokens carry typ; an access token never does.
	if _, present := claims["typ"]; present {
		return nil, errors.New("first-party token")
	}
	if cnf, present := claims["cnf"]; present && cnf != nil {
		object, isObject := cnf.(map[string]any)
		if !isObject || v.confirm == nil || !v.confirm(r, object) {
			return nil, errors.New("unconfirmed cnf")
		}
		user.Confirmation = object
	}
	return user, nil
}

// checkAccessTokenHeader reads the header by exact member name: decoding into
// jwtHeader matches names case-insensitively, so "TYP" would pass for typ.
func checkAccessTokenHeader(parsed *parsedJWT) (kid string, err error) {
	var header map[string]any
	if err := json.Unmarshal(parsed.rawHeader, &header); err != nil {
		return "", err
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return "", errors.New("unexpected algorithm")
	}
	if typ, _ := header["typ"].(string); !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return "", errors.New("not an access token")
	}
	if kid, _ = header["kid"].(string); kid == "" {
		return "", errors.New("no kid")
	}
	if _, present := header["crit"]; present {
		return "", errors.New("crit header")
	}
	return kid, nil
}

// jwkMemberIs holds for a member that is absent or the string want.
func jwkMemberIs(raw json.RawMessage, want string) bool {
	if raw == nil {
		return true
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == want
}

func unixSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

func numberClaim(claims map[string]any, name string) (float64, bool) {
	n, ok := claims[name].(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func timeFromSeconds(f float64) time.Time {
	// Beyond this a float cannot be converted to Unix nanoseconds reliably.
	if math.Abs(f) > 1e11 {
		return time.Time{}
	}
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9))
}

func tokenUserFrom(claims map[string]any) (*TokenUser, error) {
	user := &TokenUser{Claims: claims, Scopes: []string{}, Roles: []string{}, AMR: []string{}}
	var ok bool
	if user.Subject, ok = claims["sub"].(string); !ok || user.Subject == "" {
		return nil, errors.New("no sub")
	}
	if user.ClientID, ok = claims["client_id"].(string); !ok || user.ClientID == "" {
		return nil, errors.New("no client_id")
	}
	if exp, ok := numberClaim(claims, "exp"); ok {
		user.ExpiresAt = timeFromSeconds(exp)
	}
	if iat, ok := numberClaim(claims, "iat"); ok {
		user.IssuedAt = timeFromSeconds(iat)
	}

	optionalString := func(name string, into *string) error {
		raw, present := claims[name]
		if !present {
			return nil
		}
		if *into, ok = raw.(string); !ok {
			return fmt.Errorf("%s is not a string", name)
		}
		return nil
	}
	optionalStrings := func(name string, into *[]string) error {
		raw, present := claims[name]
		if !present {
			return nil
		}
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("%s is not an array", name)
		}
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("%s is not an array of strings", name)
			}
			out = append(out, s)
		}
		*into = out
		return nil
	}

	var scope string
	for _, check := range []error{
		optionalString("scope", &scope),
		optionalString("acr", &user.ACR),
		optionalString("sid", &user.SID),
		optionalStrings("amr", &user.AMR),
		optionalStrings("roles", &user.Roles),
	} {
		if check != nil {
			return nil, check
		}
	}
	if orgID, present := claims["org_id"]; present && orgID != nil {
		if user.OrgID, ok = orgID.(string); !ok {
			return nil, errors.New("org_id is not a string")
		}
	}
	if _, present := claims["auth_time"]; present {
		if user.authTime, ok = numberClaim(claims, "auth_time"); !ok {
			return nil, errors.New("auth_time is not a number")
		}
		user.hasAuthTime = true
		user.AuthTime = timeFromSeconds(user.authTime)
	}
	for _, s := range strings.Split(scope, " ") {
		if s != "" {
			user.Scopes = append(user.Scopes, s)
		}
	}
	return user, nil
}

type tokenUserKey struct{}

// TokenUserFromContext returns the user RequireToken verified.
func TokenUserFromContext(ctx context.Context) (*TokenUser, bool) {
	user, ok := ctx.Value(tokenUserKey{}).(*TokenUser)
	return user, ok
}

func writeBearerError(w http.ResponseWriter, status int, challenge string, body any) {
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

func writeMissingToken(w http.ResponseWriter) {
	writeBearerError(w, http.StatusUnauthorized, "Bearer", map[string]string{"error": "missing_token"})
}

// RequireToken answers 401 unless the request carries a valid access token, and
// puts the TokenUser on the request context for next. Guards go inside it.
func (v *Verifier) RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := v.Authenticate(r)
		if errors.Is(err, ErrMissingToken) {
			writeMissingToken(w)
			return
		}
		if err != nil {
			writeBearerError(w, http.StatusUnauthorized, `Bearer error="invalid_token"`, map[string]string{"error": "invalid_token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenUserKey{}, user)))
	})
}
