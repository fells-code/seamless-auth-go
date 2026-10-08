// Package seamlessauth is a Seamless Auth server adapter for net/http.
//
// It sits in front of the Seamless Auth API: browsers talk to it over httpOnly
// cookies on the application's own domain, native clients over bearer tokens,
// and it talks to the auth API over bearer tokens and a service token. Which
// routes it serves, and what each does to the session, comes from the auth API's
// adapter manifest.
package seamlessauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

const (
	transportHeader    = "X-Seamless-Auth-Transport"
	deliveryModeHeader = "X-Seamless-Auth-Delivery-Mode"
	maxBodyBytes       = 1 << 20
)

// Adapter serves the Seamless Auth routes. Mount Handler under a prefix, usually
// /auth, with http.StripPrefix.
type Adapter struct {
	opts      Options
	jwks      *jwksCache
	manifest  *manifestSource
	tokens    *serviceTokens
	refreshes *refresher
}

// New validates opts and returns an Adapter.
func New(opts Options) (*Adapter, error) {
	resolved, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Adapter{
		opts:      resolved,
		jwks:      newJWKSCache(resolved.AuthServerURL, resolved.HTTPClient),
		manifest:  newManifestSource(resolved.AuthServerURL, resolved.HTTPClient, !resolved.DisableManifestFetch, resolved.Logf),
		tokens:    &serviceTokens{secret: resolved.ServiceSecret, kid: resolved.JWKSKid},
		refreshes: newRefresher(),
	}, nil
}

// Handler serves the auth routes, relative to wherever it is mounted.
func (a *Adapter) Handler() http.Handler {
	return http.HandlerFunc(a.serve)
}

// result is what a route answers, applied to the response in one place.
type result struct {
	status int
	body   any
	raw    *http.Response
	set    []cookieWrite
	clear  []string
}

func errorResult(status int, code string) result {
	return result{status: status, body: map[string]any{"error": code}}
}

func (a *Adapter) serve(w http.ResponseWriter, r *http.Request) {
	if res, blocked := a.checkOrigin(r); blocked {
		a.write(w, res, false)
		return
	}

	bearer := strings.EqualFold(r.Header.Get(transportHeader), "bearer")
	path := r.URL.EscapedPath()

	var res result
	switch {
	case r.Method == http.MethodPost && strings.EqualFold(path, "/refresh"):
		res = a.refreshRoute(r, bearer)
	case r.Method == http.MethodDelete && (strings.EqualFold(path, "/logout") || strings.EqualFold(path, "/logout/all")):
		res = a.logoutRoute(r, bearer, path)
	default:
		match, ok := a.manifest.get(r.Context()).match(r.Method, path)
		if !ok {
			res = errorResult(http.StatusNotFound, "not_found")
		} else {
			res = a.manifestRoute(r, match, bearer)
		}
	}

	a.write(w, res, bearer)
}

// write applies a result. Clears go before sets, because a result that does both
// is replacing a session rather than ending one. Bearer transport writes no
// cookies at all.
func (a *Adapter) write(w http.ResponseWriter, res result, bearer bool) {
	if !bearer {
		for _, name := range uniq(res.clear) {
			a.clearCookie(w, name)
		}
		for _, c := range res.set {
			if err := a.setCookie(w, c); err != nil {
				a.opts.Logf("[seamless-auth] Could not issue cookie %s: %v", c.name, err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
				return
			}
		}
	}

	if res.raw != nil {
		defer res.raw.Body.Close()
		for _, name := range []string{"Content-Type", "Content-Disposition", "Cache-Control"} {
			if v := res.raw.Header.Get(name); v != "" {
				w.Header().Set(name, v)
			}
		}
		w.WriteHeader(res.status)
		_, _ = io.Copy(w, res.raw.Body)
		return
	}

	if res.body == nil {
		w.WriteHeader(res.status)
		return
	}
	writeJSON(w, res.status, res.body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func uniq(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// upstreamCall is one request to the auth API.
type upstreamCall struct {
	method        string
	path          string
	rawQuery      string
	body          []byte
	authorization string
	service       string
	headers       map[string]string
}

func (a *Adapter) call(ctx context.Context, r *http.Request, c upstreamCall) (*http.Response, error) {
	target := a.opts.AuthServerURL + c.path
	if c.rawQuery != "" {
		target += "?" + c.rawQuery
	}

	var body io.Reader
	if c.body != nil && c.method != http.MethodGet {
		body = bytes.NewReader(c.body)
	}

	req, err := http.NewRequestWithContext(ctx, c.method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.authorization != "" {
		req.Header.Set("Authorization", c.authorization)
	}
	if c.service != "" {
		req.Header.Set("X-Seamless-Service-Token", c.service)
	}
	if ip := a.clientIP(r); ip != "" {
		req.Header.Set("X-Seamless-Client-Ip", ip)
	}
	if ua := clientUserAgent(r); ua != "" {
		req.Header.Set("X-Seamless-Client-User-Agent", ua)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	return a.opts.HTTPClient.Do(req)
}

// readJSON reads a response body. An empty body is nil; a body that is not JSON
// reports false.
func readJSON(res *http.Response) (any, bool) {
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// failure passes an upstream error through. Callers read fields off the auth
// API's own error body, so an object goes out as-is; anything else becomes a code
// they can still branch on.
func failure(status int, body any, isJSON bool) result {
	if obj, ok := body.(map[string]any); ok && isJSON {
		return result{status: status, body: obj}
	}
	return errorResult(status, "upstream_error")
}

func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	return data, nil
}

var errBodyTooLarge = errors.New("request body too large")

// isJSONContentType is application/json or a +json type. A download such as
// application/x-ndjson is not: parsing it would keep only its first line.
func isJSONContentType(contentType string) bool {
	if contentType == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}
