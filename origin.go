package seamlessauth

import (
	"net/http"
	"net/url"
	"strings"
)

// checkOrigin blocks cross-site state changes, whatever the SameSite setting:
// a sibling subdomain is same-site, so even SameSite=Lax cookies ride along on
// its form POST.
//
// Sec-Fetch-Site is the primary signal, since page script cannot forge it:
// cross-site, or a value this check does not know, is refused, as is an Origin
// of null before anything else. same-site also covers a sibling subdomain, so
// its Origin must be on AllowedOrigins when they are set, or name the request's
// Host when they are not. Without the header, an Origin is held to the same
// rule. A non-nil empty AllowedOrigins is set, and allows no origin.
func (a *Adapter) checkOrigin(r *http.Request) (result, bool) {
	if !isUnsafeMethod(r.Method) {
		return result{}, false
	}

	blocked := errorResult(http.StatusForbidden, "cross_site_request_blocked")
	origin := r.Header.Get("Origin")

	// An opaque or sandboxed origin is cross-site, whatever Sec-Fetch-Site says.
	if strings.EqualFold(strings.TrimSpace(origin), "null") {
		return blocked, true
	}

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		switch strings.ToLower(strings.TrimSpace(site)) {
		case "same-origin", "none":
			return result{}, false
		case "same-site":
			return blocked, !a.isTrustedOrigin(origin, r.Host)
		default:
			return blocked, true
		}
	}

	if origin == "" {
		return result{}, false
	}
	return blocked, !a.isTrustedOrigin(origin, r.Host)
}

// isTrustedOrigin matches origin against AllowedOrigins when they are set, and
// otherwise against the request's Host. Host is what the browser addressed, so
// behind a proxy that rewrites it the app must set AllowedOrigins.
// X-Forwarded-Host is not consulted: nothing here can tell a proxy's from a
// client's.
func (a *Adapter) isTrustedOrigin(origin, host string) bool {
	if a.opts.AllowedOrigins != nil {
		return a.isAllowedOrigin(origin)
	}
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Scheme == "" || u.Host == "" || host == "" {
		return false
	}
	return stripDefaultPort(u.Host, u.Scheme) == stripDefaultPort(host, u.Scheme)
}

// stripDefaultPort lowercases host and drops the scheme's default port, so
// "example.com:443" from an https origin names the same host as "example.com".
func stripDefaultPort(host, scheme string) string {
	host = strings.ToLower(host)
	switch {
	case strings.EqualFold(scheme, "https") && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case strings.EqualFold(scheme, "http") && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// checkContentType refuses an unsafe request that neither declares a JSON body
// nor carries the transport header. Either one makes a cross-origin browser
// request send a CORS preflight, which a form cannot, so this holds even when
// the body is empty and there is nothing for the body check to read.
//
// POST /refresh and DELETE /logout (and /logout/all) are exempt for now: the
// client sends them with no body and neither header, and refusing them would
// sign users out when the adapter upgrades ahead of the client. They keep the
// origin check.
func (a *Adapter) checkContentType(r *http.Request, path string) (result, bool) {
	if !isUnsafeMethod(r.Method) || isExplicitJSON(r.Header.Get("Content-Type")) || r.Header.Get(transportHeader) != "" {
		return result{}, false
	}
	if isRefreshRoute(r.Method, path) || isLogoutRoute(r.Method, path) {
		return result{}, false
	}
	return errorResult(http.StatusUnsupportedMediaType, "unsupported_media_type"), true
}

func isRefreshRoute(method, path string) bool {
	return method == http.MethodPost && strings.EqualFold(path, "/refresh")
}

func isLogoutRoute(method, path string) bool {
	return method == http.MethodDelete && (strings.EqualFold(path, "/logout") || strings.EqualFold(path, "/logout/all"))
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// isAllowedOrigin matches origin against AllowedOrigins. An origin that does not
// normalize, or is missing, matches nothing, including an allowlist entry that
// does not normalize either.
func (a *Adapter) isAllowedOrigin(origin string) bool {
	want := normalizeOrigin(origin)
	if want == "" {
		return false
	}
	for _, allowed := range a.opts.AllowedOrigins {
		if normalizeOrigin(allowed) == want {
			return true
		}
	}
	return false
}

func normalizeOrigin(origin string) string {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
