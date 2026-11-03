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
// cross-site is refused. same-site also covers a sibling subdomain, so with
// AllowedOrigins set its Origin must be on the list too. Without the header,
// Origin is matched against AllowedOrigins when they are set. A non-nil empty
// AllowedOrigins is set, and allows no origin.
func (a *Adapter) checkOrigin(r *http.Request) (result, bool) {
	if !isUnsafeMethod(r.Method) {
		return result{}, false
	}

	blocked := errorResult(http.StatusForbidden, "cross_site_request_blocked")
	origin := r.Header.Get("Origin")
	listed := a.opts.AllowedOrigins != nil

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		switch {
		case strings.EqualFold(site, "cross-site"):
			return blocked, true
		case strings.EqualFold(site, "same-site") && listed:
			return blocked, !a.isAllowedOrigin(origin)
		default:
			return result{}, false
		}
	}

	if origin == "" {
		return result{}, false
	}
	if origin == "null" {
		return blocked, true
	}
	if !listed {
		return result{}, false
	}
	return blocked, !a.isAllowedOrigin(origin)
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
