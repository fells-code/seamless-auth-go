package seamlessauth

import (
	"net/http"
	"net/url"
	"strings"
)

// checkOrigin blocks cross-site state changes while cookies are SameSite=None,
// which is when the browser would otherwise attach them to such a request.
//
// Sec-Fetch-Site is the primary signal, since page script cannot forge it:
// cross-site is refused. same-site also covers a sibling subdomain, so with
// AllowedOrigins set its Origin must be on the list too. Without the header,
// Origin is matched against AllowedOrigins when they are set.
func (a *Adapter) checkOrigin(r *http.Request) (result, bool) {
	if a.opts.CookieSameSite != http.SameSiteNoneMode {
		return result{}, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return result{}, false
	}

	blocked := errorResult(http.StatusForbidden, "cross_site_request_blocked")
	origin := r.Header.Get("Origin")

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		switch {
		case strings.EqualFold(site, "cross-site"):
			return blocked, true
		case strings.EqualFold(site, "same-site") && len(a.opts.AllowedOrigins) > 0:
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
	if len(a.opts.AllowedOrigins) == 0 {
		return result{}, false
	}
	return blocked, !a.isAllowedOrigin(origin)
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
