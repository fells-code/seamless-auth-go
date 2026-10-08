package seamlessauth

import (
	"net/http"
	"net/url"
	"strings"
)

// checkOrigin blocks cross-site state changes while cookies are SameSite=None,
// which is when the browser would otherwise attach them to such a request.
func (a *Adapter) checkOrigin(r *http.Request) (result, bool) {
	if a.opts.CookieSameSite != http.SameSiteNoneMode {
		return result{}, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return result{}, false
	}

	blocked := errorResult(http.StatusForbidden, "cross_site_request_blocked")

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return blocked, strings.EqualFold(site, "cross-site")
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return result{}, false
	}
	if origin == "null" {
		return blocked, true
	}
	if len(a.opts.AllowedOrigins) == 0 {
		return result{}, false
	}

	for _, allowed := range a.opts.AllowedOrigins {
		if normalizeOrigin(allowed) == normalizeOrigin(origin) {
			return result{}, false
		}
	}
	return blocked, true
}

func normalizeOrigin(origin string) string {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
