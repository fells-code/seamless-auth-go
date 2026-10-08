package seamlessauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	consoleBasePath        = "/console"
	consoleUpstreamTimeout = 10 * time.Second
	consoleMaxRedirects    = 5
)

var consoleResponseHeaders = []string{"Content-Type", "Cache-Control", "ETag", "Last-Modified"}

// ConsoleHandler reverse-proxies the Seamless admin dashboard from the auth API,
// so it loads from the same origin as the cookie-based auth routes. Mount it at
// /console, the path the dashboard is built against:
//
//	mux.Handle("/console/", http.StripPrefix("/console", auth.ConsoleHandler()))
//
// Nothing from the incoming request is forwarded but the method and the path:
// the console is public static hosting, and the browser's session cookies have
// no business at the upstream.
func (a *Adapter) ConsoleHandler() http.Handler {
	client := &http.Client{
		Transport: a.opts.HTTPClient.Transport,
		Timeout:   consoleUpstreamTimeout,
		// A redirect is followed only while it stays inside the console on the
		// auth API's own origin.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= consoleMaxRedirects {
				return errors.New("too many redirects")
			}
			if !a.insideConsole(req.URL) {
				return errors.New("redirect leaves the console")
			}
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "Method not allowed"})
			return
		}

		upstream, ok := a.consoleUpstream(r.URL.EscapedPath(), r.URL.RawQuery)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid console path"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), consoleUpstreamTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, r.Method, upstream.String(), nil)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid console path"})
			return
		}
		res, err := client.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "Console upstream unreachable"})
			return
		}
		defer res.Body.Close()

		for _, name := range consoleResponseHeaders {
			if v := res.Header.Get(name); v != "" {
				w.Header().Set(name, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, res.Body)
		}
	})
}

// consolePrefix is the console's path on the auth API.
func (a *Adapter) consolePrefix() (*url.URL, string, bool) {
	base, err := url.Parse(a.opts.AuthServerURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, "", false
	}
	return base, strings.TrimRight(base.EscapedPath(), "/") + consoleBasePath, true
}

// consoleUpstream maps a path below the mount to the console on the auth API,
// refusing anything that could leave the console subtree: an encoded separator
// (an upstream that decodes it would read a traversal), and any dot segment,
// literal or encoded.
func (a *Adapter) consoleUpstream(subpath, rawQuery string) (*url.URL, bool) {
	lower := strings.ToLower(subpath)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(subpath, `\`) {
		return nil, false
	}
	for _, segment := range strings.Split(subpath, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." {
			return nil, false
		}
	}

	base, prefix, ok := a.consolePrefix()
	if !ok {
		return nil, false
	}
	if subpath == "/" {
		subpath = ""
	}
	if subpath != "" && !strings.HasPrefix(subpath, "/") {
		subpath = "/" + subpath
	}

	upstream, err := url.Parse(base.Scheme + "://" + base.Host + prefix + subpath)
	if err != nil {
		return nil, false
	}
	upstream.RawQuery = rawQuery
	return upstream, a.insideConsole(upstream)
}

// insideConsole holds a URL to the auth API's origin and the console subtree.
func (a *Adapter) insideConsole(u *url.URL) bool {
	base, prefix, ok := a.consolePrefix()
	if !ok || u.Scheme != base.Scheme || u.Host != base.Host {
		return false
	}
	path := u.EscapedPath()
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
