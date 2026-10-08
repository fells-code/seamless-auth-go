package seamlessauth

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ManifestPath is where the auth API publishes which token each route takes and
// which tokens its response issues or clears.
const ManifestPath = "/.well-known/seamless-adapter.json"

//go:embed manifest.json
var bundledManifestJSON []byte

// Manifest is the auth API's adapter manifest (schemaVersion 1).
type Manifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	APIVersion    string          `json:"apiVersion"`
	Routes        []ManifestRoute `json:"routes"`
}

// ManifestRoute describes one route an adapter serves.
type ManifestRoute struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Credential string   `json:"credential"`
	Issues     string   `json:"issues,omitempty"`
	Clears     []string `json:"clears,omitempty"`
	Body       *struct {
		Pick []string `json:"pick"`
	} `json:"body,omitempty"`
	Delivery bool `json:"delivery,omitempty"`
}

var (
	knownMethods     = set("GET", "POST", "PUT", "PATCH", "DELETE")
	knownCredentials = set("none", "preAuth", "registration", "access", "refresh")
	knownIssues      = set("", "preAuth", "registration", "session", "access")
	knownHeld        = set("preAuth", "registration", "access", "refresh")
)

func set(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// ParseManifest accepts a manifest only if every route is one this package knows
// how to follow. A route with a credential or effect it does not understand could
// be proxied with the wrong token, so such a manifest is refused whole.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported manifest schemaVersion %d", m.SchemaVersion)
	}
	for _, r := range m.Routes {
		if !knownMethods[r.Method] || !strings.HasPrefix(r.Path, "/") ||
			!knownCredentials[r.Credential] || !knownIssues[r.Issues] {
			return nil, fmt.Errorf("unsupported manifest route %s %s", r.Method, r.Path)
		}
		for _, held := range r.Clears {
			if !knownHeld[held] {
				return nil, fmt.Errorf("unsupported manifest route %s %s", r.Method, r.Path)
			}
		}
	}
	return &m, nil
}

// BundledManifest is the manifest this version of the package was built against.
func BundledManifest() *Manifest {
	m, err := ParseManifest(bundledManifestJSON)
	if err != nil {
		panic("seamlessauth: bundled manifest is invalid: " + err.Error())
	}
	return m
}

type routeMatch struct {
	route  ManifestRoute
	params map[string]string
}

// match finds the route for a request. Static segments compare
// case-insensitively, and a static segment beats a parameter at the same
// position, so /admin/users/import is never read as /admin/users/{userId}.
func (m *Manifest) match(method, path string) (routeMatch, bool) {
	requested := segments(path)
	var best routeMatch
	bestScore := -1

	for _, route := range m.Routes {
		if route.Method != strings.ToUpper(method) {
			continue
		}
		pattern := segments(route.Path)
		if len(pattern) != len(requested) {
			continue
		}

		params := map[string]string{}
		score := 0
		matched := true

		for i, part := range pattern {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				value, err := url.PathUnescape(requested[i])
				// Re-encoded, a dot segment survives as a literal ".." that the HTTP
				// client resolves, sending the held token to another upstream path.
				if err != nil || value == "." || value == ".." {
					matched = false
					break
				}
				params[part[1:len(part)-1]] = value
				continue
			}
			if !strings.EqualFold(part, requested[i]) {
				matched = false
				break
			}
			score++
		}

		if matched && score > bestScore {
			best = routeMatch{route: route, params: params}
			bestScore = score
		}
	}

	return best, bestScore >= 0
}

func segments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// upstreamPath fills a route's {param} segments, escaping each value.
func (r ManifestRoute) upstreamPath(params map[string]string) string {
	parts := strings.Split(r.Path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[i] = url.PathEscape(params[part[1:len(part)-1]])
		}
	}
	return strings.Join(parts, "/")
}

const (
	manifestTimeout    = 5 * time.Second
	manifestRetryAfter = time.Minute
)

// manifestSource fetches the live manifest once and keeps it, falling back to the
// bundled copy. A failed fetch is retried a minute later, not on every request.
type manifestSource struct {
	url    string
	client *http.Client
	fetch  bool
	logf   func(string, ...any)

	mu      sync.Mutex
	loaded  *Manifest
	retryAt time.Time
	bundled *Manifest
}

func newManifestSource(authServerURL string, client *http.Client, fetch bool, logf func(string, ...any)) *manifestSource {
	return &manifestSource{
		url:     authServerURL + ManifestPath,
		client:  client,
		fetch:   fetch,
		logf:    logf,
		bundled: BundledManifest(),
	}
}

func (s *manifestSource) get(ctx context.Context) *Manifest {
	if !s.fetch {
		return s.bundled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loaded != nil {
		return s.loaded
	}
	if time.Now().Before(s.retryAt) {
		return s.bundled
	}

	m, err := s.load(ctx)
	if err != nil {
		s.logf("[seamless-auth] Could not load the adapter manifest (%v). Using the bundled copy.", err)
		s.retryAt = time.Now().Add(manifestRetryAfter)
		return s.bundled
	}
	s.loaded = m
	return m
}

func (s *manifestSource) load(ctx context.Context) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), manifestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, err
	}
	return ParseManifest(raw)
}
