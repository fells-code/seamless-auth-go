package seamlessauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSecret  = "cookie-secret-cookie-secret-cookie-secret"
	testService = "service-secret-service-secret-service-secret"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// signRS256 issues a token as the auth API would.
func signRS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body := map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		body[k] = v
	}
	payload, _ := json.Marshal(body)
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

// recorded is one request the fake auth API received.
type recorded struct {
	method, path, query string
	header              http.Header
	body                string
}

// fakeAPI is an auth API: JWKS, an optional manifest, and per-route handlers.
type fakeAPI struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	calls    []recorded
	routes   map[string]http.HandlerFunc
	manifest *Manifest
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	api := &fakeAPI{t: t, routes: map[string]http.HandlerFunc{}}
	api.server = httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	return api
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
	handler := f.routes[r.Method+" "+r.URL.Path]
	f.mu.Unlock()

	switch {
	case r.URL.Path == "/.well-known/jwks.json":
		pub := rsaKey(f.t).PublicKey
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64.EncodeToString(pub.N.Bytes()),
			"e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	case r.URL.Path == ManifestPath && f.manifest != nil:
		writeJSON(w, http.StatusOK, f.manifest)
	case handler != nil:
		handler(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	}
}

func (f *fakeAPI) on(method, path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = h
}

func (f *fakeAPI) callsTo(method, path string) []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, c := range f.calls {
		if c.method == method && c.path == path {
			out = append(out, c)
		}
	}
	return out
}

func respond(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, status, body) }
}

// newTestAdapter is an adapter in front of api, on the bundled manifest unless
// fetch is set.
func newTestAdapter(t *testing.T, api *fakeAPI, mutate ...func(*Options)) *Adapter {
	t.Helper()
	opts := Options{
		AuthServerURL:        api.server.URL,
		CookieSecret:         testSecret,
		ServiceSecret:        testService,
		JWKSKid:              "test-main",
		DisableManifestFetch: true,
		Logf:                 func(string, ...any) {},
	}
	for _, m := range mutate {
		m(&opts)
	}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// apiToken is a token the fake API signs, of the given type.
func apiToken(t *testing.T, api *fakeAPI, sub, typ string) string {
	return signRS256(t, map[string]any{"sub": sub, "typ": typ, "iss": api.server.URL, "aud": api.server.URL})
}

// session is a session response the fake API returns.
func session(t *testing.T, api *fakeAPI, sub string) map[string]any {
	return map[string]any{
		"message":      "Success",
		"sub":          sub,
		"token":        signRS256(t, map[string]any{"sub": sub, "sid": "s-1", "typ": "access", "iss": api.server.URL, "aud": api.server.URL}),
		"refreshToken": "refresh-" + sub,
		"ttl":          900,
		"refreshTtl":   3600,
	}
}

// signedCookie is a cookie as the adapter writes it, with the kind its name implies.
func signedCookie(t *testing.T, name string, claims map[string]any) *http.Cookie {
	t.Helper()
	kinds := map[string]string{"seamless-access": kindAccess, "seamless-refresh": kindRefresh, "seamless-ephemeral": kindEphemeral}
	return rawCookie(t, name, kinds[name], claims)
}

// rawCookie signs claims with the cookie secret under any kind, including the wrong
// one for the slot.
func rawCookie(t *testing.T, name, kind string, claims map[string]any) *http.Cookie {
	t.Helper()
	body := map[string]any{kindClaim: kind}
	for k, v := range claims {
		body[k] = v
	}
	v, err := signHS256(body, testSecret, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: name, Value: v}
}

type reply struct {
	status  int
	body    map[string]any
	cookies map[string]*http.Cookie
	raw     *httptest.ResponseRecorder
}

func do(t *testing.T, a *Adapter, method, target string, body string, setup ...func(*http.Request)) reply {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, s := range setup {
		s(req)
	}
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	out := reply{status: rec.Code, cookies: map[string]*http.Cookie{}, raw: rec}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	for _, c := range rec.Result().Cookies() {
		out.cookies[c.Name] = c
	}
	return out
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func withHeader(k, v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func withoutHeader(k string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Del(k) }
}
