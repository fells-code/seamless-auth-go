package seamlessauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testdata/verify_only_vectors.json is a byte-for-byte copy of
// packages/core/tests/fixtures/verify-only/vectors.json in
// fells-code/seamless-auth-server, shared by every adapter's verify-only mode.
// Regenerate it there, never here.
type verifyOnlyVectors struct {
	Issuer   string            `json:"issuer"`
	Audience string            `json:"audience"`
	Now      int64             `json:"now"`
	JWKS     json.RawMessage   `json:"jwks"`
	Tokens   map[string]string `json:"tokens"`
	Verify   []struct {
		Name  string `json:"name"`
		Valid bool   `json:"valid"`
		User  *struct {
			Sub      string   `json:"sub"`
			ClientID string   `json:"client_id"`
			Scopes   []string `json:"scopes"`
			Roles    []string `json:"roles"`
			SID      *string  `json:"sid"`
			OrgID    *string  `json:"org_id"`
			ACR      *string  `json:"acr"`
			AMR      []string `json:"amr"`
			AuthTime *int64   `json:"auth_time"`
		} `json:"user"`
	} `json:"verify"`
	Requests []struct {
		Name          string  `json:"name"`
		Authorization *string `json:"authorization"`
		Guard         *struct {
			Kind      string   `json:"kind"`
			Scopes    []string `json:"scopes"`
			Roles     []string `json:"roles"`
			ACRValues []string `json:"acr_values"`
			AMR       []string `json:"amr"`
			MaxAge    *int64   `json:"max_age"`
		} `json:"guard"`
		Expect struct {
			Status          int             `json:"status"`
			Body            json.RawMessage `json:"body"`
			WWWAuthenticate *string         `json:"www_authenticate"`
		} `json:"expect"`
	} `json:"requests"`
}

func loadVectors(t *testing.T) verifyOnlyVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/verify_only_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v verifyOnlyVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Verify) == 0 || len(v.Requests) == 0 {
		t.Fatal("no vectors")
	}
	return v
}

func vectorVerifier(t *testing.T, vectors verifyOnlyVectors, confirm func(*http.Request, map[string]any) bool) *Verifier {
	t.Helper()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vectors.JWKS)
	}))
	t.Cleanup(jwks.Close)
	v, err := NewVerifier(VerifierOptions{
		Issuer:   vectors.Issuer,
		Audience: vectors.Audience,
		JWKSURI:  jwks.URL,
		Confirm:  confirm,
		Logf:     func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(vectors.Now, 0) }
	return v
}

func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func orEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestVerifyOnlyVectorsVerify(t *testing.T) {
	vectors := loadVectors(t)
	v := vectorVerifier(t, vectors, nil)
	for _, vec := range vectors.Verify {
		t.Run(vec.Name, func(t *testing.T) {
			token, ok := vectors.Tokens[vec.Name]
			if !ok {
				t.Fatalf("no token %s", vec.Name)
			}
			user, err := v.Authenticate(bearerRequest(token))
			if !vec.Valid {
				if err == nil {
					t.Fatalf("accepted an invalid token: %+v", user)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := vec.User
			var wantAuthTime time.Time
			if want.AuthTime != nil {
				wantAuthTime = time.Unix(*want.AuthTime, 0)
			}
			got := []any{user.Subject, user.ClientID, user.Scopes, user.Roles, user.SID, user.OrgID, user.ACR, user.AMR, user.AuthTime.Equal(wantAuthTime), user.AuthTime.IsZero()}
			expected := []any{want.Sub, want.ClientID, want.Scopes, want.Roles, orEmpty(want.SID), orEmpty(want.OrgID), orEmpty(want.ACR), want.AMR, true, want.AuthTime == nil}
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("got %#v, want %#v", got, expected)
			}
		})
	}
}

func vectorRoute(t *testing.T, v *Verifier, guardKind string, scopes, roles, acr, amr []string, maxAge *int64) http.Handler {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, found := TokenUserFromContext(r.Context()); !found {
			t.Error("handler reached without a user")
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	var inner http.Handler = ok
	switch guardKind {
	case "":
	case "scope":
		inner = v.RequireScope(scopes...)(ok)
	case "role":
		inner = v.RequireRole(roles...)(ok)
	case "step_up":
		step := StepUp{ACRValues: acr, AMR: amr}
		if maxAge != nil {
			d := time.Duration(*maxAge) * time.Second
			step.MaxAge = &d
		}
		mw, err := v.RequireStepUp(step)
		if err != nil {
			t.Fatal(err)
		}
		inner = mw(ok)
	default:
		t.Fatalf("unknown guard %q", guardKind)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", v.RequireToken(inner))
	return mux
}

func TestVerifyOnlyVectorsRequests(t *testing.T) {
	vectors := loadVectors(t)
	v := vectorVerifier(t, vectors, nil)
	for _, vec := range vectors.Requests {
		t.Run(vec.Name, func(t *testing.T) {
			kind := ""
			var scopes, roles, acr, amr []string
			var maxAge *int64
			if g := vec.Guard; g != nil {
				kind, scopes, roles, acr, amr, maxAge = g.Kind, g.Scopes, g.Roles, g.ACRValues, g.AMR, g.MaxAge
			}
			server := httptest.NewServer(vectorRoute(t, v, kind, scopes, roles, acr, amr, maxAge))
			defer server.Close()

			req, _ := http.NewRequest(http.MethodGet, server.URL+"/resource", nil)
			if vec.Authorization != nil {
				req.Header.Set("Authorization", *vec.Authorization)
			}
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			if res.StatusCode != vec.Expect.Status {
				t.Fatalf("status %d, want %d", res.StatusCode, vec.Expect.Status)
			}
			challenge, present := res.Header["Www-Authenticate"]
			if vec.Expect.WWWAuthenticate == nil {
				if present {
					t.Fatalf("WWW-Authenticate %q, want none", challenge)
				}
			} else if len(challenge) != 1 || challenge[0] != *vec.Expect.WWWAuthenticate {
				t.Fatalf("WWW-Authenticate %q, want %q", challenge, *vec.Expect.WWWAuthenticate)
			}

			var got any
			if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			want := any(map[string]any{"ok": true})
			if string(vec.Expect.Body) != "null" {
				if err := json.Unmarshal(vec.Expect.Body, &want); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body %v, want %v", got, want)
			}
		})
	}
}

func TestVerifierConfirmationHook(t *testing.T) {
	vectors := loadVectors(t)
	var seen map[string]any
	v := vectorVerifier(t, vectors, func(r *http.Request, cnf map[string]any) bool {
		seen = cnf
		return r.Header.Get("DPoP") == "proof"
	})
	r := bearerRequest(vectors.Tokens["cnf_bound"])
	if _, err := v.Authenticate(r); err == nil {
		t.Fatal("hook refused, token accepted")
	}
	r.Header.Set("DPoP", "proof")
	user, err := v.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 || !reflect.DeepEqual(user.Confirmation, seen) {
		t.Fatalf("confirmation %v, hook saw %v", user.Confirmation, seen)
	}
	if _, err := v.Authenticate(bearerRequest(vectors.Tokens["user_otp"])); err != nil {
		t.Fatalf("hook blocked a token with no cnf: %v", err)
	}
}

func TestNewVerifierRefusesBadConfig(t *testing.T) {
	for name, opts := range map[string]VerifierOptions{
		"no issuer":         {Audience: "https://api.example"},
		"relative issuer":   {Issuer: "login.example", Audience: "https://api.example"},
		"non-http issuer":   {Issuer: "ftp://login.example", Audience: "https://api.example"},
		"no audience":       {Issuer: "https://login.example"},
		"relative jwks uri": {Issuer: "https://login.example", Audience: "a", JWKSURI: "/jwks"},
	} {
		if _, err := NewVerifier(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v, err := NewVerifier(VerifierOptions{Issuer: "https://login.example", Audience: "a"})
	if err != nil {
		t.Fatal(err)
	}
	for name, step := range map[string]StepUp{
		"nothing":            {},
		"negative max age":   {MaxAge: durationPtr(-time.Second)},
		"fractional max age": {MaxAge: durationPtr(1500 * time.Millisecond)},
		"quoted acr":         {ACRValues: []string{`a"b`}},
		"empty amr":          {AMR: []string{""}},
		"empty acr list":     {ACRValues: []string{}, MaxAge: durationPtr(time.Minute)},
		"empty amr list":     {AMR: []string{}, MaxAge: durationPtr(time.Minute)},
	} {
		if _, err := v.RequireStepUp(step); err == nil {
			t.Errorf("RequireStepUp %s: accepted", name)
		}
	}
	for name, f := range map[string]func(){
		"no scope":     func() { v.RequireScope() },
		"spaced scope": func() { v.RequireScope("a b") },
		"no role":      func() { v.RequireRole() },
		"empty scope":  func() { v.RequireScope("a", "") },
		"empty role":   func() { v.RequireRole("") },
		"blank role":   func() { v.RequireRole(" ") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: did not panic", name)
				}
			}()
			f()
		}()
	}
}

func durationPtr(d time.Duration) *time.Duration { return &d }

func TestAGuardWithoutRequireTokenAnswersMissingToken(t *testing.T) {
	v, _ := NewVerifier(VerifierOptions{Issuer: "https://login.example", Audience: "a"})
	rec := httptest.NewRecorder()
	v.RequireScope("x")(http.NotFoundHandler()).ServeHTTP(rec, bearerRequest("whatever"))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// fakeProvider serves discovery and a key set for the test key, as kid k1.
type fakeProvider struct {
	server      *httptest.Server
	discoveries atomic.Int32
	jwksFetches atomic.Int32
	status      atomic.Int32
	mu          sync.Mutex
	doc         map[string]any
}

func (p *fakeProvider) set(member string, value any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.doc[member] = value
}

func newFakeProvider(t *testing.T, tlsServer bool) *fakeProvider {
	t.Helper()
	pub := rsaKey(t).PublicKey
	keys, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": b64.EncodeToString(pub.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	p := &fakeProvider{doc: map[string]any{}}
	p.status.Store(http.StatusOK)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			p.discoveries.Add(1)
			w.WriteHeader(int(p.status.Load()))
			p.mu.Lock()
			defer p.mu.Unlock()
			_ = json.NewEncoder(w).Encode(p.doc)
		case "/keys":
			p.jwksFetches.Add(1)
			_, _ = w.Write(keys)
		default:
			http.NotFound(w, r)
		}
	})
	if tlsServer {
		p.server = httptest.NewTLSServer(handler)
	} else {
		p.server = httptest.NewServer(handler)
	}
	t.Cleanup(p.server.Close)
	p.set("issuer", p.server.URL)
	p.set("jwks_uri", p.server.URL+"/keys")
	return p
}

func (p *fakeProvider) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierOptions{
		Issuer:     p.server.URL,
		Audience:   "https://api.example.test",
		HTTPClient: p.server.Client(),
		Logf:       func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (p *fakeProvider) token(t *testing.T) string {
	t.Helper()
	return p.tokenWithHeader(t, map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"})
}

func (p *fakeProvider) tokenWithHeader(t *testing.T, h map[string]string) string {
	t.Helper()
	return p.sign(t, h, nil, "")
}

// sign issues a token whose claims are the defaults with overrides applied (a
// nil value is kept as null), and whose payload has rawExp spliced in as exp when
// set, for literals encoding/json cannot write.
func (p *fakeProvider) sign(t *testing.T, h map[string]string, overrides map[string]any, rawExp string) string {
	t.Helper()
	header, _ := json.Marshal(h)
	claims := map[string]any{
		"iss": p.server.URL, "aud": "https://api.example.test", "sub": "u1", "client_id": "app",
		"exp": time.Now().Add(time.Minute).Unix(), "scope": "a b",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	if rawExp != "" {
		claims["exp"] = "RAW_EXP"
	}
	payload, _ := json.Marshal(claims)
	if rawExp != "" {
		payload = []byte(strings.Replace(string(payload), `"RAW_EXP"`, rawExp, 1))
	}
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func serveToken(v *Verifier, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	v.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, bearerRequest(token))
	return rec
}

func TestVerifierDiscoversTheKeySetOnce(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	token := p.token(t)
	for i := 0; i < 3; i++ {
		if rec := serveToken(v, token); rec.Code != http.StatusNoContent {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	if p.discoveries.Load() != 1 || p.jwksFetches.Load() != 1 {
		t.Fatalf("%d discoveries, %d key set fetches", p.discoveries.Load(), p.jwksFetches.Load())
	}
}

func TestVerifierClaimTypes(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	header := map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}
	refused := map[string]map[string]any{}
	for _, claim := range []string{"iss", "aud", "exp", "nbf", "sub", "client_id", "scope", "acr", "amr", "auth_time", "roles", "sid", "typ"} {
		refused[claim+" null"] = map[string]any{claim: nil}
	}
	refused["exp bool"] = map[string]any{"exp": true}
	refused["nbf bool"] = map[string]any{"nbf": false}
	refused["auth_time bool"] = map[string]any{"auth_time": true}
	refused["org_id number"] = map[string]any{"org_id": 5}
	refused["cnf without a hook"] = map[string]any{"cnf": map[string]any{"jkt": "x"}}
	for name, overrides := range refused {
		if rec := serveToken(v, p.sign(t, header, overrides, "")); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	for _, raw := range []string{"1e999", "-1e999"} {
		if rec := serveToken(v, p.sign(t, header, nil, raw)); rec.Code != http.StatusUnauthorized {
			t.Errorf("exp %s: %d", raw, rec.Code)
		}
	}
	for name, overrides := range map[string]map[string]any{
		"org_id null": {"org_id": nil},
		"cnf null":    {"cnf": nil},
		"iat string":  {"iat": "soon"},
	} {
		if rec := serveToken(v, p.sign(t, header, overrides, "")); rec.Code != http.StatusNoContent {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestVerifierAcceptsAnHTTPJWKSURIUnderAnHTTPSIssuer(t *testing.T) {
	if _, err := NewVerifier(VerifierOptions{Issuer: "https://login.example", Audience: "a", JWKSURI: "http://keys.internal/jwks"}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierReadsHeaderMembersByExactName(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	for _, h := range []map[string]string{
		{"alg": "RS256", "kid": "k1", "TYP": "at+jwt"},
		{"ALG": "RS256", "kid": "k1", "typ": "at+jwt"},
		{"alg": "RS256", "KID": "k1", "typ": "at+jwt"},
	} {
		if rec := serveToken(v, p.tokenWithHeader(t, h)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%v: %d", h, rec.Code)
		}
	}
}

func TestVerifierDiscoveryFailsClosed(t *testing.T) {
	for name, setup := range map[string]func(p *fakeProvider){
		"issuer mismatch":       func(p *fakeProvider) { p.set("issuer", p.server.URL+"/") },
		"no jwks_uri":           func(p *fakeProvider) { p.set("jwks_uri", nil) },
		"relative jwks_uri":     func(p *fakeProvider) { p.set("jwks_uri", "/keys") },
		"http error":            func(p *fakeProvider) { p.status.Store(http.StatusInternalServerError) },
		"http keys under https": nil,
	} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t, setup == nil)
			if setup == nil {
				p.set("jwks_uri", strings.Replace(p.server.URL, "https:", "http:", 1)+"/keys")
			} else {
				setup(p)
			}
			v := p.verifier(t)
			token := p.token(t)
			for i := 0; i < 2; i++ {
				rec := serveToken(v, token)
				if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
					t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
				}
			}
			if p.discoveries.Load() != 1 || p.jwksFetches.Load() != 0 {
				t.Fatalf("%d discoveries, %d key set fetches", p.discoveries.Load(), p.jwksFetches.Load())
			}

			v.mu.Lock()
			v.attemptedAt = time.Now().Add(-discoveryBackoff - time.Second)
			v.mu.Unlock()
			serveToken(v, token)
			if p.discoveries.Load() != 2 {
				t.Fatalf("%d discoveries after the backoff", p.discoveries.Load())
			}
		})
	}
}

func TestVerifierProviderUnreachableIs401(t *testing.T) {
	p := newFakeProvider(t, false)
	v := p.verifier(t)
	token := p.token(t)
	p.server.Close()
	if rec := serveToken(v, token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestJWKMemberIs(t *testing.T) {
	for raw, want := range map[string]bool{"": true, `"sig"`: true, `"enc"`: false, `null`: false, `5`: false, `""`: false} {
		var member json.RawMessage
		if raw != "" {
			member = json.RawMessage(raw)
		}
		if got := jwkMemberIs(member, "sig"); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
}

func TestRoleGrantsAccess(t *testing.T) {
	for _, c := range []struct {
		granted, required string
		want              bool
	}{
		{"admin", "admin", true},
		{" admin ", "admin", true},
		{"\ufeffadmin", "admin", true},
		{"", "", false},
		{"billing:*", "billing", true},
		{"billing:*", "billing:invoices:read", true},
		{"billing:*", "users:read", false},
		{"billing", "billing:invoices", true},
		{"billing", "billingx:invoices", false},
		{"billing", "other", false},
		{"billing:invoices:write", "billing:invoices:read", true},
		{"billing:invoices:read", "billing:invoices:write", false},
		{"billing:a:write", "billing:b:read", false},
		{"a:write", "a:b:read", false},
	} {
		if got := RoleGrantsAccess(c.granted, c.required); got != c.want {
			t.Errorf("RoleGrantsAccess(%q, %q) = %v", c.granted, c.required, got)
		}
	}
}
