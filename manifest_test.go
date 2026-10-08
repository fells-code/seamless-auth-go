package seamlessauth

import (
	"context"
	"testing"
)

func TestBundledManifestParses(t *testing.T) {
	if len(BundledManifest().Routes) == 0 {
		t.Fatal("no routes")
	}
}

func TestParseManifestRefusesWhatItCannotFollow(t *testing.T) {
	for _, raw := range []string{
		`{"schemaVersion":2,"routes":[]}`,
		`{"schemaVersion":1,"routes":[{"method":"GET","path":"/x","credential":"device"}]}`,
		`{"schemaVersion":1,"routes":[{"method":"GET","path":"/x","credential":"none","issues":"everything"}]}`,
		`{"schemaVersion":1,"routes":[{"method":"GET","path":"/x","credential":"none","clears":["cookies"]}]}`,
	} {
		if _, err := ParseManifest([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestMatch(t *testing.T) {
	m := &Manifest{SchemaVersion: 1, Routes: []ManifestRoute{
		{Method: "GET", Path: "/admin/users/{userId}", Credential: "access"},
		{Method: "POST", Path: "/admin/users/import", Credential: "access"},
		{Method: "POST", Path: "/webauthn/login/start", Credential: "preAuth"},
	}}

	if got, ok := m.match("GET", "/admin/users/a%2Fb"); !ok || got.params["userId"] != "a/b" {
		t.Fatalf("param match %+v %v", got, ok)
	}
	if got, _ := m.match("POST", "/admin/users/import"); got.route.Path != "/admin/users/import" {
		t.Fatal("a parameter beat a static segment")
	}
	if _, ok := m.match("POST", "/webAuthn/login/start"); !ok {
		t.Fatal("static segments should compare case-insensitively")
	}
	for _, path := range []string{"/admin/users", "/admin/users/1/x", "/admin/users/..", "/admin/users/%2e"} {
		if _, ok := m.match("GET", path); ok {
			t.Fatalf("matched %s", path)
		}
	}
	if _, ok := m.match("DELETE", "/admin/users/1"); ok {
		t.Fatal("matched the wrong method")
	}
}

func TestUpstreamPathEscapesParameters(t *testing.T) {
	r := ManifestRoute{Path: "/admin/users/{userId}"}
	if got := r.upstreamPath(map[string]string{"userId": "a/b?c"}); got != "/admin/users/a%2Fb%3Fc" {
		t.Fatalf("got %s", got)
	}
}

func TestManifestSourceFallsBackAndWaits(t *testing.T) {
	api := newFakeAPI(t)
	source := newManifestSource(api.server.URL, api.server.Client(), true, func(string, ...any) {})

	if got := source.get(context.Background()); got != source.bundled {
		t.Fatal("expected the bundled manifest when the API serves none")
	}
	source.get(context.Background())
	if n := len(api.callsTo("GET", ManifestPath)); n != 1 {
		t.Fatalf("fetched %d times within the retry window", n)
	}
}
