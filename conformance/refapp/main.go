// Command refapp is the reference app the Seamless Auth adapter conformance suite
// drives (seamless verify --adapter-url). Its routes and configuration follow
// verify/CONFORMANCE.md in fells-code/seamless-cli. It is a test fixture, not an
// example deployment: /__captured exposes one-time codes.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	seamlessauth "github.com/fells-code/seamless-auth-go"
)

type captured struct {
	Token        string `json:"token"`
	MagicLinkURL string `json:"magicLinkUrl,omitempty"`
	InviteURL    string `json:"inviteUrl,omitempty"`
}

func main() {
	var (
		mu         sync.Mutex
		deliveries = map[string]captured{}
	)

	adapter, err := seamlessauth.New(seamlessauth.Options{
		AuthServerURL:    os.Getenv("AUTH_SERVER_URL"),
		AuthServerIssuer: os.Getenv("AUTH_SERVER_ISSUER"),
		CookieSecret:     os.Getenv("COOKIE_SIGNING_KEY"),
		ServiceSecret:    os.Getenv("SEAMLESS_SERVICE_TOKEN"),
		JWKSKid:          os.Getenv("JWKS_KID"),
		Deliver: func(_ context.Context, d seamlessauth.Delivery) error {
			mu.Lock()
			defer mu.Unlock()
			deliveries[d.To] = captured{Token: d.Token, MagicLinkURL: d.MagicLinkURL, InviteURL: d.SignInURL}
			return nil
		},
		// One trusted hop: the harness sends each virtual user with its own
		// X-Forwarded-For. Trusting whatever the immediate peer is would be wrong in
		// a deployment, and is acceptable only because this is a test app.
		ResolveClientIP: func(r *http.Request) string {
			if hops := r.Header.Values("X-Forwarded-For"); len(hops) > 0 {
				all := strings.Split(strings.Join(hops, ","), ",")
				return strings.TrimSpace(all[len(all)-1])
			}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			return host
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /__captured/{recipient}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		entry, ok := deliveries[r.PathValue("recipient")]
		mu.Unlock()
		if !ok {
			writeJSON(w, nil)
			return
		}
		writeJSON(w, entry)
	})
	me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := seamlessauth.UserFromContext(r.Context())
		writeJSON(w, map[string]string{"id": user.ID})
	})
	mux.Handle("GET /api/me", adapter.RequireAuth(me))
	mux.Handle("GET /api/permissions/any", adapter.RequirePermission("conformance:read", "conformance:other")(me))
	mux.Handle("GET /api/permissions/all", adapter.RequirePermissionWith(
		[]string{"conformance:read", "conformance:write"}, seamlessauth.AllPermissions())(me))
	mux.Handle("GET /api/permissions/org", adapter.RequirePermissionWith(
		[]string{"conformance:org"}, seamlessauth.InOrganization())(me))
	mux.Handle("GET /api/permissions/org/{organizationId}", adapter.RequirePermissionWith(
		[]string{"conformance:org"}, seamlessauth.InRouteOrganization("organizationId"))(me))
	mux.Handle("/auth/", http.StripPrefix("/auth", adapter.Handler()))

	addr := ":" + envOr("PORT", "8080")
	log.Printf("seamless-auth-go reference app listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
