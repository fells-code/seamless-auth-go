# seamless-auth-go

A [Seamless Auth](https://github.com/fells-code/seamless-auth-api) server adapter for Go's
`net/http`, so it works with chi, Echo and Gin as well.

The adapter sits in your backend between your users and the Seamless Auth API:

- **Browsers** talk to it over `HttpOnly` cookies on your own domain. The API's tokens never
  reach page scripts.
- **Native clients** (mobile, CLIs) talk to it over bearer tokens, sending
  `x-seamless-auth-transport: bearer`.
- **The auth API** sees bearer tokens plus a service token that lets it trust the client
  address and user agent the adapter forwards.

Which routes the adapter serves, and what each does to the session, comes from the adapter
manifest the auth API publishes, so a new API route works without a new release of this
module. It has no dependencies outside the Go standard library.

It is held to the same [conformance suite](https://github.com/fells-code/seamless-cli/blob/main/verify/CONFORMANCE.md)
as the Express and Fastify adapters, in CI on every change.

## Install

```bash
go get github.com/fells-code/seamless-auth-go
```

Go 1.22 or later.

## Use

```go
package main

import (
	"log"
	"net/http"
	"os"

	seamlessauth "github.com/fells-code/seamless-auth-go"
)

func main() {
	auth, err := seamlessauth.New(seamlessauth.Options{
		AuthServerURL: os.Getenv("AUTH_SERVER_URL"),
		CookieSecret:  os.Getenv("COOKIE_SECRET"),   // at least 32 characters
		ServiceSecret: os.Getenv("SERVICE_SECRET"),  // the API's API_SERVICE_TOKEN
		JWKSKid:       os.Getenv("JWKS_KID"),
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// The auth routes, at /auth, which is where the client SDKs call.
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	// Your own routes, behind the adapter's guard.
	mux.Handle("GET /api/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := seamlessauth.UserFromContext(r.Context())
		w.Write([]byte(user.ID))
	})))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

With other routers:

```go
// chi
r.Mount("/auth", http.StripPrefix("/auth", auth.Handler()))
r.With(auth.RequireAuth).Get("/api/me", me)

// Gin
g.Any("/auth/*path", gin.WrapH(http.StripPrefix("/auth", auth.Handler())))
```

### The guard

`RequireAuth` answers 401 unless the request carries a session, and puts a `*User` on the
request context (`UserFromContext`). It accepts the adapter's session cookie, or an auth API
access token in `Authorization: Bearer` for clients with no cookie jar. The cookie wins when
both are present. It reads the `Cookie` header itself, so it works on any route. It does not
refresh: the auth routes refresh a browser session silently, and a bearer client calls
`POST /auth/refresh` itself. `Authenticate` does the same check without answering.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `AuthServerURL` | required | Where the adapter reaches the auth API |
| `AuthServerIssuer` | `AuthServerURL` | Expected `iss` of the API's tokens, when it differs from the URL you reach it at |
| `Audience` | `AuthServerIssuer` | Expected `aud` of the API's tokens |
| `CookieSecret` | required | Signs the session cookies (32 characters or more) |
| `ServiceSecret` | required | The API's `API_SERVICE_TOKEN` (32 characters or more) |
| `JWKSKid` | `dev-main` | `kid` header on service tokens |
| `CookieDomain` | none | Cookie `Domain` |
| `InsecureCookies` | `false` | Drops `Secure`, for local development over HTTP |
| `CookieSameSite` | `None`, or `Lax` with `InsecureCookies` | Cookie `SameSite` |
| `AllowedOrigins` | none | The only cross-origin callers allowed to change state while cookies are `SameSite=None` |
| `AccessCookieName`, `RefreshCookieName` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `RegistrationCookieName`, `PreAuthCookieName` | `seamless-ephemeral` | Sign-in flow cookie names |
| `Deliver` | none | Sends OTP codes and magic links through your own transports |
| `ResolveClientIP` | the connecting peer | The end user's address. See below |
| `DisableManifestFetch` | `false` | Use only the manifest bundled with this version |
| `HTTPClient`, `Logf` | defaults | Outbound client and logger |

### Client IP

The adapter forwards the end user's address and user agent so the auth API rate limits and
audits against the user, not your server. Behind a proxy, name it:

```go
ResolveClientIP: seamlessauth.TrustedProxies("10.0.0.0/8"),
```

`TrustedProxies` walks `X-Forwarded-For` from the right, skipping trusted proxies. There is
deliberately no hop-count option: a hop count cannot tell a proxy from a client that sent its
own header.

### Delivery

Without `Deliver`, the auth API sends OTP codes and magic links itself. With it, the adapter
asks the API for the message and hands it to you:

```go
Deliver: func(ctx context.Context, d seamlessauth.Delivery) error {
	return mailer.Send(ctx, d.To, d.Kind, d.Token, d.MagicLinkURL)
},
```

A delivery error answers the request with 502 `delivery_failed`.

## The manifest

On its first request the adapter fetches `/.well-known/seamless-adapter.json` from the auth API
(5 second timeout) and keeps it for the life of the process. If the API serves none, it uses the
copy embedded in this module and tries again a minute later. A manifest with anything this
version does not understand is refused whole, rather than following a route with the wrong
token. Refresh the embedded copy with `scripts/sync-manifest.sh`.

## Conformance

`conformance/refapp` is the reference app the conformance suite drives. To run it locally you
need Docker, a checkout of `seamless-auth-api` and the `seamless` CLI:

```bash
PORT=8080 AUTH_SERVER_URL=http://localhost:5312 AUTH_SERVER_ISSUER=http://auth-api:5312 \
  API_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  go run ./conformance/refapp &

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0
