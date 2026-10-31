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
		CookieSecret:  os.Getenv("COOKIE_SECRET"),          // at least 32 characters
		ServiceSecret: os.Getenv("SEAMLESS_SERVICE_TOKEN"), // same value as the API's API_SERVICE_TOKEN
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

The auth server reads the service token from `API_SERVICE_TOKEN` and your app reads it from
`SEAMLESS_SERVICE_TOKEN`; both hold the same value.

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

A session cookie is signed with `CookieSecret`, but the auth API access token inside it is
verified too, the same way as a bearer token: RS256 against the API's JWKS, with the expected
issuer and audience, in date, of type `access`, and for the cookie's subject. `User.Roles` (and
`User.Recovery`) come from that verified token, not from the cookie, so a cookie signed with a
leaked `CookieSecret` cannot grant itself roles. If the JWKS cannot be fetched and no key set is
cached, the session is refused with 401.

### Recovery sessions

Redeeming an account recovery code issues a recovery session: its access token carries
`recovery: true`, and the auth API lets it do little more than enroll a new passkey or
authenticator app. `RequireAuth` refuses one with 403 `enrollment_required`, and `Authenticate`
returns `ErrEnrollmentRequired`, so your app never treats a half-recovered account as signed
in. Set `AllowRecoverySessions` to admit them; `User.Recovery` then marks one.

Enrolling lifts the restriction, but the token keeps its claim until it is refreshed. In cookie
transport the adapter refreshes the session itself after a successful
`POST /webauthn/register/finish` or `POST /totp/enroll/verify` from a recovery session, so the
new access cookie no longer carries it. A bearer client holds its own refresh token: it calls
`POST /auth/refresh` after enrolling.

A request `RequireAuth` admits on the session cookie also gets the auth routes' cross-site
check: while cookies are `SameSite=None`, a state-changing request from another site answers
403 `cross_site_request_blocked`. That is `Sec-Fetch-Site: cross-site`; or, with
`AllowedOrigins` set, `Sec-Fetch-Site: same-site` (which also covers a sibling subdomain) from an
`Origin` that is missing or not on the list; or, from a browser that sends no `Sec-Fetch-Site`,
an `Origin` outside `AllowedOrigins`. Without `AllowedOrigins`, a same-site request passes. A
bearer token is never attached by a browser, so it is not checked. `Authenticate` makes no such
check.

### Request bodies

The auth routes forward a request body to the auth API as JSON, so a body must be sent as
`application/json` (or a `+json` type). Anything else answers 415 `unsupported_media_type`: a
cross-site form can post a `text/plain` body shaped like JSON with no CORS preflight, and read as
JSON it would be a sign-in the user never made. The client SDKs already send JSON.

## Verify-only mode (resource servers)

An API that sits behind the Seamless Auth OpenID Provider, and only receives its access tokens
(RFC 9068 JWTs) as `Authorization: Bearer`, does not need the adapter. `NewVerifier` checks those
tokens with nothing but the provider's issuer and this API's resource identifier: no cookie
secret, no service secret, no auth routes.

```go
rs, err := seamlessauth.NewVerifier(seamlessauth.VerifierOptions{
	Issuer:   "https://login.example.com",  // the provider's oidc_issuer
	Audience: "https://orders.example.com", // this API's resource identifier
})
if err != nil {
	log.Fatal(err)
}

maxAge := 5 * time.Minute
stepUp, err := rs.RequireStepUp(seamlessauth.StepUp{ACRValues: []string{"phr"}, MaxAge: &maxAge})
if err != nil {
	log.Fatal(err)
}

mux.Handle("GET /orders", rs.RequireToken(rs.RequireScope("orders:read")(http.HandlerFunc(list))))
mux.Handle("POST /refunds", rs.RequireToken(stepUp(http.HandlerFunc(refund))))
mux.Handle("GET /admin", rs.RequireToken(rs.RequireRole("orders:admin")(http.HandlerFunc(admin))))
```

`RequireToken` puts a `*TokenUser` on the request context (`TokenUserFromContext`): `Subject`,
`ClientID`, `Scopes`, `Roles`, `SID`, `OrgID`, `ACR`, `AMR` and `AuthTime`. A client credentials
token is valid too; its `Subject` is the client and it has no user claims, so it can pass a scope
guard but never a role or step-up guard. `Authenticate` does the same check without answering.

The keys come from `<Issuer>/.well-known/openid-configuration`, whose `issuer` must equal
`Issuer` exactly and whose `jwks_uri` must be https when the issuer is. Set `JWKSURI` to skip
discovery. If discovery or the key set cannot be fetched, the request is refused with 401
(discovery is retried at most every 5 seconds); it never answers 500.

A token is accepted only when it is RS256 with `typ` `at+jwt`, a `kid` the key set publishes for
RS256 signatures and no `crit` header; issued by `Issuer` for `Audience`; in date (5 seconds
leeway); with a `sub` and a `client_id`; and without a `typ` claim, which marks the provider's
own session tokens. A token bound to a key by a `cnf` claim is refused unless `Confirm` accepts
it, which is where a DPoP proof check goes.

| Outcome | Status | `WWW-Authenticate` | Body |
| --- | --- | --- | --- |
| No bearer token | 401 | `Bearer` | `{"error":"missing_token"}` |
| Token does not verify | 401 | `Bearer error="invalid_token"` | `{"error":"invalid_token"}` |
| `RequireScope` (every scope) | 403 | `Bearer error="insufficient_scope", scope="..."` | `{"error":"insufficient_scope","scope":"..."}` |
| `RequireRole` (any role) | 403 | none | `{"error":"insufficient_role"}` |
| `RequireStepUp` | 401 | RFC 9470 `insufficient_user_authentication` challenge | the same members as JSON |

`RequireRole` matches roles as `@seamless-auth/types` does (`RoleGrantsAccess`): `billing:*` and
`billing` grant `billing:invoices`, and `orders:write` grants `orders:read`. `RequireStepUp`
checks `acr` against `ACRValues` (listing `phr` also accepts `phrh`), every method in `AMR`, and
`auth_time` against `MaxAge`, then answers with the `acr_values` and `max_age` the client should
ask the provider for. Guards go inside `RequireToken`; on their own they answer as a missing
token.

With Gin, wrap the middleware:

```go
func wrap(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			c.Request, passed = r, true
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
		}
	}
}

g.GET("/orders", wrap(rs.RequireToken), wrap(rs.RequireScope("orders:read")), list)
```

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `AuthServerURL` | required | Where the adapter reaches the auth API |
| `AuthServerIssuer` | `AuthServerURL` | Expected `iss` of the API's tokens, when it differs from the URL you reach it at |
| `Audience` | `AuthServerIssuer` | Expected `aud` of the API's tokens |
| `CookieSecret` | required | Signs the session cookies (32 characters or more, and not a placeholder from the examples) |
| `ServiceSecret` | required | The service token, read from `SEAMLESS_SERVICE_TOKEN` in the examples; the same value as the API's `API_SERVICE_TOKEN` (32 characters or more, and not a placeholder) |
| `JWKSKid` | `dev-main` | `kid` header on service tokens |
| `CookieDomain` | none | Cookie `Domain` |
| `InsecureCookies` | `false` | Drops `Secure`, for local development over HTTP. Also lets placeholder secrets through, with a warning |
| `CookieSameSite` | `None`, or `Lax` with `InsecureCookies` | Cookie `SameSite` |
| `AllowedOrigins` | none | The only cross-origin and same-site callers allowed to change state while cookies are `SameSite=None` |
| `AccessCookieName`, `RefreshCookieName` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `RegistrationCookieName`, `PreAuthCookieName` | `seamless-ephemeral` | Sign-in flow cookie names |
| `Deliver` | none | Sends OTP codes and magic links through your own transports |
| `DeliverAccountNotices` | `false` | `Deliver` also sends account notices. See below |
| `AllowRecoverySessions` | `false` | `RequireAuth` admits a recovery session |
| `ResolveClientIP` | the connecting peer | The end user's address. See below |
| `DisableManifestFetch` | `false` | Use only the manifest bundled with this version |
| `HTTPClient`, `Logf` | defaults | Outbound client and logger. The client never follows a redirect: a supplied one is copied with a `CheckRedirect` that refuses them, and gets a 15 second timeout if it has none |

`New` refuses an `AuthServerURL` that is not `http` or `https`, and the known placeholder secrets
(`dev-only-cookie-signing-key-replace-me`, `GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV`, anything
containing `replace-me`) unless `InsecureCookies` is set.

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

A delivery error answers the request with 502 `delivery_failed`. `d.Kind` is one of the
`Delivery*` constants; a kind this version does not know is logged and not handed to you. A code
with `d.Purpose == seamlessauth.PurposeAccountRecovery` recovers an account rather than signing
in: word it as a warning that someone asked to recover the account.

#### Account notices

Opening an account recovery request (`POST /recovery/verify`, marked `notices` in the manifest)
tells the owner at every verified address, with a link to cancel it. By default the auth API
sends these notices itself, even when you set `Deliver`. Set `DeliverAccountNotices` once your
`Deliver` sends `account_notice_email` (`Subject`, `Text`) and `account_notice_sms` (`Text`):
the adapter then asks for them and hands each one to you. The API counts a notice it hands
back as the owner being told, so set it only when both kinds really go out.

`d.CancelURL` carries a credential: send it to `d.To` only, and never log it. A `Delivery`
prints without its code or links. If at least one notice is sent, the request answers as usual.
If none is, the adapter cancels the recovery request with the cancel link's token and answers
503 `recovery_notice_failed`, as the API does when it cannot notify the owner itself.

### Magic links

The auth API signs a user in from a magic link only on the device that asked for it. On
`GET /magic-link/verify/{token}` the adapter forwards that device's pre-auth token when it has
one: the client's own bearer token in bearer transport, or the pre-auth cookie in cookie
transport if it verifies. Without one it sends none, and never answers 401, because the API
falls back to the client address and user agent the adapter forwards.

Opened anywhere else, the link answers 409 `confirmation_required`, with `requestedFrom`
(`deviceClass`, `requestedAt`) describing the request, and is not consumed. Once the user
approves it, `POST /magic-link/verify/{token}/confirm` consumes it. The requesting attempt's
first `GET /magic-link/check` after that issues the session; later checks answer
`{ "message": "Success" }` with no tokens, and the adapter then leaves the cookies as they are.

### The admin console

`ConsoleHandler` serves the Seamless admin dashboard from your API, proxied from the auth API, so
it shares the origin and cookie scope of the `/auth` routes:

```go
mux.Handle("/console/", http.StripPrefix("/console", auth.ConsoleHandler()))
```

It serves `GET` and `HEAD` only and forwards nothing but the method and path, so the browser's
cookies never reach the upstream. The API's `X-Frame-Options`, `Content-Security-Policy` and
`X-Content-Type-Options` come back with the console, so it cannot be framed on your origin. It refuses any path that could leave the console (dot segments,
encoded separators), and follows a redirect only while it stays inside the console on the auth API.
When you serve it, add your API's origin to the auth server's `ORIGINS` so passkey ceremonies
started in the console verify.

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
  SEAMLESS_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  go run ./conformance/refapp &

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0

Project governance, including the
[Seamless Auth License Pledge](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md#the-seamless-auth-license-pledge),
is in the fells-code [GOVERNANCE.md](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md).
