# seamless-auth-go

## 0.1.0

The first release: a Seamless Auth server adapter for `net/http`, standard library only.

- Serves the auth routes from the auth API's adapter manifest, over httpOnly cookies for browsers
  and bearer tokens for native clients.
- `RequireAuth` and `Authenticate` guard your own routes.
- Passes the seamless-cli adapter conformance suite.
- A request body must be `application/json` (or a `+json` type), or the auth routes answer 415
  `unsupported_media_type`. This closes a login CSRF through cross-site `text/plain` forms.
- `RequireAuth` refuses a cookie session on cross-site state changes with 403
  `cross_site_request_blocked`.
