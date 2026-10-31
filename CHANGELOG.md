# Changelog

## [0.4.0](https://github.com/fells-code/seamless-auth-go/compare/v0.3.0...v0.4.0) (2026-10-31)


### Added

* verify-only resource server mode with audience, scope, role and step-up guards ([70388a4](https://github.com/fells-code/seamless-auth-go/commit/70388a421973aa8a0effae464811e7ba8bc7d576))
* verify-only resource server mode with audience, scope, role and step-up guards ([0361e0f](https://github.com/fells-code/seamless-auth-go/commit/0361e0fe7aeee8a4992cac19f98f07ca5914a61d))


### Fixed

* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([aa76464](https://github.com/fells-code/seamless-auth-go/commit/aa764641407980f2a83d872b30faa5361d7d086b))
* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([16f71ef](https://github.com/fells-code/seamless-auth-go/commit/16f71ef1e676cec6cd067339a6f8c1db484e663f))
* verify-only setup errors for empty guard values, and claim type tests ([a666daf](https://github.com/fells-code/seamless-auth-go/commit/a666dafa85c7d4622defb8843309233c4871fe47))

## [0.3.0](https://github.com/fells-code/seamless-auth-go/compare/v0.2.1...v0.3.0) (2026-10-25)


### Added

* recovery sessions and account notice delivery, with parity hardening ([6e8750f](https://github.com/fells-code/seamless-auth-go/commit/6e8750f615d1b80c77580cb0bded41b4f7fca6b7))
* recovery sessions and account notice delivery, with parity hardening ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02)), closes [#11](https://github.com/fells-code/seamless-auth-go/issues/11)


### Fixed

* cap cookie lifetimes at 400 days and require an http or https AuthServerURL ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02))
* **console:** keep the API's framing and content-type headers ([94f9af8](https://github.com/fells-code/seamless-auth-go/commit/94f9af8c0cf6a340856690bd54d8242f20130439)), closes [#10](https://github.com/fells-code/seamless-auth-go/issues/10)
* expire the JWKS cache, back off failed fetches and cap the key set size ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02))
* refuse placeholder cookie and service secrets outside insecure local mode ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02))
* refuse upstream redirects and keep upstream URLs out of logs ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02))
* require exp, clear cookies on a rejected logout and never pick tokens into a body ([09acec5](https://github.com/fells-code/seamless-auth-go/commit/09acec5417994b0af54cb6626b189b5640a6ce02))


### Documentation

* link the governance document and license pledge ([fa4a70f](https://github.com/fells-code/seamless-auth-go/commit/fa4a70f65e8d7d4bc7473787923dfcd102ffba11))
* link the governance document and license pledge ([73f03a1](https://github.com/fells-code/seamless-auth-go/commit/73f03a13498cd409f0c7e04be072461e5466f8dc))

## [0.2.1](https://github.com/fells-code/seamless-auth-go/compare/v0.2.0...v0.2.1) (2026-10-18)


### Fixed

* forward the pre-auth token on magic link verify and serve the confirm route ([#7](https://github.com/fells-code/seamless-auth-go/issues/7)) ([37511f2](https://github.com/fells-code/seamless-auth-go/commit/37511f22c8cdfac1ba195153464944dd13acb43d))


### Documentation

* name the app-side service token SEAMLESS_SERVICE_TOKEN ([#5](https://github.com/fells-code/seamless-auth-go/issues/5)) ([86fc6c3](https://github.com/fells-code/seamless-auth-go/commit/86fc6c35eccc808a8db690b3f48479d87464a578))

## [0.2.0](https://github.com/fells-code/seamless-auth-go/compare/v0.1.0...v0.2.0) (2026-10-08)


### Added

* serve the admin console through ConsoleHandler ([#3](https://github.com/fells-code/seamless-auth-go/issues/3)) ([fa3fd66](https://github.com/fells-code/seamless-auth-go/commit/fa3fd66ed96f194cafd4f3d1c68148dfa7459907))

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
