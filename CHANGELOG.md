# Changelog

## [0.2.2](https://github.com/fells-code/seamless-auth-go/compare/v0.2.1...v0.2.2) (2026-10-21)


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
