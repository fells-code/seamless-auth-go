# Changelog

## [0.6.0](https://github.com/fells-code/seamless-auth-go/compare/v0.5.0...v0.6.0) (2026-11-06)


### Added

* **guard:** add RequirePermission, organization aware ([#34](https://github.com/fells-code/seamless-auth-go/issues/34)) ([831fcf2](https://github.com/fells-code/seamless-auth-go/commit/831fcf216dcf4050d1dbf26c07a8d9b72673da22)), closes [#29](https://github.com/fells-code/seamless-auth-go/issues/29)
* let verify-only resource servers require a user ([cee15df](https://github.com/fells-code/seamless-auth-go/commit/cee15df21888c30a92b3f5238a421bc6c0c71f2a))
* let verify-only resource servers require a user ([5cfebe1](https://github.com/fells-code/seamless-auth-go/commit/5cfebe138107c6ba471593a2e12d643f88c321f4))


### Fixed

* check Origin on unsafe methods whatever the SameSite setting ([d8e5a40](https://github.com/fells-code/seamless-auth-go/commit/d8e5a40955394f574b6aa77e63420f0aae76ddd5)), closes [#23](https://github.com/fells-code/seamless-auth-go/issues/23)
* keep a completed refresh for cookie transport for five seconds ([eb9524f](https://github.com/fells-code/seamless-auth-go/commit/eb9524fe851ae50ce2e46ca650a22c634355b655)), closes [#21](https://github.com/fells-code/seamless-auth-go/issues/21)
* let body-less refresh and logout through the content type gate ([5447b2e](https://github.com/fells-code/seamless-auth-go/commit/5447b2e5985dcf065fa0c861f913b83ec0524352)), closes [#23](https://github.com/fells-code/seamless-auth-go/issues/23)
* no refresh replay after rotation, and origin check whatever the SameSite setting ([0d7fbe8](https://github.com/fells-code/seamless-auth-go/commit/0d7fbe886c090de4c3b8a8c802548eb76462884b))
* refuse a null Origin before checking Sec-Fetch-Site ([a4d4708](https://github.com/fells-code/seamless-auth-go/commit/a4d4708ab63196d6ca6db526555f630591c948de)), closes [#23](https://github.com/fells-code/seamless-auth-go/issues/23)
* run refresh rotation detached and keep cookies on transport errors ([e8ba2f0](https://github.com/fells-code/seamless-auth-go/commit/e8ba2f0875802e9f6df04a2b0801072624e2c35f)), closes [#22](https://github.com/fells-code/seamless-auth-go/issues/22)
* share a refresh rotation only while it is in flight ([a569544](https://github.com/fells-code/seamless-auth-go/commit/a569544a816cb17ff754d9105b12c31663e4d7d4)), closes [#21](https://github.com/fells-code/seamless-auth-go/issues/21)
* sync the bundled adapter manifest with API 0.22.0 ([61514c5](https://github.com/fells-code/seamless-auth-go/commit/61514c517e82245f9dd21bc401f2a1e713f75b71))
* sync the bundled adapter manifest with API 0.22.0 ([6b4e343](https://github.com/fells-code/seamless-auth-go/commit/6b4e343998bef4f3971f4d76fd2da0ec4a41a5e6))
* sync the bundled manifest with seamless-auth-api 0.22.0 ([6bf02d7](https://github.com/fells-code/seamless-auth-go/commit/6bf02d71d3129a284d88f2e8c66cc257eb703b0b))

## [0.5.0](https://github.com/fells-code/seamless-auth-go/compare/v0.4.0...v0.5.0) (2026-11-01)


### Added

* add a first-party role guard and the organization on User ([81f1972](https://github.com/fells-code/seamless-auth-go/commit/81f1972c4974b0d3af781de4e30f0ba215926853)), closes [#25](https://github.com/fells-code/seamless-auth-go/issues/25)
* first-party role guard and the organization on User ([85aacec](https://github.com/fells-code/seamless-auth-go/commit/85aacecb83a9430e598501422c7cf6df3347198c))


### Fixed

* clear a custom pre-auth cookie on logout ([9777d29](https://github.com/fells-code/seamless-auth-go/commit/9777d2959daf04078294b69ac2c0eed74aecf01f)), closes [#25](https://github.com/fells-code/seamless-auth-go/issues/25)
* sync the bundled adapter manifest with API 0.21.1 ([334848c](https://github.com/fells-code/seamless-auth-go/commit/334848c94f415feb55947cb18e9a792f14bedf1b)), closes [#24](https://github.com/fells-code/seamless-auth-go/issues/24)
* sync the bundled adapter manifest with API 0.21.1 and check it in CI ([96d380b](https://github.com/fells-code/seamless-auth-go/commit/96d380b68e0277802e21f9cca4382af1abfde73a))

## [0.4.0](https://github.com/fells-code/seamless-auth-go/compare/v0.3.0...v0.4.0) (2026-11-01)


### Added

* verify-only resource server mode with audience, scope, role and step-up guards ([70388a4](https://github.com/fells-code/seamless-auth-go/commit/70388a421973aa8a0effae464811e7ba8bc7d576))
* verify-only resource server mode with audience, scope, role and step-up guards ([0361e0f](https://github.com/fells-code/seamless-auth-go/commit/0361e0fe7aeee8a4992cac19f98f07ca5914a61d))


### Fixed

* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([aa76464](https://github.com/fells-code/seamless-auth-go/commit/aa764641407980f2a83d872b30faa5361d7d086b))
* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([16f71ef](https://github.com/fells-code/seamless-auth-go/commit/16f71ef1e676cec6cd067339a6f8c1db484e663f))
* verify-only setup errors for empty guard values, and claim type tests ([a666daf](https://github.com/fells-code/seamless-auth-go/commit/a666dafa85c7d4622defb8843309233c4871fe47))


### Documentation

* show unsubscribe headers from your own sender and the invite's signInUrl ([978d428](https://github.com/fells-code/seamless-auth-go/commit/978d42885c4e5d293babf0a83e876f17ab4542d1))
* show unsubscribe headers from your own sender and the invite's signInUrl ([00ae549](https://github.com/fells-code/seamless-auth-go/commit/00ae549b25d84a52dd8a4e275e78072c67cb674d))

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
