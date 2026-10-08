# AGENTS.md

This file is for coding agents working in `seamless-auth-go`, the Seamless Auth server adapter
for Go's `net/http`.

## Working Standards (fells-code baseline)

These rules apply to every repository in the fells-code org. Repo-specific
guidance may extend them but must not contradict them.

### Attribution

- Commit and open PRs solely under the repository owner's identity. Never
  commit under an agent or assistant identity.
- Never attribute work to an AI assistant: no `Co-Authored-By: Claude` (or any
  assistant) trailers, no "Generated with" / "Created with Claude" notes, and no
  assistant branding or emoji anywhere in commit messages, PR or issue titles
  and descriptions, changesets, code comments, or docs.

### Comments

- Comment only when the code genuinely needs explaining: a non-obvious reason, a
  gotcha, or an invariant. Never narrate what the code plainly does.

### TODOs

- Every `TODO`/`FIXME` must reference a ticket, e.g. `// TODO(#123): ...`.
  Do not leave a bare TODO. If no ticket exists, create one first.

### Commits & branches

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `test:`).
- Descriptive branch names (`feat/...`, `fix/...`); never a `claude/` or other
  tool-generated prefix.

### Public-facing text

- No em dashes in commit messages, code comments, PR or issue text, changesets,
  or docs. Use a comma, parentheses, or a separate sentence.

### Before declaring work done

- All code quality checks must pass before you open a PR or call the work done.
  Run them and report the real output; do not open a PR while any check is failing.
- Match the surrounding code's style, naming, and comment density.

## Checks

| Check | Command |
| --- | --- |
| Format | `gofmt -l .` (must print nothing) |
| Vet | `go vet ./...` |
| Tests | `go test -race ./...` |
| Conformance | see README, "Conformance" |
| Changeset | `npx changeset status` (a user-facing change needs one) |

The module targets Go 1.22. Do not use standard library APIs newer than that (CI runs 1.22).

## Shape

- `adapter.go`: `Adapter`, the request pipeline, the upstream call, writing results.
- `routes.go`: manifest routes, credential resolution (with silent refresh), session
  verification, what a cookie-transport body may contain.
- `refresh.go`: refresh sharing (one result per refresh token for 5 seconds), `POST /refresh`,
  logout.
- `manifest.go`: parsing, matching, the live and embedded manifest.
- `guard.go`: `RequireAuth`, `Authenticate`.
- `jwt.go`, `jwks.go`, `servicetoken.go`: HS256 cookies and service tokens, RS256 against the
  API's JWKS.
- `conformance/refapp`: the reference app for the conformance suite. A test fixture.

## Contract

This module bridges to the `seamless-auth-api` contract. Behaviour must match the Node adapters
in `fells-code/seamless-auth-server` and the conformance contract in
`fells-code/seamless-cli` (`verify/CONFORMANCE.md`). When they disagree, the conformance suite
is the arbiter: change the suite deliberately, never the adapter quietly.

- No external dependencies. Adopters audit this code; keep it standard library only.
- Never put `token` or `refreshToken` in a cookie-transport response body.
- Verify every session token against the API's JWKS before issuing a cookie from it.
- Never add a hop-count client IP option. It cannot tell a proxy from a client.

## Releases

Go modules release by git tag (`vX.Y.Z`). Pre-1.0: a breaking change is a minor bump, and 1.0 is
a deliberate decision, not a side effect.

Releases go through changesets, as in the other seamless-* repos. Do not tag by hand.

1. A pull request that changes what adopters get adds a changeset (`npx changeset`). Its summary
   is the release note.
2. On merge, `.github/workflows/release.yml` opens or updates the `chore: version packages` pull
   request, which bumps `package.json` and `CHANGELOG.md`.
3. Merging that pull request tags `vX.Y.Z` and publishes the GitHub release (`scripts/release.sh`).

`package.json` exists only for this tooling and to hold the version. It is not a dependency of
the module, which stays standard library only. A v2 needs the module path to end in `/v2` first,
and the release script refuses one that does not.
