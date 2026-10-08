# Changesets

Add a changeset to every pull request that changes what adopters get:

```sh
npx changeset
```

Pick patch, minor or major, and write the summary as the release note an adopter reads. Before
1.0, a breaking change is a minor bump.

The release workflow turns merged changesets into a `chore: version packages` pull request.
Merging that pull request tags `vX.Y.Z` and publishes the GitHub release. `package.json` only
carries the version for this tooling; the Go module is versioned by its tag.
