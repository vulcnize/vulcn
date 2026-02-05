# Changesets

This project uses [Changesets](https://github.com/changesets/changesets) to manage versions and changelogs.

## Adding a Changeset

When you make a change that should be included in the changelog:

```bash
pnpm changeset
```

This will prompt you to:

1. Select which packages are affected (`@vulcn/engine`, `vulcn`, or both)
2. Choose the semver bump type (patch, minor, major)
3. Write a summary of the change

## Releasing

Releases are automated via GitHub Actions:

1. When PRs with changesets are merged to `main`, a "Release" PR is automatically created
2. The Release PR accumulates changes and updates versions/changelogs
3. When the Release PR is merged, packages are published to npm automatically

## Manual Release (Emergency)

For hotfixes, trigger the workflow manually from GitHub Actions.
