# Zeam Release Process

This document describes the PR-based, label-based release process used by the automated GitHub Actions release workflow.

## Overview

A release is created by merging a Pull Request from the `release` branch into `main` with release labels.

The workflow always reads release metadata from PR labels:

- `release` — required; enables the release workflow
- `x.y.z` — required version label, for example `0.4.36`
- `devnetN` — optional network label, for example `devnet4` or `devnet5`

The workflow resolves the release commit from the release PR head, not blindly from the top of `main`. If the PR head is an empty release commit, the workflow publishes its parent. This allows two release modes:

1. **Current-main release** — create `release` from `origin/main`.
2. **Pinned release** — create `release` from a specific earlier commit, then add an empty release commit.

This keeps the process PR-reviewed and label-based while allowing releases from exact commits.

## Prerequisites

- Repository access with permission to create/push the `release` branch and open PRs
- Permission to add release labels and merge the release PR
- A unique semantic version label, for example `0.4.36`

## Important Behavior

### Release commit

The workflow starts from the release PR head commit:

```text
github.event.pull_request.head.sha
```

If the PR head is an empty single-parent release commit, the workflow publishes the parent commit instead. Git tags, Docker metadata, and the devnet branch point to the commit whose code is actually being released.

### `latest` Docker tag

`blockblaz/zeam:latest` is only updated when the resolved release tree matches current `main`.

- Current-main release: updates `latest`
- Pinned older release: does **not** update `latest`

This prevents an older pinned devnet release from accidentally overwriting `latest`.

### Devnet branch

When a devnet label is present, the corresponding lowercase branch is updated to the release commit:

```text
devnet4, devnet5, ...
```

The branch is intentionally lowercase, while the GitHub Release tag is capitalized:

```text
Docker/branch: devnet4
GitHub tag:   Devnet4
```

## Release Mode 1: Current-Main Release

Use this when the release should include the latest code on `main`.

### Steps

```bash
git fetch origin --prune --tags
git checkout -B release origin/main
git commit --allow-empty -m "Release commit for devnet5 v0.5.0"
git push -f origin release
```

Open a PR:

```text
release -> main
```

Add labels:

```text
release
0.5.0
devnet5
```

After review, merge the PR. The workflow will publish the parent of the empty release commit and, because its tree matches current `main`, update `latest`.

## Release Mode 2: Pinned Release from a Specific Commit

Use this when the release should be cut from an exact older commit, not from top of `main`.

Common uses:

- final release for an old devnet
- release before a large breaking PR
- known-good historical build
- hotfix-style release from an earlier point in history

### Steps

Find the target commit:

```bash
git fetch origin --prune --tags
git log --oneline origin/main
```

Create the release branch from that commit:

```bash
git checkout -B release <target-commit>
git commit --allow-empty -m "Release commit for devnet4 v0.4.36 from <target-commit>"
git push -f origin release
```

Open a PR:

```text
release -> main
```

Add labels:

```text
release
0.4.36
devnet4
```

After review, merge the PR. The workflow will publish the parent of the empty release commit. Because the release tree does not match current `main`, the workflow will skip the `latest` Docker tag.

### Example: Final devnet4 Before devnet5

If `0009ea9` is the commit immediately before devnet5 landed:

```bash
git fetch origin --prune --tags
git checkout -B release 0009ea9
git commit --allow-empty -m "Release commit for devnet4 v0.4.36 from 0009ea9"
git push -f origin release
```

PR labels:

```text
release
0.4.36
devnet4
```

Expected outputs:

```text
v0.4.36
Devnet4
blockblaz/zeam:0.4.36
blockblaz/zeam:devnet4
```

`blockblaz/zeam:latest` is not updated for this pinned release.

## What the Workflow Creates

When the PR is merged with a version label and optional devnet label, the workflow produces:

### Git tags

- Version tag: `v{VERSION}`, for example `v0.4.36`
- Devnet tag: `{GITHUB_TAG}`, for example `Devnet4`
  - The devnet tag is recreated if it already exists.
  - The version tag must not already exist.

### Docker images

- Versioned image:
  - `blockblaz/zeam:{VERSION}`
  - `blockblaz/zeam:{VERSION}-amd64`
  - `blockblaz/zeam:{VERSION}-arm64`
- Devnet image, when a devnet label is present:
  - `blockblaz/zeam:{DOCKER_TAG}`
  - `blockblaz/zeam:{DOCKER_TAG}-amd64`
  - `blockblaz/zeam:{DOCKER_TAG}-arm64`
- Latest image, only for current-main releases:
  - `blockblaz/zeam:latest`
  - `blockblaz/zeam:latest-amd64`
  - `blockblaz/zeam:latest-arm64`

### GitHub Release

Created only when a devnet label is present.

- Tag: `DevnetN`, for example `Devnet4`
- Title: `Zeam DevnetN Release`
- Marked as prerelease
- Includes version, release commit, changelog, and Docker pull commands
- Changelog source:
  - If a `devnetN` label is present, changelog is generated from `DevnetN-1` when that tag exists.
  - If no devnet label is present, or the previous devnet tag does not exist, changelog falls back to the nearest lower `vX.Y.Z` version tag.

### Devnet branch

Created or updated to the release commit:

```text
{DOCKER_TAG}
```

For example:

```text
devnet4
```

## Label Mapping

- Version label `0.4.36` → `VERSION=0.4.36` → tag `v0.4.36`
- Devnet label `devnet4` → Docker tag/branch `devnet4`
- Devnet label `devnet4` → GitHub Release tag `Devnet4`

## Guardrails

The workflow enforces these checks:

- PR must be merged into `main`.
- PR head branch must be `release`.
- PR must have the `release` label.
- PR must have exactly a valid semantic version-style label, such as `0.4.36`.
- Version tag `v{VERSION}` must not already exist.
- Release PR parent must be reachable from `main` history.
- `latest` is only published when the resolved release tree matches current `main`.

## Troubleshooting

### PR says it is behind main

This is expected for pinned releases.

Example:

```text
A -- B -- C -- D  main
      \
       R          release
```

If `release` was created from `B` and `R` is an empty release commit, GitHub may show the PR as behind `main`. That is fine. The empty release commit normally merges without conflicts because it changes no files.

### Will a pinned release PR create conflicts?

Usually no, as long as the release branch only contains the empty release commit. Since the commit changes no files, there is normally nothing to conflict with.

### Why did `latest` not update?

The workflow only updates `latest` when the resolved release tree matches current `main`. Pinned releases intentionally skip `latest`.

### Why does the PR contain an empty release commit?

The empty commit exists only to make a reviewable PR from `release` to `main`. The workflow detects empty single-parent release commits and publishes the parent commit, so the recorded release SHA is the target commit being released.
