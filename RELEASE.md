# Zeam Release Process

This document outlines the complete process for creating releases using the automated GitHub Actions workflow.

## Overview

The Zeam release process uses a GitHub Actions workflow that automatically creates git tags, builds Docker images, and publishes releases when a Pull Request from the `release` branch to `main` branch is merged with specific labels.

## Prerequisites

- Repository access with write permissions to create branches and merge PRs
- Understanding of semantic versioning (e.g., `1.0.0`, `1.2.3`)
- Basic knowledge of Git and GitHub

## Step-by-Step Release Process

### 1. Create Release Branch

Start by creating a release branch from the latest `main` branch:
```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create and checkout release branch
git checkout -b release 
```

### 2. Create Empty Commit (Required for PR)

Since the release branch is identical to main, create an empty commit to enable PR creation:

```bash
# Create an empty commit with release message
git commit --allow-empty -m "Release commit for devnet x"

# Push the release branch
git push origin release
```

### 3. Create Pull Request

Create a Pull Request from release branch to main branch with the following labels:

- Required Labels:
  - `release` – Mandatory label to trigger the release workflow
  - Version label (MANDATORY): `x.y.z` (e.g., `1.0.0`)
- Optional Labels:
  - Network tag (optional): `devnet0`, `devnet1`, `devnet2`, etc.

### 4. Review and Merge Pull Request

- Have the PR reviewed and approved by team members
- Merge the Pull Request to main
- The GitHub Actions workflow will automatically trigger

## What the Workflow Creates

When the PR is merged with a version label and an optional devnet label, the workflow produces the following:

- Git Tags (created on the main branch)
  - Version tag: `v{VERSION}` (e.g., `v1.2.3`)
  - GitHub devnet tag: `{GITHUB_TAG}` (capitalized, e.g., `Devnet2`)
    - Used for the git tag and the GitHub Release
- Docker Images (Multi-architecture: AMD64 & ARM64)
  - Latest: `blockblaz/zeam:latest`
  - Version: `blockblaz/zeam:{VERSION}` (e.g., `blockblaz/zeam:1.2.3`)
  - Devnet (docker tag): `blockblaz/zeam:{DOCKER_TAG}` (lowercase, e.g., `blockblaz/zeam:devnet2`)
  - Architecture-specific:
    - `blockblaz/zeam:{TAG}-amd64`
    - `blockblaz/zeam:{TAG}-arm64`
  - Manifests:
    - `latest` = `latest-amd64` + `latest-arm64`
    - `{VERSION}` = `{VERSION}-amd64` + `{VERSION}-arm64`
    - `{DOCKER_TAG}` = `{DOCKER_TAG}-amd64` + `{DOCKER_TAG}-arm64`
- Branch
  - Created/updated: `{DOCKER_TAG}` (lowercase, e.g., `devnet2`)
  - Note: Branch name intentionally differs from the GitHub devnet tag (`Devnet2`)
- GitHub Release
  - Created only when a devnet tag is present
  - Title: `Zeam {GITHUB_TAG} Release` (e.g., `Zeam Devnet2 Release`)
  - Tag name: `{GITHUB_TAG}` (e.g., `Devnet2`)
  - Body includes:
    - Version: `{VERSION}`
    - Docker pull commands using `{DOCKER_TAG}`
    - Link to the release: `/releases/tag/{GITHUB_TAG}`
  - Marked as prerelease for devnet tags

### Labels to Outputs Mapping

- Version label → `VERSION` → creates `v{VERSION}` git tag and versioned Docker images
- Devnet label (e.g., `devnet2`) → two outputs:
  - `github_tag` = `Devnet2` (capitalized)
    - Used for git tag and GitHub Release
  - `docker_tag` = `devnet2` (lowercase)
    - Used for Docker image tags, manifests, and branch name

### Example

For labels:
- Version: `0.2.6`
- Devnet: `devnet2`

Outputs:
- Git tags: `v0.2.6`, `Devnet2`
- Docker images:
  - `blockblaz/zeam:latest`
  - `blockblaz/zeam:0.2.6`, `blockblaz/zeam:0.2.6-amd64`, `blockblaz/zeam:0.2.6-arm64`
  - `blockblaz/zeam:devnet2`, `blockblaz/zeam:devnet2-amd64`, `blockblaz/zeam:devnet2-arm64`
- Branch: `devnet2`
- GitHub Release: tag `Devnet2`, title `Zeam Devnet2 Release`, prerelease