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
### 2.  Create Empty Commit (Required for PR)

Since the release branch is identical to main, create an empty commit to enable PR creation:

```bash
# Create an empty commit with release message
git commit --allow-empty -m "Release commit for devnet x"/

# Push the release branch
git push origin release
```
### 3. Create Pull Request
Create a Pull Request from release branch to main branch with the following labels:

- Required Labels:
  - `release` - Mandatory label to trigger the release workflow

   - Version label - One of the following formats (MANDATORY):
        - `v1.0.0`
        - `version:1.0.0`
        - `1.0.0`
   - Optional Labels:
      - Network tag (optional) - One of:
           - `devnet0`, `devnet1`, `devnet2`, etc.

### 4. Review and Merge Pull Request

Have the PR reviewed and approved by team members
Merge the Pull Request to main
The GitHub Actions workflow will automatically trigger


## What the Workflow Creates

- Git Tags (Created on main branch)

   - Version tag: v{VERSION} (e.g., v1.2.3)
   - Network tag: {NETWORK} (e.g., devnet1, testnet, mainnet)
- Docker Images (Multi-architecture: AMD64 & ARM64)
     - Latest: blockblaz/zeam:latest
     - Version: blockblaz/zeam:{VERSION} (e.g., blockblaz/zeam:1.2.3)
     - Network: blockblaz/zeam:{NETWORK} (e.g., blockblaz/zeam:devnet1)
     - Architecture-specific:
        - blockblaz/zeam:{TAG}-amd64
        - blockblaz/zeam:{TAG}-arm64
- GitHub Release
     Created only when a network tag is present
     Title: "Zeam Release {NETWORK}"
     Includes Docker pull commands and version information
     Marked as prerelease for devnet tags, regular release for testnet/mainnet