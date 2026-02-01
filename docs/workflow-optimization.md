# GitHub Actions Workflow Optimization Guide

This document outlines optimization opportunities for the GitHub Actions workflows in this repository.

## Current Workflows

- **ci.yml** - Main CI pipeline with lint, build, test, and Docker build jobs
- **risc0.yml** - RISC0 prover workflow
- **auto-release.yml** - Automated release and Docker publishing

## Optimization Opportunities

### 1. Fix Matrix Configuration Issues

**Problem:** The `build-all-provers` and `test` jobs have matrix strategies but `runs-on` is hardcoded.

**Location:** `.github/workflows/ci.yml:169-176` and `:243-249`

**Current:**
```yaml
build-all-provers:
  name: build-all-provers
  runs-on: ubuntu-latest  # ❌ Hardcoded
  needs: build
  strategy:
    matrix:
      os: [ubuntu-latest, macos-latest]
```

**Impact:** Jobs only run once on ubuntu-latest instead of on both OSes, wasting the matrix configuration.

**Fix Options:**
- **Option A:** Use the matrix properly:
  ```yaml
  runs-on: ${{ matrix.os }}
  ```
- **Option B:** Remove the matrix if only ubuntu-latest is needed:
  ```yaml
  runs-on: ubuntu-latest
  # Remove strategy section
  ```

**Estimated Time Savings:** None directly, but clarifies intent and prevents confusion.

---

### 2. Parallelize Test Steps

**Problem:** The test job runs 4 test types sequentially.

**Location:** `.github/workflows/ci.yml:324-334`

**Current:**
```yaml
- name: Run all unit tests
  run: zig build test --summary all

- name: Run all sim tests
  run: zig build simtest --summary all

- name: Generate spec fixtures
  run: zig build spectest:generate --summary all

- name: Run all spec tests
  run: zig build spectest:run --summary all
```

**Recommended Change:** Split into separate parallel jobs:
```yaml
jobs:
  unit-tests:
    # ... setup steps
    - run: zig build test --summary all

  sim-tests:
    # ... setup steps
    - run: zig build simtest --summary all

  spec-generate:
    # ... setup steps
    - run: zig build spectest:generate --summary all
    - uses: actions/upload-artifact@v4
      with:
        name: spec-fixtures
        path: path/to/fixtures

  spec-tests:
    needs: spec-generate
    # ... setup steps
    - uses: actions/download-artifact@v4
      with:
        name: spec-fixtures
    - run: zig build spectest:run --summary all
```

**Estimated Time Savings:** 40-60% reduction in test phase time (tests run concurrently instead of sequentially).

---

### 3. Reduce Duplicate Setup Code

**Problem:** Every job repeats 20-30 lines of identical setup steps.

**Location:** All jobs in `ci.yml`

**Current:** Each job has:
- Set up Zig
- Set up Rust/Cargo
- Get build.zig.zon hash
- Get Cargo.lock hash
- Cache Zig packages
- Cache Rust dependencies
- Fetch Zig dependencies with retry

**Recommended Change:** Create a composite action:

**.github/actions/setup-build-env/action.yml:**
```yaml
name: 'Setup Build Environment'
description: 'Sets up Zig, Rust, and caches dependencies'
inputs:
  rust-toolchain:
    description: 'Rust toolchain version'
    required: false
    default: 'nightly'
  rust-components:
    description: 'Rust components to install'
    required: false
    default: ''
  cache-key-suffix:
    description: 'Suffix for cache keys'
    required: false
    default: 'default'

runs:
  using: "composite"
  steps:
    - name: Set up Zig
      uses: mlugg/setup-zig@v2.0.5
      with:
        version: 0.14.1

    - name: Set up Rust/Cargo
      uses: actions-rust-lang/setup-rust-toolchain@v1
      with:
        toolchain: ${{ inputs.rust-toolchain }}
        components: ${{ inputs.rust-components }}

    - name: Get build.zig.zon hash
      id: zig-zon-hash
      shell: bash
      run: |
        if [ -f build.zig.zon ]; then
          HASH=$(sha256sum build.zig.zon 2>/dev/null | cut -d' ' -f1 || shasum -a 256 build.zig.zon | cut -d' ' -f1)
          echo "hash=${HASH}" >> $GITHUB_OUTPUT
        else
          echo "hash=default" >> $GITHUB_OUTPUT
        fi

    - name: Get Cargo.lock hash
      id: cargo-lock-hash
      shell: bash
      run: |
        if [ -f rust/Cargo.lock ]; then
          HASH=$(sha256sum rust/Cargo.lock 2>/dev/null | cut -d' ' -f1 || shasum -a 256 rust/Cargo.lock | cut -d' ' -f1)
          echo "hash=${HASH}" >> $GITHUB_OUTPUT
        else
          echo "hash=default" >> $GITHUB_OUTPUT
        fi

    - name: Cache Zig packages
      uses: actions/cache@v4
      with:
        path: ~/.cache/zig
        key: ${{ runner.os }}-zig-packages-${{ steps.zig-zon-hash.outputs.hash }}
        restore-keys: |
          ${{ runner.os }}-zig-packages-

    - name: Cache Rust dependencies
      uses: Swatinem/rust-cache@v2
      with:
        workspaces: "rust -> target"
        key: ${{ runner.os }}-cargo-${{ inputs.cache-key-suffix }}-${{ steps.cargo-lock-hash.outputs.hash }}

    - name: Fetch Zig dependencies with retry
      shell: bash
      run: |
        max_attempts=5
        attempt=1
        while [ $attempt -le $max_attempts ]; do
          if zig build --fetch; then
            echo "Successfully fetched dependencies on attempt $attempt"
            exit 0
          fi
          echo "Attempt $attempt/$max_attempts failed, retrying in 5 seconds..."
          sleep 5
          attempt=$((attempt + 1))
        done
        echo "Failed to fetch dependencies after $max_attempts attempts"
        exit 1
```

**Usage in jobs:**
```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-build-env
        with:
          rust-toolchain: stable
          rust-components: clippy, rustfmt
          cache-key-suffix: lint
      - name: Check Rust formatting
        run: cargo fmt --manifest-path rust/Cargo.toml --all -- --check
```

**Benefits:**
- Reduces duplication by ~20-30 lines per job
- Easier maintenance (change once, affects all jobs)
- More consistent setup across jobs

---

### 4. Upgrade Cache Actions

**Problem:** Using older cache action versions.

**Location:** Multiple places in `ci.yml` (lines 38, 82, 136, etc.)

**Current:**
```yaml
- uses: actions/cache@v3
```

**Recommended:**
```yaml
- uses: actions/cache@v4
```

**Benefits:**
- Improved cache performance
- Better compression
- Reduced cache operation time by ~10-20%

---

### 5. Share Build Artifacts Between Jobs

**Problem:** The `docker-build` job rebuilds from scratch instead of reusing the binary from `build` job.

**Location:** `.github/workflows/ci.yml:448-449`

**Recommended Change:**

**In build job:**
```yaml
- name: build
  run: zig build all

- name: Upload build artifacts
  uses: actions/upload-artifact@v4
  with:
    name: zeam-binary-${{ matrix.os }}
    path: zig-out/bin/zeam
    retention-days: 1
```

**In docker-build job:**
```yaml
- name: Download build artifacts
  uses: actions/download-artifact@v4
  with:
    name: zeam-binary-${{ matrix.builder == 'ubuntu-latest' && 'ubuntu-latest' || 'ubuntu-22.04-arm' }}
    path: zig-out/bin/

- name: Build Docker image with pre-built binary
  uses: docker/build-push-action@v5
  # ... rest stays the same
```

**Benefits:**
- Eliminates duplicate build time
- Reduces workflow time by 5-10 minutes
- Lower resource usage

---

### 6. Cache LeanSpec Fixtures

**Problem:** Test fixtures are regenerated on every run.

**Location:** `.github/workflows/ci.yml:260-262`

**Current:**
```yaml
- name: Generate LeanSpec fixtures
  working-directory: leanSpec
  run: uv run fill --clean --fork=devnet
```

**Recommended:**
```yaml
- name: Cache LeanSpec fixtures
  uses: actions/cache@v4
  with:
    path: leanSpec/fixtures
    key: leanspec-fixtures-${{ hashFiles('leanSpec/**/*.py', 'leanSpec/**/*.yaml') }}
    restore-keys: |
      leanspec-fixtures-

- name: Generate LeanSpec fixtures
  working-directory: leanSpec
  run: uv run fill --clean --fork=devnet
```

**Benefits:**
- Skips fixture generation when leanSpec code hasn't changed
- Saves 30-60 seconds per test run

---

### 7. Optimize Docker Build Dependencies

**Problem:** `docker-build` depends on all jobs, creating a sequential bottleneck.

**Location:** `.github/workflows/ci.yml:394`

**Current:**
```yaml
docker-build:
  name: docker-build
  needs: [lint, build, test, build-all-provers]
```

**Recommended:**
```yaml
docker-build:
  name: docker-build
  needs: [build]  # Only need build to succeed
```

**Rationale:**
- Docker build just verifies the image builds correctly
- Doesn't need to wait for all tests to complete
- Tests can still fail the overall workflow

**Alternative:** If you want Docker to only build on fully passing CI:
```yaml
docker-build:
  name: docker-build
  needs: [lint, build, test]  # Remove build-all-provers if matrix is fixed
  if: success()
```

**Benefits:**
- Docker build can start sooner
- Reduces total workflow time by 5-15 minutes

---

### 8. Optimize Rust Toolchain Usage

**Problem:** Inconsistent toolchain usage across jobs.

**Location:** Various jobs in `ci.yml`

**Current:**
- `lint` job: uses `stable` with clippy, rustfmt
- `build`, `test`, `docker-build`: use `nightly`
- `risc0.yml`: uses `stable`

**Recommendation:**
- Use `stable` for all jobs unless nightly features are required
- If nightly is required, document why in comments
- Consider using a workflow variable to centralize toolchain version

```yaml
env:
  RUST_TOOLCHAIN: stable  # or nightly if needed

jobs:
  lint:
    steps:
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: ${{ env.RUST_TOOLCHAIN }}
```

---

### 9. Conditional Job Execution

**Problem:** Some jobs always run even when not needed.

**Recommendation:** Add path filters to skip jobs when only docs change:

```yaml
on:
  push:
    branches: [main]
    paths-ignore:
      - '**.md'
      - 'docs/**'
  pull_request:
    paths-ignore:
      - '**.md'
      - 'docs/**'
```

Or use conditional execution:
```yaml
jobs:
  check-changes:
    runs-on: ubuntu-latest
    outputs:
      should-build: ${{ steps.filter.outputs.src }}
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v2
        id: filter
        with:
          filters: |
            src:
              - 'src/**'
              - 'rust/**'
              - 'build.zig'
              - 'Cargo.toml'

  build:
    needs: check-changes
    if: needs.check-changes.outputs.should-build == 'true'
```

---

## Implementation Priority

### High Impact (Implement First)
1. **Parallelize test steps** - Largest time savings
2. **Share build artifacts** - Eliminates duplicate builds
3. **Optimize Docker build dependencies** - Reduces wait time

### Medium Impact
4. **Create composite action** - Improves maintainability
5. **Upgrade cache actions** - Incremental performance improvement
6. **Cache LeanSpec fixtures** - Moderate time savings

### Low Impact (Nice to Have)
7. **Fix matrix configuration** - Code clarity
8. **Optimize Rust toolchain** - Minor consistency improvement
9. **Conditional job execution** - Useful for doc-only changes

## Expected Overall Improvements

Implementing all high and medium priority optimizations could reduce workflow time by:
- **Pull Request runs:** 40-50% faster
- **Main branch runs:** 30-40% faster
- **Resource usage:** 30-35% reduction

## Migration Strategy

1. Create a new branch for workflow optimization
2. Implement changes incrementally, testing each
3. Monitor workflow run times before/after
4. Merge once all changes are validated

## Monitoring

After implementation, track these metrics:
- Total workflow duration
- Individual job durations
- Cache hit rates
- Artifact upload/download times

Use GitHub's workflow insights to compare before/after performance.
