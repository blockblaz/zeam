# AGENTS

## Guidelines

- **Keep changes minimal and focused.** Only modify code directly related to the task at hand. Do not refactor unrelated code, rename existing variables or functions for style, or bundle unrelated fixes into the same commit or PR.
- **Do not add, remove, or update dependencies** unless the task explicitly requires it.

## Pre-Commit Checklist

Before every commit, run **all** of the following checks and ensure they pass:

### 1. Formatting

Before committing, always run `cargo fmt` and `cargo clippy` in the rust libraries:

```sh
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --workspace -- -D warnings
```

Then run `zig fmt`:

```sh
zig fmt --check .
```

This runs additional style checks. Fix any issues before committing.

### 3. Tests

```sh
zig build test --summary all
zig build simtest --summary all
```

## Commit Message Format

Commit messages must be prefixed with the name of the modules they modify, followed by a short lowercase description:

```
<package(s)>: description
```

Examples:
- `risc0: implement prover`
- `libp2p: fix swarm re-entrancy issue`

Use comma-separated package names when multiple areas are affected. Keep the description concise.

Do not use the braindead, non-descriptive style `feat`, `chore`, etc... as it is redundant with the github labelling system.
