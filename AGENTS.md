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

## Ship workflow

When implementation work is **complete** (fixes, features, dependency bumps), **commit and push** without waiting to be asked. Skip this for question-only, review-only, or explicitly read-only tasks.

1. Run the pre-commit checklist above.
2. Commit each affected repo with the message format above.
3. Push to the tracked remote branch.
4. **zig-libp2p → zeam:** commit and push `zig-libp2p` first; tag (`v0.1.N`) when zeam needs the release; `zig fetch` the new ref to get the `build.zig.zon` hash; then commit and push zeam.

Do not commit secrets, local devnet artifacts, or unrelated dirty files. Do not post GitHub comments unless explicitly asked.
