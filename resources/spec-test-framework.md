## Spectest framework

### Overview
The Zig spectest harness consumes fixtures directly from the bundled
`leanSpec` submodule rather than duplicating JSON blobs inside this repository.
Generated Zig tests wrap the fixtures and invoke the appropriate runner module
to reconstruct Zeam state, execute the scenario, and check the expected
outcome.

### Regenerating and running tests
- `zig build spectest:generate` – rebuilds the generated test files only.
- `zig build spectest` – regenerates the fixtures and runs the full spectest suite.
- `zig build spectest:run` – executes the suite using whatever files are already generated.

All commands run from the repository root and assume fixtures live at
`leanSpec/fixtures`. Pass `--vectors-root <path>` after `--` when generating if
you want to point at an alternate directory.

To skip fixtures that are expected to fail, set the environment variable before
invocation:

```bash
ZEAM_SPECTEST_SKIP_EXPECTED_ERRORS=true zig build spectest:run
```

The same flag works with `spectest` or `spectest:generate`. As a shortcut you
can pass `--skip-expected-error-fixtures` after `--` when invoking the build
step; the build script converts that into the environment toggle.

### Fixture layout and generated tests
`pkgs/spectest/src/generated/index.zig` (rewritten by the generator) hosts the
per-fixture Zig tests. Each generated test resolves the fixture directory,
prints a helpful diagnostic, and gracefully skips when the LeanSpec checkout is
missing, allowing the rest of the Zeam tree to build without external
dependencies.

### Runner modules
The harness ships two runners: `pkgs/spectest/src/runner/state_transition_runner.zig`
and `pkgs/spectest/src/runner/fork_choice_runner.zig`. Each exports a `TestCase` type
that knows how to parse its portion of the LeanSpec JSON tree, rebuild Zeam
state, execute the transition, and validate post-conditions. The generator
instantiates these runners based on fixture metadata (kind, fork, handler).

`pkgs/spectest/src/lib.zig` re-exports the runners and registers a single Zig
test that walks the default consensus fixture tree, ensuring every generated
test is referenced. Missing fixtures trigger a skip instead of a failure so the
suite behaves well on machines without the submodule.

### Adding a New Runner

Follow the existing `state_transition_runner.zig` and `fork_choice_runner.zig`
modules as templates. A runner is responsible for turning a leanSpec JSON
fixture into Zeam state, executing the scenario, and checking the outcome. To
wire up an additional runner:

1. **Create the runner module** in `pkgs/spectest/src/`. Export a
	`pub const name`, enumerate the supported handlers, and implement
	`baseRelRoot`, `includeFixtureFile`, and the generic `TestCase(Fork, rel_path)`
	type. The generated harness instantiates `TestCase(Fork, rel_path)` and calls
	its `execute` method, so those entry points must be present. Keep the public
	surface area identical to the existing runners to avoid generator changes.
2. **Register the fixture kind** in `pkgs/spectest/src/fixture_kind.zig` by
	adding a new enum variant, returning the module name from `runnerModule`, and
	pointing `handlerSubdir` at the leanSpec directory that hosts your fixtures.
	Make sure to extend the `all` constant so the generator discovers the new
	kind.
3. **Regenerate fixtures** by running `zig build spectest:generate` to ensure the
	new kind produces tests. Point the generator at a fixture tree that contains
	the new JSON files (for example, with `--vectors-root` if they live outside
	`leanSpec/fixtures`).
4. **Execute the suite** with `zig build spectest:run` (or `zig build test` once
	the new runner is part of the generated index) to verify the fixtures pass
	and to catch missing skip logic early.

Take advantage of `std.testing.refAllDeclsRecursive` in dedicated unit tests for
the runner module itself—building small, deterministic fixtures helps exercise
parsing and validation logic without regenerating the full spectest tree during
iteration.
