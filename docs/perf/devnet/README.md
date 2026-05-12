# Devnet profile — runbook

A thin workflow for capturing a system-level profile of a running zeam node
in a multi-node devnet. The output answers four questions:

1. Which slot-budget probes (`chain.onBlock`, `fc.aggregate`, …) go over budget?
2. Do the chain-worker queues saturate under real gossip load?
3. Does the libxev IO thread run CPU-heavy work it shouldn't (the `#803` invariant)?
4. Where is the top lock contention?

See `docs/superpowers/specs/2026-05-12-perf-devnet-profile-design.md` for the
design rationale. This README is the user-facing runbook.

## Prerequisites

Recommended host: **GitHub Codespace, 4-core 16 GB Ubuntu 24.04** (8-core/32GB
faster). Local Linux works too. macOS works via `samply` fallback but threading
behaviour differs from production — prefer Codespace.

```bash
# One-time setup on Linux (codespace or other)
sudo apt update
sudo apt install -y linux-tools-generic linux-tools-"$(uname -r)" jq yq

# FlameGraph scripts (Brendan Gregg's) — only needed for the `perf` path
git clone --depth=1 https://github.com/brendangregg/FlameGraph /opt/FlameGraph
echo 'export PATH=/opt/FlameGraph:$PATH' >> ~/.bashrc
export PATH=/opt/FlameGraph:$PATH

# Allow non-root perf sampling. NOTE: codespaces reset this to 4 on every
# new SSH session — run this at the start of every shell that uses perf.
sudo sysctl -w kernel.perf_event_paranoid=1
perf record -F 1 -p $$ -o /tmp/x -- sleep 0.1 && echo "perf OK" && rm /tmp/x
```

For the `samply` fallback (macOS):

```bash
cargo install samply
```

### Codespace-specific gotchas (validated 2026-05-12)

Working from a fresh GitHub Codespace surfaces a handful of friction points
that aren't documented in lean-quickstart's own README:

- **Default Zig is 0.15.1** (Ubuntu 24.04 + GitHub's default Zig). zeam needs
  **0.16.0**. Install manually:

  ```bash
  curl -sSL https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz \
      | tar -xJ -C ~/ && mv ~/zig-linux-x86_64-0.16.0 ~/zig-0.16
  export PATH=$HOME/zig-0.16:$PATH
  zig version   # → 0.16.0
  ```

- **`cargo` may exist but not be on `$PATH`.** Codespace's stock image puts
  `cargo` at `~/.cargo/bin/cargo`, but doesn't source `~/.cargo/env` for
  non-interactive SSH sessions. Add it explicitly:

  ```bash
  export PATH=$HOME/.cargo/bin:$PATH
  cargo --version
  ```

  Without this, `zig build` fails with `error: failed to spawn and capture
  stdio from cargo: FileNotFound`.

- **`kernel.perf_event_paranoid` resets to 4 on every SSH session.** Codespace
  policy. Run `sudo sysctl -w kernel.perf_event_paranoid=1` at the start of
  any shell that will invoke `capture.sh`. (The script's preflight test for
  perf availability catches this and falls back to `samply` if it can't be
  set.)

- **Git remote may be configured to single-branch fetch.** If
  `git fetch origin perf-devnet-profile` fails with "couldn't find remote
  ref", widen the refspec:

  ```bash
  git config --add remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
  git fetch origin
  ```

- **`/workspaces/zeam` might not be zeam.** Some codespaces mount this name
  for a different repo (e.g. lean-quickstart). Check `git remote -v` before
  acting; the actual zeam clone may be at `/workspaces/zeam-build/` or
  similar. The runbook assumes you `cd` to the real zeam working tree before
  every command.

- **Linux smoke-test target needs CPU work.** The `sleep N` target referenced
  in `scripts/devnet-profile/README.md` and earlier macOS smoke tests
  produces zero CPU samples under `perf record --call-graph dwarf` (it's all
  `nanosleep` syscall time). For a Linux smoke test of `capture.sh`, use a
  CPU-busy target like `yes >/dev/null &` instead.

Also required: `git submodule update --init lean-quickstart` from the zeam repo root.

## Step 1: Build target node with slot probes

```bash
zig build -Dslot-probes=true -Doptimize=ReleaseFast
```

The default step builds `zig-out/bin/zeam`. `lean-quickstart` in binary mode
picks it up. All four nodes will run with probes enabled — that's fine, the
`NoopProbe`-vs-`RealProbe` selector is a build-time decision and `RealProbe`
only logs *when over budget* (`std.log.warn`-level), so noise is bounded.

## Step 2: Start the devnet

```bash
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh \
    --node zeam_0,zeam_1,zeam_2,zeam_3 \
    --generateGenesis
```

This starts 4 nodes in foreground (one terminal each via `tmux`/`screen` is
easier; lean-quickstart can also `--popupTerminal` on a desktop Linux).

Wait ~60 seconds for the gossip mesh to stabilize. Check via the metrics
endpoint:

```bash
curl -s http://127.0.0.1:8000/metrics | grep lean_gossip_mesh_peers
```

Each node should have peers in its mesh (value > 0).

## Step 3: Capture the profile

Open another terminal at the repo root:

```bash
scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
    docs/perf/devnet/raw/$(date +%F)/
```

This:
1. Resolves the PID of the zeam_0 process via `pgrep -f`.
2. Pre-flights: ≥ 2 GB free in `docs/perf/devnet/raw/`.
3. Tests `perf record` permissions; falls back to `samply --save-only` if
   `perf_event_paranoid` blocks non-root.
4. Records for 1800 seconds (30 min) at 997 Hz with DWARF call-graph unwind
   (depth 16 KB for the deep Plonky3 stacks).
5. On Linux + FlameGraph scripts available: also generates `flamegraph.svg`.

Expected output dir contents:
- `perf.data` (300-500 MB, gitignored) **OR** `samply.json` (50-200 MB, gitignored)
- `flamegraph.svg` (~1-5 MB, **commit** if interesting — see Step 5)

## Step 4: Extract slot probes

```bash
LOG=lean-quickstart/local-devnet/data/zeam_0/stderr.log
grep "slot_probe over budget" "$LOG" \
    | awk -f scripts/devnet-profile/parse-slot-probes.awk \
    > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
```

The TSV has columns: `line_no`, `probe_name`, `elapsed_ns`, `budget_ns`,
`over_pct`. Header row always present.

Quick check: counts per probe.

```bash
awk -F'\t' 'NR>1 {print $2}' docs/perf/devnet/baselines/*-slot_probe.tsv \
    | sort | uniq -c | sort -rn
```

If `chain.onBlock` shows up frequently → block processing is over budget;
if `fc.aggregate` shows up → aggregation is over budget (likely, given
the bench finding of ~411ms gossip-only / ~3.9s recursive vs 800ms budget).

## Step 5: Interpret + write a summary

1. Open `flamegraph.svg` in a browser (or upload `samply.json` to
   <https://profiler.firefox.com/>).
2. Look for:
   - **Forbidden symbols on the libxev TID**: `apply_raw_block`,
     `apply_transition`, `verifySsz`, `aggregate`, `hashTreeRoot`.
     (Identify the libxev/event-loop thread from the profiler — `samply`
     shows thread names in the UI; for `perf`, use
     `perf report -i perf.data --sort=pid,comm,dso,sym` to find the
     event-loop thread by name.)
   - **Top lock-related callers**: `pthread_mutex_lock`, `__psynch_cvwait`,
     `_pthread_cond_wait` — and what functions called them.
   - **Unexpected hot paths**: anything not in the bench-aggregation profile.
3. Copy `docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md` to
   `docs/perf/devnet/baselines/$(date +%F)-$(git rev-parse --short HEAD)-summary.md`
   and fill in. Each section has 1-2 quick-analysis recipes inline.
4. Commit the summary + `slot_probe.tsv` + (optionally) `flamegraph.svg`:

```bash
SHA=$(git rev-parse --short HEAD)
DATE=$(date +%F)
cp docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md \
   docs/perf/devnet/baselines/${DATE}-${SHA}-summary.md
# (edit the new file)

# Move artifacts to baselines
cp docs/perf/devnet/raw/${DATE}/flamegraph.svg \
   docs/perf/devnet/baselines/${DATE}-${SHA}-flamegraph.svg
# slot_probe.tsv is already in baselines/ from Step 4 — rename for consistency:
mv docs/perf/devnet/baselines/${DATE}-slot_probe.tsv \
   docs/perf/devnet/baselines/${DATE}-${SHA}-slot_probe.tsv

git add docs/perf/devnet/baselines/${DATE}-${SHA}-*.{md,tsv,svg}
git commit -m "docs/perf/devnet: baseline ${DATE} @ ${SHA}"
```

## Limitations

- Single-target profile: we only attach to `zeam_0`. Cross-node effects
  show up indirectly (gossip behaviour, fork frequency).
- No auto-correlation between probe events and `perf` samples — read both
  side-by-side. If patterns emerge across 3+ baselines, write a
  `scripts/devnet-profile/analyze.py` follow-up.
- Codespace OOM risk on 4 nodes + perf at 4-core/16GB. If you see `oom-killer`
  in `dmesg`, drop to 2 nodes via `--node zeam_0,zeam_1` and document
  "OOM-degraded run" in the summary headline.

## Follow-ups (out of scope for this branch)

- Automated `run.sh` orchestrator (spin-up + warmup + capture + teardown)
- `analyze.py` report generator (auto-fill the four sections of the summary)
- `.devcontainer/` config for one-click Codespace setup
- Prometheus scrape loop running during capture
- macOS-native multi-node devnet support
