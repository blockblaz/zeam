# Perf Devnet Profile — Design

Date: 2026-05-12
Branch: `perf-devnet-profile`
Base: `perf-profile-bench` (depends on the `slot_probe` infrastructure shipped there)
Status: **DESIGN — pending implementation**

## Why this branch

The `perf-profile-bench` work (PR #861) shipped micro-benchmarks for four CPU-critical paths and showed that aggregation cost is **78% Poseidon1 inside Plonky3** — algorithmically locked, no zeam-side fix possible. What micro-benchmarks **cannot** show:

- Whether the libxev IO thread runs CPU-heavy work it shouldn't (`#803` slice-(a) invariant)
- Whether the chain-worker queue saturates under real gossip load
- Lock contention across the per-resource locks added in `#803`
- Real-load probe-budget violations (`chain.onBlock` / `fc.aggregate` / etc.)

These questions need a **running multi-node devnet under real load**, profiled at the system level. This branch ships the **thin tooling** to do that — not a fully automated harness, but enough that any contributor can reproduce the capture in ~20 minutes of human time after a one-time codespace setup.

## Goal

Deliver:

1. A thin **capture script** that attaches `perf` (or `samply` fallback) to a running zeam process and records 30 minutes of profile + flamegraph.
2. An **awk parser** for `slot_probe over budget` log lines → structured TSV.
3. A **runbook** documenting the manual-but-quick workflow: start lean-quickstart by hand, run the capture script, extract probes, write a 1-page summary.
4. A **`docs/perf/devnet/baselines/`** directory where the first hand-written summary commits the initial findings.
5. **Optional bonus**: add `lean_chain_worker_queue_depth` to `pkgs/metrics/` if it's not already present — without this metric we cannot answer the "queue saturation?" question from prometheus alone.

## Non-goals (explicit follow-ups, not built here)

- A `run.sh` orchestrator that manages the full lifecycle (spin-up → warmup → capture → teardown). Manual `lean-quickstart` is fine; its own docs are good.
- A Codespace `.devcontainer/` config. README documents prerequisites; setup is two `apt install` lines.
- A Python `analyze.py` report generator. First runs are eyeballed; if patterns emerge across runs, automation is a follow-up PR.
- A Prometheus scraper loop. If a run needs metrics, the runbook documents `curl localhost:8000/metrics` ad-hoc into a file.
- matplotlib charts embedded in baselines. Screenshots from Grafana / browser-rendered SVG are fine.
- macOS support. `samply` works on Mac but `perf` is Linux-only and is the production target. macOS is documented as "use codespace instead."

These are documented here so reviewers can see where scope was cut. None are gated by anything in this design.

## Approach

**Manual lean-quickstart + thin capture script.**

User starts `lean-quickstart` manually following its own README. Once the devnet is in steady state, user invokes `scripts/devnet-profile/capture.sh` to attach `perf` to the target node (`zeam_0`) for 30 minutes. The script produces three artifacts: `perf.data` (gitignored), `flamegraph.svg` (small, committable), and the kernel of slot-probe analysis via the awk script. User reads flamegraph + TSV by eye and writes a 1-page summary into `docs/perf/devnet/baselines/`.

Why this over the rejected approaches:

- **vs. full orchestrator**: the orchestrator's value is "next person re-runs without thinking." Current goal is "ship something useful fast." Different optimization target. Orchestration can be a follow-up PR once we have ≥3 baseline runs and know what patterns to automate.
- **vs. pure-Zig in-process devnet**: a single Zig process simulating multiple nodes via libp2p loopback would skip Docker but doesn't catch real cross-process gossip dynamics; the manual lean-quickstart path gets us the same Linux-host fidelity with a tool that already works.
- **vs. macOS-only**: the threading model and lock implementations differ between Darwin and Linux. The deployment target is Linux. Codespaces gives us Linux for free.

## Repository layout

```
scripts/devnet-profile/
  README.md                            # short: usage examples + arg reference
  capture.sh                           # main capture script (~50 lines)
  parse-slot-probes.awk                # log line → TSV converter (~20 lines)
docs/perf/devnet/
  README.md                            # the full runbook + how-to-interpret
  baselines/
    .gitkeep                           # empty; populated by hand after first run
    <YYYY-MM-DD>-<sha>-summary.md      # hand-written; committed per run
    <YYYY-MM-DD>-<sha>-flamegraph.svg  # captured artifact; committed if interesting
    <YYYY-MM-DD>-<sha>-slot_probe.tsv  # captured artifact; committed
  raw/
    .gitignore                         # ignore *.data, large logs, prometheus dumps
pkgs/metrics/src/lib.zig               # ADD lean_chain_worker_queue_depth (if absent)
pkgs/node/src/chain_worker.zig         # ADD recorder call for the new metric
```

## Component specs

### A. `scripts/devnet-profile/capture.sh`

```bash
#!/usr/bin/env bash
# Capture a perf profile of a running zeam node.
#
# Usage: capture.sh <process-pattern> <duration-sec> [out-dir]
# Example: capture.sh "zeam.*--node zeam_0" 1800 docs/perf/devnet/raw/$(date +%F)/
set -euo pipefail

PATTERN="${1:?usage: capture.sh <process-pattern> <duration> [out-dir]}"
DURATION="${2:?usage: capture.sh <process-pattern> <duration> [out-dir]}"
OUT_DIR="${3:-docs/perf/devnet/raw/$(date +%F-%H%M%S)}"
mkdir -p "$OUT_DIR"

# Resolve PID
PID=$(pgrep -f "$PATTERN" | head -1)
if [[ -z "$PID" ]]; then
    echo "no process matching: $PATTERN" >&2
    exit 1
fi
echo "target pid: $PID"

# Choose sampler
if perf record -F 1 -p $$ -o /tmp/perf-probe.data -- sleep 0.1 2>/dev/null; then
    SAMPLER=perf
    rm -f /tmp/perf-probe.data
elif command -v samply >/dev/null; then
    SAMPLER=samply
    echo "perf_event_paranoid blocks perf; falling back to samply" >&2
else
    echo "no working sampler (perf denied, samply not installed)" >&2
    exit 1
fi

# Disk-space pre-check (perf.data can be 300-500 MB)
free_mb=$(df -BM "$OUT_DIR" | awk 'NR==2 {gsub("M",""); print $4}')
if [[ "$free_mb" -lt 2000 ]]; then
    echo "less than 2 GB free in $OUT_DIR — aborting" >&2
    exit 1
fi

# Record
case "$SAMPLER" in
    perf)
        perf record -F 997 --call-graph dwarf,16384 -p "$PID" \
            -o "$OUT_DIR/perf.data" -- sleep "$DURATION"
        perf script -i "$OUT_DIR/perf.data" \
            | stackcollapse-perf.pl \
            | flamegraph.pl > "$OUT_DIR/flamegraph.svg"
        ;;
    samply)
        samply record --save-only --pid "$PID" \
            -o "$OUT_DIR/samply.json" -- sleep "$DURATION"
        echo "samply.json written; open at https://profiler.firefox.com/ to view"
        ;;
esac

echo "artifacts written to: $OUT_DIR"
ls -lh "$OUT_DIR/"
```

Implementation notes:
- `--call-graph dwarf,16384` for deep Plonky3 stacks (default 8 KB truncates).
- `-F 997` avoids harmonics with common 1000-Hz timer events.
- Sampler detection happens once at script start; the same sampler is used for the real recording.
- Disk-space pre-check is cheap insurance; 30 min of `perf.data` at 997 Hz can easily hit 500 MB.

### B. `scripts/devnet-profile/parse-slot-probes.awk`

Input log lines (from `slot_probe.zig`'s `RealProbe.end()`):
```
... slot_probe over budget: chain.onBlock took 312000000ns (budget 800000000ns)
```

Output TSV columns: `epoch_ms`, `probe_name`, `elapsed_ns`, `budget_ns`, `over_pct`.

```awk
#!/usr/bin/awk -f
# parse-slot-probes.awk — convert zeam slot_probe warnings to TSV.
#
# Usage: grep "slot_probe over budget" zeam_0.log | awk -f parse-slot-probes.awk > slot_probe.tsv
#
# Input lines look like:
#   2026-05-12T10:20:30.123Z WARN  ... slot_probe over budget: chain.onBlock took 312000000ns (budget 800000000ns)
# Output: epoch_ms<TAB>probe_name<TAB>elapsed_ns<TAB>budget_ns<TAB>over_pct

BEGIN { OFS="\t"; print "epoch_ms","probe_name","elapsed_ns","budget_ns","over_pct" }

/slot_probe over budget:/ {
    # Extract timestamp (assume ISO 8601 in first field)
    ts = $1
    cmd = "date -u -d \"" ts "\" +%s%3N 2>/dev/null || gdate -u -d \"" ts "\" +%s%3N 2>/dev/null"
    cmd | getline epoch_ms
    close(cmd)

    # Extract probe name (between "over budget:" and "took")
    match($0, /over budget: [^ ]+/)
    probe = substr($0, RSTART+13, RLENGTH-13)

    # Extract numbers
    match($0, /took [0-9]+ns/);    elapsed = substr($0, RSTART+5, RLENGTH-7)
    match($0, /budget [0-9]+ns/);  budget  = substr($0, RSTART+7, RLENGTH-9)

    over_pct = (budget > 0) ? int(100 * (elapsed - budget) / budget) : 0
    print epoch_ms, probe, elapsed, budget, over_pct
}
```

Implementation notes:
- Uses GNU `date -d` (or `gdate` on macOS) for ISO 8601 parsing. Codespace ubuntu has GNU date.
- One-process-per-line `date` call is slow for million-line logs; in practice we expect ≤ few thousand over-budget events per 30 min run, so acceptable. If it becomes a problem, swap to a tiny Python parser — but that's not where the bottleneck will be.
- TSV header written once at BEGIN; downstream tooling (`sort`, `awk`, `duckdb`) recognises the columns by name.

### C. `docs/perf/devnet/README.md` — the runbook

Sections:
1. **Prerequisites** — Linux box (Codespace 4-core/16GB recommended), `linux-tools-generic`, FlameGraph scripts on PATH, `git submodule update --init lean-quickstart`, `yq` and Docker (for lean-quickstart genesis).
2. **One-time setup** — `apt install linux-tools-generic`; clone FlameGraph; verify `perf record -F 1 -p $$ -- sleep 0.1` works (if denied, sysctl tweak documented).
3. **Build target node** — `zig build -Dslot-probes=true -Doptimize=ReleaseFast` (the default step builds `zig-out/bin/zeam`; lean-quickstart's binary mode picks it up). Note that **all four nodes** will run the slot-probe-enabled binary, which is fine — `NoopProbe` is zero-cost when disabled, and `RealProbe` only logs when over budget. We only `perf`-attach to `zeam_0`, so probe data from the other three is harmless noise on disk.
4. **Start devnet** — verbatim command pointing at lean-quickstart:
   ```bash
   cd lean-quickstart
   NETWORK_DIR=local-devnet ./spin-node.sh \
       --node zeam_0,zeam_1,zeam_2,zeam_3 \
       --generateGenesis
   ```
   Wait ~60 seconds for gossip mesh to stabilize.
5. **Capture profile**:
   ```bash
   scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
       docs/perf/devnet/raw/$(date +%F)/
   ```
6. **Extract slot probes** — lean-quickstart writes each node's log to `lean-quickstart/<NETWORK_DIR>/data/<node>/{stdout,stderr}.log` (per `spin-node.sh:877` `itemDataDir`):
   ```bash
   LOG=lean-quickstart/local-devnet/data/zeam_0/stderr.log
   grep "slot_probe over budget" "$LOG" \
       | awk -f scripts/devnet-profile/parse-slot-probes.awk \
       > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
   ```
   (Probe warnings are emitted via `std.log.warn`, which lands in stderr.)
7. **Eyeball flamegraph** — open `flamegraph.svg` in browser. Look for: (a) `apply_raw_block`/`verifySsz`/`aggregate` on the libxev main thread (IO-invariant violation); (b) top lock-related symbols (`pthread_mutex_lock`, `__psynch_cvwait`) and their callers; (c) any unexpected hot path.
8. **Write summary** — copy the template at the end of the README into `docs/perf/devnet/baselines/<date>-<sha>-summary.md` and fill in. Template covers the four questions (probes / queue / IO invariant / locks) with prose + tables.
9. **Commit** — `flamegraph.svg`, `slot_probe.tsv`, `summary.md` to `docs/perf/devnet/baselines/`. Do NOT commit `perf.data` or raw logs — `raw/.gitignore` covers them.

### D. `lean_chain_queue_depth` metric — verified already shipped

Initial design assumed we might need to add this metric. **Verified during plan-writing**: `pkgs/metrics/src/lib.zig:177` already exports `lean_chain_queue_depth: LeanChainQueueDepthGauge` with `queue=block|attestation` labels, and `pkgs/node/src/chain_worker.zig:567,584` (`sendBlock`/`sendAttestation`) already call `.set(...)` on each enqueue. Also present: `lean_chain_queue_dropped_total` (queue-full counter) and `lean_chain_worker_loop_iters_total` (watchdog liveness). Section D in this design is therefore a **no-op** — the implementation plan skips it.

### E. Codespace prerequisites (documented, not automated)

The README lists:
```bash
sudo apt install -y linux-tools-generic linux-tools-$(uname -r)
# FlameGraph: clone + add to PATH
git clone --depth=1 https://github.com/brendangregg/FlameGraph /opt/FlameGraph
export PATH=/opt/FlameGraph:$PATH
# yq + docker (for lean-quickstart genesis)
sudo apt install -y yq jq
# verify perf works without elevation:
perf record -F 1 -p $$ -o /tmp/x -- sleep 0.1 && echo OK
# if denied:
sudo sysctl -w kernel.perf_event_paranoid=1
```

Total one-time setup: ~5 minutes. After that, each capture run is one `spin-node.sh` + one `capture.sh` command.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `perf_event_paranoid` denies non-root perf in codespace | `capture.sh` tests at start; falls back to `samply --save-only`. README documents the sysctl tweak. |
| Codespace OOM (4 nodes + perf + analysis on 4-core/16GB) | README recommends 4-core/16GB as minimum; documents `--nodes 2` fallback. Manual run = user sees the OOM directly via `dmesg`. |
| Target node crashes mid-capture | `perf record` exits when `-p $PID` dies; partial `perf.data` is still useful; user notes "INCOMPLETE" in summary. |
| 30 min `perf.data` blows codespace disk | `capture.sh` pre-checks ≥ 2 GB free in out dir; bails early if not. |
| lean-quickstart genesis generation fails | Surfaces as `spin-node.sh` exit code; user sees stderr directly. Out of this design's scope to handle. |
| `parse-slot-probes.awk`'s `date -d` parsing fails on unexpected timestamp format | Header gets written but rows missing `epoch_ms` — easy to spot in output. If recurring, swap to a tiny Python parser. |
| Codespace user wants different node count or duration | All as `capture.sh` args; lean-quickstart's `--node` flag controls node set. |

## Implementation order (preview)

1. `scripts/devnet-profile/capture.sh` + executable bit
2. `scripts/devnet-profile/parse-slot-probes.awk`
3. `scripts/devnet-profile/README.md` (very short — points at docs/perf/devnet/README.md)
4. `docs/perf/devnet/README.md` (the runbook)
5. `docs/perf/devnet/raw/.gitignore`
6. `docs/perf/devnet/baselines/.gitkeep`
7. (optional) `lean_chain_worker_queue_depth` metric + recorder call
8. Smoke test: build, run on a 1-min `sleep` target locally just to verify the script wires up (don't actually run a 30-min devnet in this implementation phase — that's the first baseline run, done after merge)

## Open questions (none blocking)

- Should we ship a tiny Python `analyze.py` for v1, or keep the runbook fully manual? **Design choice: fully manual.** First run informs whether automation is worth it. If after 3 runs the same hand-calculation appears, we automate then.
- Codespace machine type — recommend 4-core/16GB or default? **Design choice: 4-core/16GB recommended, but document the default works for 2-node runs.**
- Should the lean_chain_worker_queue_depth metric land in this branch or be a separate PR? **Design choice: in this branch, IF absent.** Adding it here scopes the "queue saturation?" answerability properly; otherwise we can't answer one of the four questions.
