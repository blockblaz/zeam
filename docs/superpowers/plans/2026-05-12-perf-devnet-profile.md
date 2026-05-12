# Perf Devnet Profile — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a thin capture script + parser + runbook so any contributor can take a `perf`-based system-level profile of a running zeam node in ~20 minutes of human time, with structured slot-probe + flamegraph artifacts that go into `docs/perf/devnet/baselines/`.

**Architecture:** Manual `lean-quickstart` for devnet startup; `scripts/devnet-profile/capture.sh` attaches `perf record --pid` (with `samply` fallback) for a configurable duration and writes `flamegraph.svg` + `perf.data`; `scripts/devnet-profile/parse-slot-probes.awk` converts the `RealProbe.end()` warnings (already wired into `chain.zig`/`forkchoice.zig` from PR #861) into a 5-column TSV; the runbook tells the user how to chain them and write a 1-page summary. No metric additions needed — `lean_chain_queue_depth` and friends already shipped in `pkgs/metrics/src/lib.zig`.

**Tech Stack:** bash, awk (BSD- and gawk-compatible), Linux `perf` + Brendan Gregg's FlameGraph scripts, `samply` as fallback. zeam build with `-Dslot-probes=true -Doptimize=ReleaseFast`. lean-quickstart already-existing submodule. Codespace as the recommended host (default Ubuntu 24.04 runner has all the deps via `apt install linux-tools-generic`).

**Spec:** `docs/superpowers/specs/2026-05-12-perf-devnet-profile-design.md`

**Worktree:** Already on branch `perf-devnet-profile` at HEAD `f102e812` (or later). Branch is based on `perf-profile-bench` which carries the `slot_probe` module — do not re-implement that here.

---

## File Map

| Path | Action | Purpose |
|---|---|---|
| `scripts/devnet-profile/capture.sh` | Create | Resolve PID, choose sampler, record profile, generate flamegraph |
| `scripts/devnet-profile/parse-slot-probes.awk` | Create | Convert `slot_probe over budget` log lines to TSV |
| `scripts/devnet-profile/README.md` | Create | One-pager: usage examples + arg reference + cross-link to runbook |
| `docs/perf/devnet/README.md` | Create | The runbook: prereqs, setup, run, interpret, write summary |
| `docs/perf/devnet/raw/.gitignore` | Create | Ignore `*.data`, `*.json`, large logs |
| `docs/perf/devnet/baselines/.gitkeep` | Create | Empty placeholder so directory tracked |
| `docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md` | Create | Template a contributor copies into `<date>-<sha>-summary.md` after running |

---

## Task 1: Scaffold `scripts/devnet-profile/` directory

**Files:**
- Create: `scripts/devnet-profile/.keep` (placeholder so the dir tracks before we add real files)

- [ ] **Step 1: Create the directory and placeholder**

```bash
mkdir -p scripts/devnet-profile
touch scripts/devnet-profile/.keep
```

- [ ] **Step 2: Verify and commit**

```bash
ls -la scripts/devnet-profile/
git add scripts/devnet-profile/.keep
git commit -m "scripts/devnet-profile: scaffold directory"
```

Expected `ls` output: directory exists with one `.keep` file.

The `.keep` file is removed in Task 2 when `capture.sh` lands.

---

## Task 2: `parse-slot-probes.awk` — log line → TSV (TDD)

**Files:**
- Create: `scripts/devnet-profile/parse-slot-probes.awk`
- Create: `scripts/devnet-profile/test/sample-log.txt` (test fixture)
- Create: `scripts/devnet-profile/test/expected-slot-probe.tsv` (expected output)

This task is fully test-driven because awk is easy to test offline and the parser is the load-bearing component.

- [ ] **Step 1: Write the test fixture (input log lines)**

Create `scripts/devnet-profile/test/sample-log.txt`:

```
May-12 10:20:30.001 [INFO] (default) some unrelated info line
May-12 10:20:30.123 [WARN] (default) slot_probe over budget: chain.onBlock took 950000000ns (budget 800000000ns)
May-12 10:20:34.567 [WARN] (default) slot_probe over budget: fc.aggregate took 1100000000ns (budget 800000000ns)
May-12 10:20:35.099 [WARN] (default) slot_probe over budget: fc.acceptNewAttestations took 410000000ns (budget 400000000ns)
May-12 10:20:36.000 [DEBUG] (default) noise that should be skipped
May-12 10:20:36.500 [WARN] (default) slot_probe over budget: chain.onGossip took 800000001ns (budget 800000000ns)
```

- [ ] **Step 2: Write the expected output**

Create `scripts/devnet-profile/test/expected-slot-probe.tsv`:

```
timestamp	probe_name	elapsed_ns	budget_ns	over_pct
May-12 10:20:30.123	chain.onBlock	950000000	800000000	18
May-12 10:20:34.567	fc.aggregate	1100000000	800000000	37
May-12 10:20:35.099	fc.acceptNewAttestations	410000000	400000000	2
May-12 10:20:36.500	chain.onGossip	800000001	800000000	0
```

Notes on expected values:
- `chain.onBlock`: `(950-800)/800 = 0.1875` → `int(18.75) = 18`
- `fc.aggregate`: `(1100-800)/800 = 0.375` → `int(37.5) = 37`
- `fc.acceptNewAttestations`: `(410-400)/400 = 0.025` → `int(2.5) = 2`
- `chain.onGossip`: `(800000001-800000000)/800000000 ≈ 0.000000125%` → `int(0) = 0`

Two non-slot_probe lines (info, debug) are filtered out. Only `WARN slot_probe over budget` rows emit output.

The fields are TAB-separated. Header row is always present.

- [ ] **Step 3: Run the (not-yet-existing) script — verify it fails clearly**

```bash
awk -f scripts/devnet-profile/parse-slot-probes.awk \
    < scripts/devnet-profile/test/sample-log.txt
```

Expected: error like `awk: can't open file scripts/devnet-profile/parse-slot-probes.awk`.

- [ ] **Step 4: Implement `parse-slot-probes.awk`**

Create `scripts/devnet-profile/parse-slot-probes.awk`:

```awk
#!/usr/bin/awk -f
#
# parse-slot-probes.awk — convert zeam slot_probe warning lines to TSV.
#
# Usage:
#   grep "slot_probe over budget" zeam_0.log \
#       | awk -f scripts/devnet-profile/parse-slot-probes.awk > slot_probe.tsv
#
# Input format (from pkgs/utils/src/slot_probe.zig RealProbe.end):
#   May-12 10:20:30.123 [WARN] (default) slot_probe over budget: chain.onBlock took 950000000ns (budget 800000000ns)
#
# Output columns (TAB separated, header always present):
#   timestamp  probe_name  elapsed_ns  budget_ns  over_pct
#
# Portable across BSD awk (macOS) and gawk (Linux/codespace).
BEGIN {
    OFS = "\t"
    print "timestamp", "probe_name", "elapsed_ns", "budget_ns", "over_pct"
}

/slot_probe over budget:/ {
    ts = $1 " " $2

    if (match($0, /over budget: [^ ]+/)) {
        probe = substr($0, RSTART + 13, RLENGTH - 13)
    } else { next }

    if (match($0, /took [0-9]+ns/)) {
        elapsed = substr($0, RSTART + 5, RLENGTH - 7) + 0
    } else { next }

    if (match($0, /budget [0-9]+ns/)) {
        budget = substr($0, RSTART + 7, RLENGTH - 9) + 0
    } else { next }

    over_pct = (budget > 0) ? int(100 * (elapsed - budget) / budget) : 0
    print ts, probe, elapsed, budget, over_pct
}
```

- [ ] **Step 5: Run the script + diff against expected output**

```bash
awk -f scripts/devnet-profile/parse-slot-probes.awk \
    < scripts/devnet-profile/test/sample-log.txt \
    > /tmp/actual-slot-probe.tsv
diff scripts/devnet-profile/test/expected-slot-probe.tsv /tmp/actual-slot-probe.tsv
```

Expected: `diff` exits 0 with no output.

If `diff` shows differences, inspect both files (`cat /tmp/actual-slot-probe.tsv` vs the expected) and fix the awk script.

- [ ] **Step 6: Remove the `.keep` placeholder from Task 1**

```bash
rm scripts/devnet-profile/.keep
```

- [ ] **Step 7: Commit**

```bash
git add scripts/devnet-profile/parse-slot-probes.awk scripts/devnet-profile/test/
git rm scripts/devnet-profile/.keep
git commit -m "scripts/devnet-profile: add slot-probe log → TSV awk parser + tests"
```

---

## Task 3: `capture.sh` — main capture script

**Files:**
- Create: `scripts/devnet-profile/capture.sh` (executable)

This task is harder to TDD (it spawns `perf`/`samply` against a real PID). We smoke-test by running against a short `sleep` target via `samply` (which works on macOS, the implementer's likely environment).

- [ ] **Step 1: Write `capture.sh`**

Create `scripts/devnet-profile/capture.sh`:

```bash
#!/usr/bin/env bash
#
# capture.sh — attach a sampling profiler to a running zeam node and
# record for $DURATION seconds, then emit a flamegraph (perf path).
#
# Usage: capture.sh <process-pattern> <duration-sec> [out-dir]
#
# Example:
#   scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
#       docs/perf/devnet/raw/$(date +%F)/
#
# Behavior:
#   - Tries Linux `perf` first; falls back to `samply --save-only`
#     if `perf_event_paranoid` blocks it.
#   - Pre-flight: requires the target PID to exist and at least
#     2 GB free disk in the output directory.
#   - On `perf` path, generates `flamegraph.svg` via Brendan Gregg's
#     stackcollapse-perf.pl / flamegraph.pl (must be on PATH).
set -euo pipefail

usage() {
    echo "Usage: $0 <process-pattern> <duration-sec> [out-dir]" >&2
    echo "  Example: $0 'zeam.*zeam_0' 1800 docs/perf/devnet/raw/\$(date +%F)/" >&2
    exit 1
}

[[ $# -ge 2 ]] || usage
PATTERN="$1"
DURATION="$2"
OUT_DIR="${3:-docs/perf/devnet/raw/$(date +%F-%H%M%S)}"

# 1. Resolve target PID
PID=$(pgrep -f "$PATTERN" | head -1 || true)
if [[ -z "$PID" ]]; then
    echo "error: no process matches pattern: $PATTERN" >&2
    exit 1
fi
echo "target pid: $PID ($(ps -p "$PID" -o comm= 2>/dev/null || echo unknown))"

mkdir -p "$OUT_DIR"

# 2. Disk-space pre-check (perf.data can be 300-500 MB for 30 min @ 997 Hz)
free_mb=$(df -BM "$OUT_DIR" 2>/dev/null | awk 'NR==2 {gsub("M",""); print $4}')
if [[ -z "$free_mb" ]]; then
    # macOS df doesn't support -BM; fall back to -m
    free_mb=$(df -m "$OUT_DIR" | awk 'NR==2 {print $4}')
fi
if [[ "$free_mb" -lt 2000 ]]; then
    echo "error: less than 2 GB free in $OUT_DIR (have ${free_mb} MB)" >&2
    exit 1
fi

# 3. Pick sampler: perf if it works, else samply
SAMPLER=""
if perf record -F 1 -p $$ -o /tmp/perf-probe-$$.data -- sleep 0.1 >/dev/null 2>&1; then
    SAMPLER=perf
    rm -f /tmp/perf-probe-$$.data
elif command -v samply >/dev/null 2>&1; then
    SAMPLER=samply
    echo "perf unavailable or perf_event_paranoid blocks non-root use; using samply"
fi
if [[ -z "$SAMPLER" ]]; then
    echo "error: no working sampler (perf failed, samply not installed)" >&2
    echo "  Linux: sudo apt install linux-tools-generic && sudo sysctl -w kernel.perf_event_paranoid=1" >&2
    echo "  macOS: cargo install samply" >&2
    exit 1
fi
echo "sampler: $SAMPLER, duration: ${DURATION}s, output: $OUT_DIR"

# 4. Record
case "$SAMPLER" in
    perf)
        perf record -F 997 --call-graph dwarf,16384 -p "$PID" \
            -o "$OUT_DIR/perf.data" -- sleep "$DURATION"
        echo "perf.data: $(du -h "$OUT_DIR/perf.data" | cut -f1)"

        if command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null; then
            echo "generating flamegraph..."
            perf script -i "$OUT_DIR/perf.data" \
                | stackcollapse-perf.pl \
                | flamegraph.pl > "$OUT_DIR/flamegraph.svg"
            echo "flamegraph.svg: $(du -h "$OUT_DIR/flamegraph.svg" | cut -f1)"
        else
            echo "warning: FlameGraph scripts not on PATH; perf.data is saved but flamegraph.svg not generated"
            echo "  install: git clone https://github.com/brendangregg/FlameGraph && export PATH=\$PWD/FlameGraph:\$PATH"
        fi
        ;;
    samply)
        samply record --save-only --pid "$PID" \
            -o "$OUT_DIR/samply.json" -- sleep "$DURATION"
        echo "samply.json: $(du -h "$OUT_DIR/samply.json" | cut -f1)"
        echo "view at: https://profiler.firefox.com/ (upload samply.json)"
        ;;
esac

echo
echo "artifacts:"
ls -lh "$OUT_DIR/"
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x scripts/devnet-profile/capture.sh
ls -la scripts/devnet-profile/capture.sh
```

Expected mode: `-rwxr-xr-x` (755).

- [ ] **Step 3: Argument-validation smoke test**

```bash
scripts/devnet-profile/capture.sh 2>&1 || true
```

Expected: prints `Usage: ...` and exits 1.

```bash
scripts/devnet-profile/capture.sh 'definitely-no-such-process-xyzqq' 10 /tmp/cap-test/ 2>&1 || true
```

Expected: prints `error: no process matches pattern: ...` and exits 1.

- [ ] **Step 4: End-to-end smoke test against a real short-lived target**

This step verifies the script picks the right sampler and writes artifacts. We run a `sleep 30` background process and capture it for 5 seconds.

```bash
# Start a target
sleep 30 &
TARGET_PID=$!
sleep 1

# Capture 5 seconds against it
scripts/devnet-profile/capture.sh "sleep 30" 5 /tmp/cap-smoke/

# Clean up the target
kill "$TARGET_PID" 2>/dev/null || true
wait 2>/dev/null || true

# Verify outputs
ls -la /tmp/cap-smoke/
```

Expected on macOS (samply path): `samply.json` exists, > 1 KB.
Expected on Linux (perf path): `perf.data` exists; `flamegraph.svg` exists if FlameGraph scripts are on PATH, otherwise warning printed.

If neither artifact exists, debug before continuing.

- [ ] **Step 5: Commit**

```bash
git add scripts/devnet-profile/capture.sh
git commit -m "scripts/devnet-profile: add capture.sh (perf with samply fallback)"
```

---

## Task 4: `docs/perf/devnet/` scaffold

**Files:**
- Create: `docs/perf/devnet/raw/.gitignore`
- Create: `docs/perf/devnet/baselines/.gitkeep`

- [ ] **Step 1: Create the directories**

```bash
mkdir -p docs/perf/devnet/raw docs/perf/devnet/baselines
```

- [ ] **Step 2: Write `docs/perf/devnet/raw/.gitignore`**

```bash
cat > docs/perf/devnet/raw/.gitignore <<'EOF'
# Raw profile artifacts and devnet logs — large + non-portable.
# Only `docs/perf/devnet/baselines/*` is tracked.
*
!.gitignore
EOF
```

The `*` + `!.gitignore` pattern ignores everything in this directory except `.gitignore` itself. Captured files (perf.data, samply.json, logs) auto-ignored when written here.

- [ ] **Step 3: Create the `.gitkeep` in baselines/**

```bash
touch docs/perf/devnet/baselines/.gitkeep
```

- [ ] **Step 4: Verify scaffold**

```bash
ls -la docs/perf/devnet/
ls -la docs/perf/devnet/raw/
ls -la docs/perf/devnet/baselines/
```

Both subdirs exist; raw/ has `.gitignore`; baselines/ has `.gitkeep`.

- [ ] **Step 5: Commit**

```bash
git add docs/perf/devnet/
git commit -m "docs/perf/devnet: scaffold baselines/ + raw/ (gitignored)"
```

---

## Task 5: `docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md`

**Files:**
- Create: `docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md`

- [ ] **Step 1: Write the template**

Create `docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md`:

```markdown
# Devnet profile — <YYYY-MM-DD>, zeam_0 @ <commit-sha>

> Copy this file to `<date>-<short-sha>-summary.md` (e.g. `2026-05-12-43bb8362-summary.md`)
> and fill in the blanks after running `scripts/devnet-profile/capture.sh`.

**Run parameters**

- Duration: <e.g. 30 min>
- Nodes: <e.g. 4 (zeam_0..zeam_3)>
- Validators per node: <e.g. 8>
- Slot interval: 4 s (mainnet preset)
- Host: <e.g. GitHub Codespace 4-core 16GB>
- zeam build: `-Dslot-probes=true -Doptimize=ReleaseFast` at sha `<sha>`
- Sampler: <perf|samply>

## Headline numbers

- Slots observed: <count>
- Total `slot_probe over budget` events: <count>
- Worst probe (highest over-budget rate): <name> at <pct>%
- IO-thread invariant violations observed: <yes / no / count>
- Chain-worker queue max depth: <N> (block) / <N> (attestation)

## 1. Slot-budget probes

Source: `<date>-<sha>-slot_probe.tsv`.

| Probe | Events | Min | Median | p99 | Max | Budget |
|---|---:|---:|---:|---:|---:|---:|
| `chain.onBlock` | … | … | … | … | … | 800ms |
| `chain.produceBlock` | … | … | … | … | … | 800ms |
| `chain.onGossip` | … | … | … | … | … | 800ms |
| `chain.onInterval` | … | … | … | … | … | 800ms |
| `fc.aggregate` | … | … | … | … | … | 800ms |
| `fc.acceptNewAttestations` | … | … | … | … | … | 400ms |

Quick analysis recipe:

```bash
# Counts and percentiles per probe (requires GNU `datamash` or pipe to awk)
awk -F'\t' 'NR>1 {print $2 "\t" $3}' <date>-<sha>-slot_probe.tsv \
    | sort \
    | uniq -c
```

Findings: <2-4 sentences>.

## 2. Chain-worker queue saturation

Source: scrape of `lean_chain_queue_depth{queue="block"|"attestation"}` from
`http://<zeam_0_ip>:8000/metrics` if you ran the scrape loop, or eyeballed
from grafana.

- Max block queue depth: <N> / <capacity>
- Max attestation queue depth: <N> / <capacity>
- Time periods above 50% capacity: <list timestamps>
- Any `lean_chain_queue_dropped_total` increments: <yes / no>

Findings: <2-4 sentences>.

## 3. IO-thread invariant

`#803` invariant: the libxev main thread runs *only* the event router —
no STF, no XMSS verify, no aggregation. To check, identify the libxev TID
in the zeam_0 log (search for `libxev main thread tid=`) and look in
`flamegraph.svg` for that TID. The forbidden symbol set:

- `apply_raw_block` / `apply_transition`
- `verifySsz` (XMSS verify)
- `AggregatedSignatureProof.aggregate`
- `process_block` / `process_slots`
- `hashTreeRoot`

Observation: <samples landing on libxev TID in forbidden set / total libxev samples>
= <pct>%. Anything above ~0.1% is a violation worth filing.

Findings: <2-4 sentences>.

## 4. Lock contention

Top callers of `pthread_mutex_lock` / `__psynch_cvwait` / `_pthread_cond_wait`
in `flamegraph.svg`:

| Caller | Approx % of total samples |
|---|---:|
| <e.g. forkchoice.onAttestation → state_lock> | <pct> |
| <e.g. chain.onBlock → block_cache_lock> | <pct> |
| <e.g. node.onGossip → events_lock> | <pct> |

Findings: <2-4 sentences>.

## Headline findings (bullet form, action-oriented)

- <e.g. "fc.aggregate exceeds budget 14% of slots — confirms aggregation must move off chain-worker thread or run async">
- <e.g. "block queue saturated only during fork-period bursts; sized correctly for steady-state">
- <e.g. "no IO invariant violations observed → slice (c) holds in steady-state">
- <e.g. "top lock contention is `state_lock` on attestation path → candidate for arena allocator refactor">

## Reproducibility

```bash
# 1. Start devnet (separate shell)
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh \
    --node zeam_0,zeam_1,zeam_2,zeam_3 \
    --generateGenesis

# Wait ~60 seconds for gossip mesh

# 2. Capture
scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
    docs/perf/devnet/raw/$(date +%F)/

# 3. Extract probes from log (parser is portable across BSD awk + gawk)
LOG=lean-quickstart/local-devnet/data/zeam_0/stderr.log
grep "slot_probe over budget" "$LOG" \
    | awk -f scripts/devnet-profile/parse-slot-probes.awk \
    > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
```

Raw `perf.data` (~300-500 MB) is in `docs/perf/devnet/raw/`, gitignored.
`flamegraph.svg` and `slot_probe.tsv` are alongside this summary file.
```

- [ ] **Step 2: Commit**

```bash
git add docs/perf/devnet/baselines/SUMMARY_TEMPLATE.md
git commit -m "docs/perf/devnet: add summary template for baseline runs"
```

---

## Task 6: `docs/perf/devnet/README.md` — the runbook

**Files:**
- Create: `docs/perf/devnet/README.md`

- [ ] **Step 1: Write the runbook**

Create `docs/perf/devnet/README.md`:

```markdown
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

Recommended host: **GitHub Codespace, 4-core 16 GB Ubuntu 24.04**. Local Linux
works too. macOS works via `samply` fallback but threading behaviour differs
from production — prefer Codespace.

```bash
# One-time setup on Linux (codespace or other)
sudo apt update
sudo apt install -y linux-tools-generic linux-tools-"$(uname -r)" jq yq

# FlameGraph scripts (Brendan Gregg's) — only needed for the `perf` path
git clone --depth=1 https://github.com/brendangregg/FlameGraph /opt/FlameGraph
echo 'export PATH=/opt/FlameGraph:$PATH' >> ~/.bashrc
export PATH=/opt/FlameGraph:$PATH

# Verify perf works without root; if denied, allow non-root sampling:
perf record -F 1 -p $$ -o /tmp/x -- sleep 0.1 && echo "perf OK"
# If the above fails:
sudo sysctl -w kernel.perf_event_paranoid=1
```

For the `samply` fallback (macOS):

```bash
cargo install samply
```

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

The TSV has columns: `timestamp`, `probe_name`, `elapsed_ns`, `budget_ns`,
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
     `apply_transition`, `verifySsz`, `aggregate`, `hashTreeRoot`. (Find
     libxev's TID in the zeam_0 startup log: `grep "libxev" stderr.log`.)
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
```

- [ ] **Step 2: Verify markdown renders cleanly**

```bash
# Optional: render check (skip if no markdown linter available)
which mdl >/dev/null && mdl docs/perf/devnet/README.md || true
```

Visually inspect the file: headings hierarchy correct, code blocks closed, no broken links.

- [ ] **Step 3: Commit**

```bash
git add docs/perf/devnet/README.md
git commit -m "docs/perf/devnet: add runbook README"
```

---

## Task 7: `scripts/devnet-profile/README.md` — short pointer

**Files:**
- Create: `scripts/devnet-profile/README.md`

- [ ] **Step 1: Write the script-dir README**

Create `scripts/devnet-profile/README.md`:

```markdown
# scripts/devnet-profile/

Thin shell+awk tooling for capturing a system-level profile of a running
zeam node in a multi-node devnet.

## Contents

| File | Purpose |
|---|---|
| `capture.sh` | Attach `perf` (or `samply`) to a running zeam process, record for N seconds, generate flamegraph |
| `parse-slot-probes.awk` | Convert `slot_probe over budget` lines from a zeam log to a 5-column TSV |
| `test/sample-log.txt` | Synthetic input for testing the awk parser |
| `test/expected-slot-probe.tsv` | Expected output (used by `diff` in tests) |

## Quick usage

```bash
# 1. Start lean-quickstart devnet manually (see docs/perf/devnet/README.md)

# 2. Capture 30 min of zeam_0
scripts/devnet-profile/capture.sh "zeam.*zeam_0" 1800 \
    docs/perf/devnet/raw/$(date +%F)/

# 3. Extract slot probes
grep "slot_probe over budget" \
    lean-quickstart/local-devnet/data/zeam_0/stderr.log \
  | awk -f scripts/devnet-profile/parse-slot-probes.awk \
  > docs/perf/devnet/baselines/$(date +%F)-slot_probe.tsv
```

Full runbook + summary template: **`docs/perf/devnet/README.md`**.

## Testing the awk parser locally

```bash
awk -f scripts/devnet-profile/parse-slot-probes.awk \
    < scripts/devnet-profile/test/sample-log.txt \
    | diff scripts/devnet-profile/test/expected-slot-probe.tsv -
```

Expected: no output (clean diff).
```

- [ ] **Step 2: Commit**

```bash
git add scripts/devnet-profile/README.md
git commit -m "scripts/devnet-profile: add directory README"
```

---

## Task 8: Final smoke test + verification

**No files modified.** This task verifies the shipped artifacts behave as designed.

- [ ] **Step 1: Re-run awk parser test**

```bash
awk -f scripts/devnet-profile/parse-slot-probes.awk \
    < scripts/devnet-profile/test/sample-log.txt \
    | diff scripts/devnet-profile/test/expected-slot-probe.tsv -
```

Expected: empty diff (exit 0).

- [ ] **Step 2: Re-run capture.sh argument validation**

```bash
scripts/devnet-profile/capture.sh 2>&1 | head -3
```

Expected: `Usage: ...` line.

```bash
scripts/devnet-profile/capture.sh 'no-such-process-xyzqq' 10 /tmp/cap-test/ 2>&1 | head -3
```

Expected: `error: no process matches pattern: ...` line, exit 1.

- [ ] **Step 3: Build zeam with slot probes (sanity)**

```bash
zig build -Dslot-probes=true -Doptimize=ReleaseFast 2>&1 | tail -3
```

Expected: `Finished release profile [optimized] target(s)` line, no errors.

This confirms the dependency on PR #861's `slot_probe` module is intact.

- [ ] **Step 4: Confirm no production code changed**

```bash
git diff --stat 80677fbe..HEAD -- pkgs/ src/ build.zig build.zig.zon
```

Expected: empty output (this branch only adds docs + scripts; no zeam runtime change).

If anything in `pkgs/` or `build.zig` shows in the diff, investigate before
declaring done.

- [ ] **Step 5: Confirm git log shape**

```bash
git log --oneline 80677fbe..HEAD
```

Expected: 7 commits matching the task layout above (scaffold, awk parser,
capture.sh, devnet scaffold, summary template, runbook, script README).
No format-fix commit unless needed.

- [ ] **Step 6: Run format checks**

```bash
zig fmt --check . 2>&1 | head -5
shellcheck scripts/devnet-profile/capture.sh 2>&1 | head -20 || true
```

`zig fmt --check`: no output (the branch adds no zig files).
`shellcheck` (if installed): may suggest improvements; address any errors, leave warnings.

- [ ] **Step 7: If any format fix needed, commit**

If shellcheck flagged a real error, fix it inline and commit:

```bash
git add scripts/devnet-profile/capture.sh
git commit -m "scripts/devnet-profile: fix shellcheck findings"
```

Otherwise skip.

---

## Self-Review Checklist (for the implementer)

After all 8 tasks:

- [ ] `scripts/devnet-profile/{capture.sh,parse-slot-probes.awk,README.md}` exist
- [ ] `scripts/devnet-profile/test/{sample-log.txt,expected-slot-probe.tsv}` exist and parser passes diff
- [ ] `scripts/devnet-profile/capture.sh` is executable (mode 755)
- [ ] `docs/perf/devnet/{README.md,raw/.gitignore,baselines/.gitkeep,baselines/SUMMARY_TEMPLATE.md}` exist
- [ ] `git diff` shows no production code (`pkgs/`, `build.zig`) changes
- [ ] `zig build -Dslot-probes=true -Doptimize=ReleaseFast` still succeeds
- [ ] 7 task commits, plus optional format-fix commit
- [ ] First baseline run is NOT in scope — it happens after merge

---

## Out of scope (explicit follow-ups)

These were documented as non-goals in the spec; they don't appear in any task above:

- `scripts/devnet-profile/run.sh` orchestrator
- `.devcontainer/perf-devnet/devcontainer.json`
- `analyze.py` Python report generator
- Prometheus scraper loop
- macOS-native multi-node devnet support
- `lean_chain_queue_depth` metric (verified during plan-writing: **already shipped** in `pkgs/metrics/src/lib.zig:177`)

If you find yourself drawn to implement any of these "while you're here", **don't**. Get the first baseline shipped, then circle back if patterns emerge that justify automation.
