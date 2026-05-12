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
free_mb=$(df -BM "$OUT_DIR" 2>/dev/null | awk 'NR==2 {gsub("M",""); print $4}') || true
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
#
# Call-graph mode notes:
#   - `fp` (default): frame-pointer-based unwind. Tiny perf.data (~10× smaller
#     than dwarf), fast. Zig ReleaseFast retains frame pointers, so this
#     works for zeam. Default for that reason.
#   - `dwarf,8192`: captures 8KB user stack per sample. Use when frame
#     pointers are missing (e.g., Rust dep with `-Cforce-frame-pointers=no`).
#     The earlier `dwarf,16384` default produced 2.4 GB perf.data for a 20s
#     8-core run — unworkable on a codespace. Half-size also produces deep
#     enough stacks for Plonky3 (depth observed: ~30 frames, ~6 KB).
#   - Override via env: `CAPTURE_CALL_GRAPH=dwarf,8192 capture.sh ...`
CALL_GRAPH="${CAPTURE_CALL_GRAPH:-fp}"
case "$SAMPLER" in
    perf)
        perf record -F 997 --call-graph "$CALL_GRAPH" -p "$PID" \
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
        # samply attach mode: send SIGINT after $DURATION seconds so it
        # writes the output file (it ignores -d in --pid mode on macOS).
        samply record --save-only --pid "$PID" \
            -d "$DURATION" -o "$OUT_DIR/samply.json" &
        SAMPLY_PID=$!
        sleep "$DURATION" && kill -INT "$SAMPLY_PID" 2>/dev/null &
        wait "$SAMPLY_PID" 2>/dev/null || true
        if [[ -f "$OUT_DIR/samply.json" ]]; then
            echo "samply.json: $(du -h "$OUT_DIR/samply.json" | cut -f1)"
        else
            echo "warning: samply.json not found — samply may have errored before write" >&2
        fi
        echo "view at: https://profiler.firefox.com/ (upload samply.json)"
        ;;
esac

echo
echo "artifacts:"
ls -lh "$OUT_DIR/"
