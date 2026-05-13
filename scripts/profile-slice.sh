#!/usr/bin/env bash
#
# profile-slice.sh — extract a time-window flamegraph from a rotated
# perf.data chunk produced by profile-continuous.sh.
#
# Usage:
#   profile-slice.sh <chunk-file> [start_sec end_sec] [out.svg]
#
# Examples:
#   # Whole chunk → flamegraph
#   scripts/profile-slice.sh /var/lib/zeam-perf/perf.data.20260513120000 out.svg
#
#   # Slice 12.3s–14.5s (perf-relative; see --header for capture start)
#   scripts/profile-slice.sh /var/lib/zeam-perf/perf.data.20260513120000 12.3 14.5 slow-slot.svg
#
# Workflow:
#   1. profile-continuous.sh runs forever on each node, rotates chunks.
#   2. Operator notes a slow event from Prometheus (e.g. fc.aggregate
#      duration histogram p99 spike at wall-clock T).
#   3. Find the chunk covering T (chunk filename includes capture-start
#      timestamp). Use `perf script --header -i <chunk>` to see the
#      capture-start absolute time, then compute T_relative = T - start.
#   4. Run this script with the chunk and T_relative-window to get a
#      flamegraph of just that slot.
#
# This script is Linux-only because samply chunks (macOS) are already
# self-contained JSON — load them at https://profiler.firefox.com/ and use
# the timeline slider to focus a time window.
set -euo pipefail

usage() {
    echo "Usage: $0 <chunk-file> [start_sec end_sec] [out.svg]" >&2
    echo "  Pass start/end as fractional seconds from chunk start." >&2
    echo "  Omit them to flamegraph the whole chunk." >&2
    exit 1
}

[[ $# -ge 1 ]] || usage
CHUNK="$1"; shift

[[ -r "$CHUNK" ]] || { echo "error: cannot read $CHUNK" >&2; exit 1; }

TIME_FILTER=""
case $# in
    0)
        OUT="${CHUNK%.data}.svg"
        ;;
    1)
        OUT="$1"
        ;;
    2)
        TIME_FILTER="--time=$1,$2"
        OUT="${CHUNK%.data}-slice.svg"
        ;;
    3)
        TIME_FILTER="--time=$1,$2"
        OUT="$3"
        ;;
    *)
        usage
        ;;
esac

for tool in perf stackcollapse-perf.pl flamegraph.pl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not on PATH" >&2
        echo "  install perf via linux-tools; FlameGraph via" >&2
        echo "  git clone https://github.com/brendangregg/FlameGraph && export PATH=\$PWD/FlameGraph:\$PATH" >&2
        exit 1
    fi
done

echo "slicing $CHUNK ${TIME_FILTER:-(whole chunk)} → $OUT"

# perf script emits warnings about kernel symbols on hosts with restricted
# kallsyms. They don't affect the user-space stacks we care about; guard
# the pipeline so a warning on stderr doesn't trip `set -e`.
set +e
# shellcheck disable=SC2086  # TIME_FILTER is intentionally word-split when set
perf script $TIME_FILTER -i "$CHUNK" 2>/dev/null \
    | stackcollapse-perf.pl \
    | flamegraph.pl > "$OUT"
RC=$?
set -e

if [[ ! -s "$OUT" ]]; then
    echo "error: flamegraph SVG is empty (no samples in window?)" >&2
    rm -f "$OUT"
    exit 1
fi

echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
exit $RC
