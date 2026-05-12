#!/usr/bin/env bash
# Wrap samply (macOS) or perf (linux) around a bench binary.
# Usage: scripts/profile.sh <bench-name>
#
# Examples:
#   scripts/profile.sh xmss
#   scripts/profile.sh stf
set -euo pipefail

NAME="${1:?usage: scripts/profile.sh <bench-name>}"; shift || true
BIN="zig-out/bin/bench-${NAME}"

if [[ ! -x "$BIN" ]]; then
    zig build "bench-${NAME}" -Doptimize=ReleaseFast
fi

mkdir -p docs/perf/profiles

case "$(uname -s)" in
    Darwin)
        if ! command -v samply >/dev/null 2>&1; then
            echo "samply not found — install with: cargo install samply" >&2
            exit 1
        fi
        OUT="docs/perf/profiles/${NAME}.samply.json"
        echo "Profiling ${BIN} with samply → ${OUT}"
        samply record -o "$OUT" -- "$BIN" "$@"
        ;;
    Linux)
        if ! command -v perf >/dev/null 2>&1; then
            echo "perf not found — install linux-tools or similar" >&2
            exit 1
        fi
        OUT="docs/perf/profiles/${NAME}.perf.data"
        SVG="docs/perf/profiles/${NAME}.svg"
        echo "Profiling ${BIN} with perf → ${OUT}, flamegraph → ${SVG}"
        perf record -F 997 --call-graph dwarf -o "$OUT" -- "$BIN" "$@"
        if command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
            perf script -i "$OUT" | stackcollapse-perf.pl | flamegraph.pl > "$SVG"
        else
            echo "FlameGraph scripts not on PATH — skipping SVG generation" >&2
        fi
        ;;
    *)
        echo "Unsupported OS: $(uname -s)" >&2
        exit 1
        ;;
esac
