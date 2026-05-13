#!/usr/bin/env bash
#
# profile-continuous.sh — attach a sampling profiler to a running zeam node
# and keep recording until killed (SIGINT/SIGTERM). Designed for always-on
# production use under systemd: pair this with a sidecar uploader that
# ships rotated chunks to object storage.
#
# Usage: profile-continuous.sh <process-pattern> [out-dir]
#
# Example:
#   scripts/profile-continuous.sh "zeam.*node" /var/lib/zeam-perf/
#
# Tunables (env vars):
#   PROFILE_FREQ_HZ      sample frequency in Hz       (default: 19  ~0.5% CPU)
#   PROFILE_CHUNK_BYTES  perf chunk rotation size     (default: 200M, Linux only)
#   PROFILE_CHUNK_SECS   samply chunk duration secs   (default: 300, macOS only)
#   PROFILE_CALL_GRAPH   perf --call-graph mode       (default: fp)
#
# Output layout:
#   Linux : $OUT_DIR/perf.data.YYYYMMDDHHMMSS  (rotated by perf --switch-output)
#   macOS : $OUT_DIR/samply-<epoch>.json       (one file per chunk)
#
# Stop with Ctrl-C / SIGTERM. perf flushes its current chunk on signal;
# the samply loop kills the in-flight samply and exits cleanly.
#
# Production tip: run as a systemd unit with Restart=on-failure, and have
# an inotify-based uploader push completed chunks to s3:// with structured
# keys (`<host>/<sha>/<date>/<chunk-name>`). Correlate after the fact by
# joining wall-clock to Prometheus metrics.
set -euo pipefail

usage() {
    echo "Usage: $0 <process-pattern> [out-dir]" >&2
    echo "  Example: $0 'zeam.*node' /var/lib/zeam-perf/" >&2
    exit 1
}

[[ $# -ge 1 ]] || usage
PATTERN="$1"
OUT_DIR="${2:-/var/lib/zeam-perf}"

FREQ_HZ="${PROFILE_FREQ_HZ:-19}"
CHUNK_BYTES="${PROFILE_CHUNK_BYTES:-200M}"
CHUNK_SECS="${PROFILE_CHUNK_SECS:-300}"
CALL_GRAPH="${PROFILE_CALL_GRAPH:-fp}"

PID=$(pgrep -f "$PATTERN" | head -1 || true)
if [[ -z "$PID" ]]; then
    echo "error: no process matches pattern: $PATTERN" >&2
    exit 1
fi
echo "target pid: $PID ($(ps -p "$PID" -o comm= 2>/dev/null || echo unknown))"

mkdir -p "$OUT_DIR"

case "$(uname -s)" in
    Linux)
        if ! command -v perf >/dev/null 2>&1; then
            echo "error: perf not installed (try: apt install linux-tools-generic)" >&2
            exit 1
        fi
        # Sanity-check perf works for non-root use. If perf_event_paranoid
        # blocks it, fail loud — the operator should fix the host setting
        # rather than silently fall back to a higher-overhead sampler.
        if ! perf record -F 1 -p $$ -o /tmp/perf-probe-$$.data -- sleep 0.1 >/dev/null 2>&1; then
            rm -f /tmp/perf-probe-$$.data
            echo "error: perf record blocked (kernel.perf_event_paranoid?)" >&2
            echo "  fix: sudo sysctl -w kernel.perf_event_paranoid=1" >&2
            exit 1
        fi
        rm -f /tmp/perf-probe-$$.data

        echo "linux: perf record -F ${FREQ_HZ} --call-graph ${CALL_GRAPH} --switch-output=${CHUNK_BYTES}"
        echo "       output: ${OUT_DIR}/perf.data.<timestamp>"
        echo "       stop with Ctrl-C / SIGTERM"
        exec perf record \
            -F "$FREQ_HZ" \
            --call-graph "$CALL_GRAPH" \
            -p "$PID" \
            --switch-output="$CHUNK_BYTES" \
            --timestamp-filename \
            -o "$OUT_DIR/perf.data"
        ;;
    Darwin)
        if ! command -v samply >/dev/null 2>&1; then
            echo "error: samply not installed (try: cargo install samply)" >&2
            exit 1
        fi

        echo "macOS: samply loop with ${CHUNK_SECS}s chunks at ${FREQ_HZ}Hz"
        echo "       output: ${OUT_DIR}/samply-<epoch>.json"
        echo "       stop with Ctrl-C / SIGTERM"

        # Track the current samply pid so the signal handler can SIGINT it
        # for a clean per-chunk shutdown. samply ignores `-d` in --pid mode,
        # so we drive duration externally.
        CUR_SAMPLY=""
        on_signal() {
            if [[ -n "$CUR_SAMPLY" ]] && kill -0 "$CUR_SAMPLY" 2>/dev/null; then
                kill -INT "$CUR_SAMPLY" 2>/dev/null || true
                wait "$CUR_SAMPLY" 2>/dev/null || true
            fi
            exit 0
        }
        trap on_signal INT TERM

        while kill -0 "$PID" 2>/dev/null; do
            OUT="$OUT_DIR/samply-$(date +%s).json"
            samply record --save-only --pid "$PID" -r "$FREQ_HZ" -o "$OUT" &
            CUR_SAMPLY=$!
            sleep "$CHUNK_SECS"
            kill -INT "$CUR_SAMPLY" 2>/dev/null || true
            wait "$CUR_SAMPLY" 2>/dev/null || true
            CUR_SAMPLY=""
        done
        echo "target pid $PID no longer running; exiting"
        ;;
    *)
        echo "error: unsupported OS: $(uname -s)" >&2
        exit 1
        ;;
esac
