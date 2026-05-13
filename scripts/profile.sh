#!/usr/bin/env bash
#
# profile.sh — sample-profile and analyze zeam.
#
# Subcommands:
#   bench  <name>                              run a bench binary under samply/perf
#   attach <pattern> [out-dir]                 continuously sample a running zeam node
#   slice  <chunk-file> [start end] [out.svg]  flamegraph a (window of a) rotated chunk
#
# Tools:
#   - macOS: samply (cargo install samply)
#   - Linux: perf (apt install linux-tools-generic) + FlameGraph scripts
#     (git clone https://github.com/brendangregg/FlameGraph; export PATH=$PWD/FlameGraph:$PATH)
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  profile.sh bench  <name>                              # one-shot bench profile
  profile.sh attach <process-pattern> [out-dir]         # continuous attach (production)
  profile.sh slice  <chunk-file> [start end] [out.svg]  # extract flamegraph from chunk

Examples:
  profile.sh bench xmss
  profile.sh attach "zeam.*node" /var/lib/zeam-perf/
  profile.sh slice /var/lib/zeam-perf/perf.data.20260513120000 12.3 14.5 slow-slot.svg

Env overrides (attach):
  PROFILE_FREQ_HZ      sample frequency in Hz       (default: 19)
  PROFILE_CHUNK_BYTES  perf chunk rotation size     (default: 200M, Linux only)
  PROFILE_CHUNK_SECS   samply chunk duration secs   (default: 300, macOS only)
  PROFILE_CALL_GRAPH   perf --call-graph mode       (default: fp)
EOF
    exit 1
}

cmd_bench() {
    [[ $# -ge 1 ]] || usage
    local name="$1"; shift
    local bin="zig-out/bin/bench-${name}"

    if [[ ! -x "$bin" ]]; then
        zig build "bench-${name}" -Doptimize=ReleaseFast
    fi
    mkdir -p docs/perf/profiles

    case "$(uname -s)" in
        Darwin)
            command -v samply >/dev/null 2>&1 \
                || { echo "samply not found — install with: cargo install samply" >&2; exit 1; }
            local out="docs/perf/profiles/${name}.samply.json"
            echo "Profiling ${bin} with samply → ${out}"
            # --save-only: write the JSON and exit. Without it, samply opens
            # a local web UI and blocks until the user closes the browser
            # tab, which breaks any non-interactive use. Load the JSON at
            # https://profiler.firefox.com/ or via `samply load <file>`.
            samply record --save-only -o "$out" -- "$bin" "$@"
            ;;
        Linux)
            command -v perf >/dev/null 2>&1 \
                || { echo "perf not found — install linux-tools" >&2; exit 1; }
            local out="docs/perf/profiles/${name}.perf.data"
            local svg="docs/perf/profiles/${name}.svg"
            echo "Profiling ${bin} with perf → ${out}, flamegraph → ${svg}"
            perf record -F 997 --call-graph dwarf -o "$out" -- "$bin" "$@"
            if command -v stackcollapse-perf.pl >/dev/null 2>&1 \
                && command -v flamegraph.pl >/dev/null 2>&1; then
                perf script -i "$out" | stackcollapse-perf.pl | flamegraph.pl > "$svg"
            else
                echo "FlameGraph scripts not on PATH — skipping SVG generation" >&2
            fi
            ;;
        *)
            echo "Unsupported OS: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

# ----------------------------------------------------------------------
# attach: continuously sample a running zeam process by PID. Designed for
# always-on production capture under systemd, paired with a sidecar that
# uploads rotated chunks to object storage. Correlate offline by joining
# wall-clock to existing Prometheus metrics.
# ----------------------------------------------------------------------
cmd_attach() {
    [[ $# -ge 1 ]] || usage
    local pattern="$1"
    local out_dir="${2:-/var/lib/zeam-perf}"

    local freq_hz="${PROFILE_FREQ_HZ:-19}"
    local chunk_bytes="${PROFILE_CHUNK_BYTES:-200M}"
    local chunk_secs="${PROFILE_CHUNK_SECS:-300}"
    local call_graph="${PROFILE_CALL_GRAPH:-fp}"

    local pid
    pid=$(pgrep -f "$pattern" | head -1 || true)
    if [[ -z "$pid" ]]; then
        echo "error: no process matches pattern: $pattern" >&2
        exit 1
    fi
    echo "target pid: $pid ($(ps -p "$pid" -o comm= 2>/dev/null || echo unknown))"
    mkdir -p "$out_dir"

    case "$(uname -s)" in
        Linux)
            command -v perf >/dev/null 2>&1 \
                || { echo "error: perf not installed (try: apt install linux-tools-generic)" >&2; exit 1; }
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

            echo "linux: perf record -F ${freq_hz} --call-graph ${call_graph} --switch-output=${chunk_bytes}"
            echo "       output: ${out_dir}/perf.data.<timestamp>"
            echo "       stop with Ctrl-C / SIGTERM"
            exec perf record \
                -F "$freq_hz" \
                --call-graph "$call_graph" \
                -p "$pid" \
                --switch-output="$chunk_bytes" \
                --timestamp-filename \
                -o "$out_dir/perf.data"
            ;;
        Darwin)
            command -v samply >/dev/null 2>&1 \
                || { echo "error: samply not installed (try: cargo install samply)" >&2; exit 1; }

            echo "macOS: samply loop with ${chunk_secs}s chunks at ${freq_hz}Hz"
            echo "       output: ${out_dir}/samply-<epoch>.json"
            echo "       stop with Ctrl-C / SIGTERM"

            # Track the current samply pid so the signal handler can SIGINT it
            # for a clean per-chunk shutdown. samply ignores `-d` in --pid mode,
            # so we drive duration externally.
            local cur_samply=""
            on_signal() {
                if [[ -n "$cur_samply" ]] && kill -0 "$cur_samply" 2>/dev/null; then
                    kill -INT "$cur_samply" 2>/dev/null || true
                    wait "$cur_samply" 2>/dev/null || true
                fi
                exit 0
            }
            trap on_signal INT TERM

            while kill -0 "$pid" 2>/dev/null; do
                local out="$out_dir/samply-$(date +%s).json"
                samply record --save-only --pid "$pid" -r "$freq_hz" -o "$out" &
                cur_samply=$!
                sleep "$chunk_secs"
                kill -INT "$cur_samply" 2>/dev/null || true
                wait "$cur_samply" 2>/dev/null || true
                cur_samply=""
            done
            echo "target pid $pid no longer running; exiting"
            ;;
        *)
            echo "error: unsupported OS: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

# ----------------------------------------------------------------------
# slice: extract a time-window flamegraph from a rotated perf.data chunk.
# Workflow: Prometheus shows a slow event at wall-clock T → find the chunk
# covering T → `perf script --header` shows capture-start absolute time →
# compute T_rel = T - capture_start → call this.
#
# samply (macOS) chunks are self-contained JSON; upload to
# https://profiler.firefox.com/ and use the timeline slider instead.
# ----------------------------------------------------------------------
cmd_slice() {
    [[ $# -ge 1 ]] || usage
    local chunk="$1"; shift
    [[ -r "$chunk" ]] || { echo "error: cannot read $chunk" >&2; exit 1; }

    # samply (macOS) JSON chunks are self-contained — slicing happens
    # interactively in the Firefox Profiler UI, not via a CLI tool.
    case "$chunk" in
        *.json|*.samply.json)
            cat >&2 <<'EOF'
error: this subcommand only handles Linux perf.data chunks.
       samply JSON is self-contained — slice it interactively by uploading
       to https://profiler.firefox.com/ and using the timeline range tool.
EOF
            exit 1
            ;;
    esac
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "error: 'slice' requires Linux perf + FlameGraph (not available on $(uname -s))" >&2
        echo "       use https://profiler.firefox.com/ on a samply JSON chunk instead" >&2
        exit 1
    fi

    local time_filter=""
    local out
    case $# in
        0) out="${chunk%.data}.svg" ;;
        1) out="$1" ;;
        2) time_filter="--time=$1,$2"; out="${chunk%.data}-slice.svg" ;;
        3) time_filter="--time=$1,$2"; out="$3" ;;
        *) usage ;;
    esac

    for tool in perf stackcollapse-perf.pl flamegraph.pl; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "error: $tool not on PATH" >&2
            echo "  install perf via linux-tools; FlameGraph via" >&2
            echo "  git clone https://github.com/brendangregg/FlameGraph && export PATH=\$PWD/FlameGraph:\$PATH" >&2
            exit 1
        }
    done

    echo "slicing $chunk ${time_filter:-(whole chunk)} → $out"

    # perf script emits warnings about kernel symbols on hosts with restricted
    # kallsyms. They don't affect the user-space stacks we care about; guard
    # the pipeline so a warning on stderr doesn't trip `set -e`.
    set +e
    # shellcheck disable=SC2086  # time_filter is intentionally word-split when set
    perf script $time_filter -i "$chunk" 2>/dev/null \
        | stackcollapse-perf.pl \
        | flamegraph.pl > "$out"
    set -e

    if [[ ! -s "$out" ]]; then
        echo "error: flamegraph SVG is empty (no samples in window?)" >&2
        rm -f "$out"
        exit 1
    fi
    echo "wrote $out ($(du -h "$out" | cut -f1))"
}

[[ $# -ge 1 ]] || usage
sub="$1"; shift
case "$sub" in
    bench)  cmd_bench  "$@" ;;
    attach) cmd_attach "$@" ;;
    slice)  cmd_slice  "$@" ;;
    -h|--help|help) usage ;;
    *) echo "error: unknown subcommand: $sub" >&2; usage ;;
esac
