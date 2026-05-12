#!/usr/bin/awk -f
#
# parse-slot-probes.awk — convert zeam slot_probe warning lines to TSV.
#
# Usage:
#   grep "slot_probe over budget" zeam_0.log \
#       | awk -f scripts/devnet-profile/parse-slot-probes.awk > slot_probe.tsv
#
# Input format (from pkgs/utils/src/slot_probe.zig RealProbe.end, via std.log.warn):
#   warning: slot_probe over budget: chain.onBlock took 950000000ns (budget 800000000ns)
#
# Note: std.log.warn emits no timestamp prefix (just "warning: ").  The first
# column is therefore the line number (NR) in the input stream, which gives a
# stable ordering key.  If you need wall-clock ordering across multiple runs,
# prepend `nl` or `cat -n` to the pipeline before this script.
#
# Output columns (TAB separated, header always present):
#   line_no  probe_name  elapsed_ns  budget_ns  over_pct
#
# Portable across BSD awk (macOS) and gawk (Linux/codespace).
BEGIN {
    OFS = "\t"
    print "line_no", "probe_name", "elapsed_ns", "budget_ns", "over_pct"
}

/slot_probe over budget:/ {
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
    print NR, probe, elapsed, budget, over_pct
}
