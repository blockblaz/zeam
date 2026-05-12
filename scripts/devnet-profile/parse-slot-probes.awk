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
