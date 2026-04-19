#!/usr/bin/env bash
#
# Emit a markdown summary of a hive results directory.
#
# Reads every `<unix>-<hex>.json` suite file hive writes under RESULTS_DIR,
# aggregates pass/fail/timeout counts across suites, and for each failure
# pulls the relevant slice out of the suite's testDetailsLog (via the
# {begin,end} byte offsets hive records on each failing test) so the
# summary can show why the test failed without forcing the reader to
# download the artifact.
#
# Usage: hive-summary.sh <results-dir> [output-file]
#
#   <results-dir>   directory hive wrote with `--results-root`
#   [output-file]   file to append the markdown summary to; defaults to
#                   stdout. Intended to be pointed at $GITHUB_STEP_SUMMARY
#                   and/or a PR-comment fragment.
#
# Output is markdown. If the directory has no suite files (e.g. hive
# failed before running any tests) the script still emits a summary
# block noting that no results were produced.

set -euo pipefail

results_dir="${1:-}"
output="${2:-/dev/stdout}"

if [ -z "$results_dir" ]; then
  echo "usage: $0 <results-dir> [output-file]" >&2
  exit 2
fi

if [ ! -d "$results_dir" ]; then
  echo "results directory not found: $results_dir" >&2
  exit 1
fi

# Emit markdown to a temp buffer first so a partial failure doesn't
# truncate an already-open $GITHUB_STEP_SUMMARY.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

shopt -s nullglob
# Suite files are named `<unix>-<hex>.json` (see libhive/testmanager.go:
# writeSuiteFile). `hive.json` is the top-level run metadata and must be
# excluded.
suites=()
for f in "$results_dir"/*.json; do
  base="$(basename "$f")"
  [ "$base" = "hive.json" ] && continue
  suites+=("$f")
done

if [ "${#suites[@]}" -eq 0 ]; then
  {
    echo "### Hive test results"
    echo
    echo "No suite result files were produced in \`$results_dir\`. This usually means hive failed before any test suite finished (e.g. during client or simulator image build)."
  } >> "$tmp"
  cat "$tmp" >> "$output"
  exit 0
fi

# Aggregate counters and a compact per-failure record in a single jq pass
# per suite. Timeouts are counted both as failures and as a separate
# bucket, matching how hiveview displays them.
total=0
passed=0
failed=0
timeouts=0
# Failures list: one record per line, tab-separated fields:
#   <suite>\t<test>\t<timeout?>\t<details_log>\t<begin>\t<end>\t<inline_details>
failures_tsv=""

for suite in "${suites[@]}"; do
  suite_name="$(jq -r '.name // "(unnamed)"' "$suite")"
  details_log_rel="$(jq -r '.testDetailsLog // ""' "$suite")"
  details_log_abs=""
  if [ -n "$details_log_rel" ] && [ -f "$results_dir/$details_log_rel" ]; then
    details_log_abs="$results_dir/$details_log_rel"
  fi

  counts="$(jq -r '
    [.testCases[].summaryResult] as $r
    | [($r|length),
       ([$r[] | select(.pass==true)] | length),
       ([$r[] | select(.pass==false)] | length),
       ([$r[] | select(.timeout==true)] | length)]
    | @tsv
  ' "$suite")"
  IFS=$'\t' read -r t p f to <<<"$counts"
  total=$((total + t))
  passed=$((passed + p))
  failed=$((failed + f))
  timeouts=$((timeouts + to))

  suite_failures="$(jq -r --arg suite "$suite_name" --arg log "$details_log_abs" '
    .testCases
    | to_entries
    | map(select(.value.summaryResult.pass == false))
    | .[]
    | [$suite,
       .value.name,
       (.value.summaryResult.timeout // false | tostring),
       $log,
       (.value.summaryResult.log.begin // ""),
       (.value.summaryResult.log.end   // ""),
       (.value.summaryResult.details   // "")]
    | @tsv
  ' "$suite")"
  if [ -n "$suite_failures" ]; then
    failures_tsv+="${suite_failures}"$'\n'
  fi
done

# Devnet label is carried through by the caller via HIVE_DEVNET_LABEL; we
# intentionally don't re-parse it from the results (hive's JSON doesn't
# record the client-file path).
devnet_label="${HIVE_DEVNET_LABEL:-unknown}"
simulator_label="${HIVE_SIMULATOR_LABEL:-unknown}"

{
  echo "### Hive test results"
  echo
  echo "| Simulator | Devnet | Suites | Tests | Passed | Failed | Timeouts |"
  echo "|---|---|---|---|---|---|---|"
  echo "| \`$simulator_label\` | \`$devnet_label\` | ${#suites[@]} | $total | $passed | $failed | $timeouts |"
  echo
} >> "$tmp"

if [ "$failed" -eq 0 ]; then
  echo "All $total tests passed." >> "$tmp"
  cat "$tmp" >> "$output"
  exit 0
fi

# Snippet budget per failure. GitHub step summary caps at 1 MiB total
# and PR comments at 65536 chars, so keep each excerpt bounded and
# collapse via <details> so the comment stays scannable.
snippet_bytes=1024

{
  echo "<details open>"
  echo "<summary><strong>Failed tests ($failed)</strong></summary>"
  echo
} >> "$tmp"

# Read the TSV line-by-line. Using a file descriptor to avoid subshell
# scoping of the loop variables.
while IFS=$'\t' read -r suite name timeout log_path begin end inline; do
  [ -z "$name" ] && continue

  badge=""
  [ "$timeout" = "true" ] && badge=" _(timeout)_"

  {
    echo "<hr>"
    echo
    echo "**\`$suite\`** → \`$name\`$badge"
    echo
  } >> "$tmp"

  # Prefer the inline `details` string if the suite recorded one;
  # otherwise slice the log file using the byte offsets hive wrote.
  excerpt=""
  if [ -n "$inline" ]; then
    excerpt="$inline"
  elif [ -n "$begin" ] && [ -n "$end" ] && [ -n "$log_path" ] && [ -f "$log_path" ]; then
    count=$((end - begin))
    if [ "$count" -gt 0 ]; then
      # `dd` skips `begin` bytes then reads `count` bytes. Cap at
      # snippet_bytes so a runaway test log doesn't blow the summary.
      if [ "$count" -gt "$snippet_bytes" ]; then
        count="$snippet_bytes"
      fi
      excerpt="$(dd if="$log_path" bs=1 skip="$begin" count="$count" 2>/dev/null || true)"
    fi
  fi

  if [ -n "$excerpt" ]; then
    {
      echo '```'
      # Strip trailing whitespace and cap length as a defence in depth.
      printf '%s\n' "$excerpt" | head -c "$snippet_bytes"
      echo
      echo '```'
    } >> "$tmp"
  else
    echo "_(no details recorded; check the uploaded hive results artifact)_" >> "$tmp"
  fi
  echo >> "$tmp"
done <<<"$failures_tsv"

echo "</details>" >> "$tmp"

cat "$tmp" >> "$output"
