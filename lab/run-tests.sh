#!/bin/sh
# Runs a check against every case in a cases file and compares the results.
# Start the lab first (docker compose up -d in the lab's directory).
#
# Usage:
#   lab/run-tests.sh <script.nse> <cases.tsv> [report.txt]
#
# With a third argument it also writes a full report there: environment,
# results table, service detection and the complete Nmap output. That is the
# file to keep in tests/ when recording a run.
#
# Examples, from the repository root:
#   lab/run-tests.sh nse/http-vuln-cve2026-123007.nse lab/nginx2root/cases.tsv
#   lab/run-tests.sh nse/my-new-check.nse lab/my-new-lab/cases.tsv
#   lab/run-tests.sh templates/http-vuln-version-condition.nse templates/lab/cases.tsv
#
# If the cases file has an "args" column, rows are grouped by its value and
# scanned once per group, so the same port can be tested with and without
# extra --script-args. Rows with no args are scanned plainly.
#
# Exits non-zero if any case does not match. Needs Nmap and python3.
set -e
SCRIPT=$1
CASES=$2
REPORT=$3
[ -f "$SCRIPT" ] && [ -f "$CASES" ] || { echo "usage: $0 <script.nse> <cases.tsv> [report.txt]" >&2; exit 2; }
for tool in nmap python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

nmap --version | head -1

# Which column holds the extra arguments, if any.
ARGCOL=$(awk -F'\t' '/^#case/ {for(i=1;i<=NF;i++) if($i=="args") print i; exit}' "$CASES")

# One scan per distinct args value. Empty args first, so the plain scan leads.
if [ -n "$ARGCOL" ]; then
  awk -F'\t' -v c="$ARGCOL" '!/^#/ && NF>1 {print ($c=="" ? "-" : $c)}' "$CASES" | sort -u > "$WORK/groups"
else
  echo "-" > "$WORK/groups"
fi

: > "$WORK/manifest.tsv"
N=0
# read line by line: an args value may contain commas, so never word split
while IFS= read -r GROUP; do
  [ -n "$GROUP" ] || continue
  N=$((N + 1))
  if [ "$GROUP" = "-" ]; then
    EXTRA=""
    PORTS=$(awk -F'\t' -v c="$ARGCOL" '!/^#/ && NF>1 {if (c=="" || $c=="") print $2}' "$CASES" | sort -un | paste -sd, -)
  else
    EXTRA=",$GROUP"
    PORTS=$(awk -F'\t' -v c="$ARGCOL" -v g="$GROUP" '!/^#/ && NF>1 && $c==g {print $2}' "$CASES" | sort -un | paste -sd, -)
  fi
  [ -n "$PORTS" ] || continue
  echo "Scanning ports $PORTS on 127.0.0.1 with $SCRIPT${EXTRA:+ (args: $GROUP)}"
  # -sV so the HTTP port rule matches non-standard lab ports.
  nmap -Pn -n -sT -sV --version-light -p "$PORTS" \
    --script "$SCRIPT" --script-args "vulns.showall$EXTRA" \
    -oX "$WORK/scan-$N.xml" 127.0.0.1 > "$WORK/scan-$N.txt"
  printf '%s\t%s\n' "$WORK/scan-$N.xml" "$([ "$GROUP" = "-" ] && echo "" || echo "$GROUP")" >> "$WORK/manifest.tsv"
done < "$WORK/groups"

if [ -n "$REPORT" ]; then
  {
    printf 'Docker=%s\n' "$(docker --version 2>/dev/null | sed 's/^Docker version //;s/,.*//')"
    printf 'Host=%s %s %s\n' "$(uname -s)" "$(uname -r)" "$(uname -m)"
    printf 'Check=%s\n' "$SCRIPT"
    if command -v shasum >/dev/null 2>&1; then
      printf 'Check sha256=%s\n' "$(shasum -a 256 "$SCRIPT" | cut -d' ' -f1)"
    elif command -v sha256sum >/dev/null 2>&1; then
      printf 'Check sha256=%s\n' "$(sha256sum "$SCRIPT" | cut -d' ' -f1)"
    fi
    printf 'Cases=%s\n' "$CASES"
  } > "$WORK/env.txt"
  cat "$WORK"/scan-*.txt > "$WORK/scan-all.txt"
  # exit 1 means a case mismatched, which check.py reports below; anything
  # else is a real failure and must not be swallowed
  python3 "$(dirname "$0")/report.py" "$WORK/manifest.tsv" "$CASES" \
    --env "$WORK/env.txt" --full "$WORK/scan-all.txt" > "$REPORT" || RC=$?
  if [ "${RC:-0}" -gt 1 ]; then
    echo "report.py failed with exit ${RC}" >&2
    exit "$RC"
  fi
  echo "Report written to $REPORT"
fi

python3 "$(dirname "$0")/check.py" "$CASES" "$WORK/manifest.tsv"
