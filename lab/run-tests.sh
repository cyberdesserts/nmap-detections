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
# Exits non-zero if any case does not match. Needs Nmap and python3.
set -e
SCRIPT=$1
CASES=$2
REPORT=$3
[ -f "$SCRIPT" ] && [ -f "$CASES" ] || { echo "usage: $0 <script.nse> <cases.tsv> [report.txt]" >&2; exit 2; }
for tool in nmap python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found" >&2; exit 1; }
done

PORTS=$(grep -v '^#' "$CASES" | awk -F'\t' 'NF>1 {print $2}' | paste -sd, -)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

nmap --version | head -1
echo "Scanning ports $PORTS on 127.0.0.1 with $SCRIPT"
# -sV so the HTTP port rule matches non-standard lab ports.
nmap -Pn -n -sT -sV --version-light -p "$PORTS" \
  --script "$SCRIPT" --script-args vulns.showall \
  -oX "$WORK/scan.xml" 127.0.0.1 > "$WORK/scan.txt"

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
  python3 "$(dirname "$0")/report.py" "$WORK/scan.xml" "$CASES" \
    --env "$WORK/env.txt" --full "$WORK/scan.txt" > "$REPORT" || true
  echo "Report written to $REPORT"
fi

python3 "$(dirname "$0")/check.py" "$WORK/scan.xml" "$CASES"
