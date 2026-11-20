#!/bin/sh
# Checks that -Pn changes no result against a host that answers.
#
# The README tells people to pass -Pn, because without it Nmap probes the host
# first and reports "Host seems down" when those probes are filtered. That
# advice is only safe if -Pn does not change the answer when the host does
# reply. This scans the lab both ways and compares every state.
#
# Usage, from the repository root:
#   lab/check-pn.sh <script.nse> <cases.tsv>
#
# Timing is deliberately not asserted: it varies by machine and would make a
# flaky test. What matters is that the states are identical.
#
# Exits non-zero if any state differs. Needs Nmap and python3.
set -e
SCRIPT=$1
CASES=$2
[ -f "$SCRIPT" ] && [ -f "$CASES" ] || { echo "usage: $0 <script.nse> <cases.tsv>" >&2; exit 2; }
for tool in nmap python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Only the plainly scanned rows: the point is host discovery, not script args.
ARGCOL=$(awk -F'\t' '/^#case/ {for(i=1;i<=NF;i++) if($i=="args") print i; exit}' "$CASES")
PORTS=$(awk -F'\t' -v c="$ARGCOL" '!/^#/ && NF>1 {if (c=="" || $c=="") print $2}' "$CASES" | sort -un | paste -sd, -)

for MODE in with without; do
  [ "$MODE" = with ] && FLAG=-Pn || FLAG=
  # shellcheck disable=SC2086
  nmap $FLAG -n -sT -sV --version-light -p "$PORTS" \
    --script "$SCRIPT" --script-args vulns.showall \
    -oX "$WORK/$MODE.xml" 127.0.0.1 > /dev/null
done

python3 - "$WORK/with.xml" "$WORK/without.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET


def states(path):
    out = {}
    for port in ET.parse(path).getroot().iter("port"):
        pid = port.get("portid")
        for script in port.iter("script"):
            for tbl in script.findall("table"):
                key = tbl.get("key") or ""
                if key.startswith("CVE-"):
                    for elem in tbl.findall("elem"):
                        if elem.get("key") == "state":
                            out[(pid, key)] = (elem.text or "").strip()
    return out


a, b = states(sys.argv[1]), states(sys.argv[2])
keys = sorted(set(a) | set(b))
if not keys:
    sys.exit("no results from either scan; is the lab running?")
bad = [k for k in keys if a.get(k) != b.get(k)]
for port, cve in keys:
    mark = "DIFFERS" if (port, cve) in bad else "same"
    print("  %-6s %-16s %s" % (port, cve, mark))
print()
print("%d of %d results identical with and without -Pn." % (len(keys) - len(bad), len(keys)))
sys.exit(1 if bad else 0)
PY
