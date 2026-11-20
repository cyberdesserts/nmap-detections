#!/bin/sh
# Scan your own servers for the two nginx2root HTTP/2 flaws and print a
# summary. A convenience wrapper: it runs the same check as
#
#   nmap -sV -p <ports> --script nse/http-vuln-cve2026-123007.nse <target>
#
# and formats the result. The .nse script stands alone and needs nothing from
# this repository, so the nmap command above is always available instead.
#
# Usage:
#   ./scan.sh www.example.com
#   ./scan.sh www.example.com 80,443,8443
#   ./scan.sh 10.0.0.5 443 app.example.com   # scanning by IP, pick a vhost
#
# Scan by hostname where you can: HTTP/2 is set per site, so the name you send
# decides which site answers. Scan only systems you are authorised to test.
set -e
cd "$(dirname "$0")"

TARGET=$1
PORTS=${2:-80,443}
SERVERNAME=$3

if [ -z "$TARGET" ]; then
  echo "usage: $0 <target> [ports] [tls servername]" >&2
  echo "example: $0 www.example.com 80,443" >&2
  exit 2
fi

command -v nmap >/dev/null 2>&1 || { echo "nmap not found" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }

SCRIPT=nse/http-vuln-cve2026-123007.nse
[ -f "$SCRIPT" ] || { echo "$SCRIPT not found; run from the repository root" >&2; exit 1; }

ARGS=vulns.showall
[ -n "$SERVERNAME" ] && ARGS="$ARGS,tls.servername=$SERVERNAME"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Scanning $TARGET on $PORTS ..."
# -sV so the HTTP port rule matches non-standard ports and the banner is read.
nmap -Pn -sV --version-light \
  -p "$PORTS" \
  --script "$SCRIPT" --script-args "$ARGS" \
  -oX "$WORK/scan.xml" \
  "$TARGET" > "$WORK/scan.txt"

python3 lab/nginx2root/report.py "$WORK/scan.xml" - --full "$WORK/scan.txt"
