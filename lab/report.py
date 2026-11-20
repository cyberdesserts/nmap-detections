#!/usr/bin/env python3
"""Turn an Nmap XML scan of the nginx2root lab into a formatted results file.

Reads the per-CVE state the vulns library writes into the XML, compares each
case with the expected result in cases.tsv, and prints a report. Standard
library only.

Usage: report.py <scan.xml> <cases.tsv> [--env env.txt] [--full output.txt]
"""

import hashlib
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

W = 70


def rule(ch="="):
    return ch * W


def read_cases(path):
    """Returns (cases, cve_columns). The last commented line before the rows is
    the header; every column whose name starts with CVE- is a verdict column."""
    cases, header = [], None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                header = line.lstrip("#").rstrip("\n").split("\t")
                continue
            if not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if header and len(parts) == len(header):
                cases.append(dict(zip(header, parts)))
    if not header:
        return [], []
    cves = [c for c in header if c.startswith("CVE-")]
    # the first four columns are case, port, version and config, whatever the
    # header calls them; alias them so the rest of this file can rely on it
    out = []
    for row in cases:
        vals = list(row.values())
        out.append(dict(row, case=vals[0], port=vals[1],
                        nginx=vals[2], config=vals[3]))
    return out, cves


def normalise(state):
    """'UNKNOWN (unable to test)' and 'UNKNOWN' are the same verdict."""
    return (state or "").replace("(unable to test)", "").strip()


def read_scan(path):
    """Return {port: {"service": str, "cpe": str, "states": {cve: state}}}."""
    root = ET.parse(path).getroot()
    found = {}
    for port in root.iter("port"):
        pid = port.get("portid")
        svc = port.find("service")
        entry = {"service": "", "cpe": "", "states": {}}
        if svc is not None:
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            entry["service"] = (product + " " + version).strip()
            cpe = svc.find("cpe")
            entry["cpe"] = cpe.text if cpe is not None else ""
        for script in port.iter("script"):
            # the vulns library writes one <table key="CVE-..."> per finding
            for tbl in script.findall("table"):
                key = tbl.get("key") or ""
                if not key.startswith("CVE-"):
                    continue
                for elem in tbl.findall("elem"):
                    if elem.get("key") == "state":
                        entry["states"][key] = normalise(elem.text)
        found[pid] = entry
    return found, root


def sha256(path):
    if not os.path.exists(path):
        return "not found"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def column_widths(rows, headers):
    return [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]


def render_table(headers, rows, indent="  "):
    widths = column_widths(rows, headers)
    out = []
    fmt = indent + "  ".join("%-" + str(w) + "s" for w in widths)
    out.append((fmt % tuple(headers)).rstrip())
    out.append(indent + "  ".join("-" * w for w in widths))
    for r in rows:
        out.append((fmt % tuple(str(c) for c in r)).rstrip())
    return "\n".join(out)


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: report.py <scan.xml> <cases.tsv> [--env f] [--full f]")
    xml_path, cases_path = sys.argv[1], sys.argv[2]
    env_path = full_path = None
    args = sys.argv[3:]
    for i, a in enumerate(args):
        if a == "--env" and i + 1 < len(args):
            env_path = args[i + 1]
        if a == "--full" and i + 1 < len(args):
            full_path = args[i + 1]

    findings_only = cases_path == "-"
    cases, cves = ([], []) if findings_only else read_cases(cases_path)
    scan, root = read_scan(xml_path)
    if findings_only:
        # no cases file: report every CVE the scan returned
        seen = []
        for p in scan:
            for c in scan[p]["states"]:
                if c not in seen:
                    seen.append(c)
        cves = sorted(seen)

    print(rule())
    print("nginx2root scan results" if findings_only else "nginx2root lab results")
    print("Generated %s" % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    print(rule())
    print()

    print("ENVIRONMENT")
    print("  %-22s %s" % ("Nmap", root.get("version") or "unknown"))
    if env_path and os.path.exists(env_path):
        with open(env_path, encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    print("  %-22s %s" % (k, v))
    args_line = root.get("args") or ""
    # drop the -oX temp path: it is scaffolding, not part of the record
    args_line = re.sub(r"\s-oX\s+\S+", "", args_line)
    print("  %-22s %s" % ("Scan arguments", args_line))
    print()

    if findings_only:
        rows = []
        for port in sorted(scan, key=lambda x: int(x)):
            st = scan[port]["states"]
            if not st:
                continue
            for cve in cves:
                rows.append([port, scan[port]["service"] or "unknown",
                             cve, st.get(cve, "no result")])
        print("FINDINGS")
        if rows:
            print(render_table(["port", "service", "cve", "state"], rows))
        else:
            print("  No port answered as NGINX Open Source with a readable banner.")
            print("  If NGINX is on a non-standard port, add -sV. A CDN, load balancer")
            print("  or WAF in front of NGINX replaces the banner, so scan the origin.")
        print()
        flagged = [r for r in rows if r[3].startswith("LIKELY")]
        unknown = [r for r in rows if r[3].startswith("UNKNOWN")]
        print("SUMMARY")
        print("  %d LIKELY VULNERABLE, %d UNKNOWN, across %d port(s)."
              % (len(flagged), len(unknown), len({r[0] for r in rows})))
        if flagged:
            print("  Upgrade to NGINX 1.30.7 (stable) or 1.31.9 (mainline), then RESTART.")
            print("  A configuration reload leaves the old binary running.")
            print("  Distribution packages may carry a backported fix without a version")
            print("  change: check your distribution's advisory before raising a finding.")
        if unknown:
            print("  UNKNOWN means a condition could not be seen from the network, not")
            print("  that the host is safe. Confirm on the host with nginx -v and nginx -T.")
        print()
        print("SERVICE DETECTION")
        svc_rows = [[p, scan[p]["service"], scan[p]["cpe"]]
                    for p in sorted(scan, key=lambda x: int(x))]
        if svc_rows:
            print(render_table(["port", "service", "cpe"], svc_rows))
        print()
        if full_path and os.path.exists(full_path):
            print(rule("-"))
            print("FULL NMAP OUTPUT")
            print(rule("-"))
            with open(full_path, encoding="utf-8", errors="replace") as fh:
                sys.stdout.write(fh.read())
        return 0

    rows, mismatches = [], []
    likely_123633 = 0
    for c in cases:
        got = scan.get(c["port"], {}).get("states", {})
        row = [c["case"], c["port"], c["nginx"], c["config"]]
        ok = True
        for cve in cves:
            expected = c[cve]
            actual = got.get(cve, "NO RESULT")
            row.extend([expected, actual])
            if actual != expected:
                ok = False
                mismatches.append((c["case"], c["port"], cve, expected, actual))
            if c.get(cve, "").startswith("UNKNOWN") and actual.startswith("LIKELY"):
                likely_123633 += 1
        row.append("yes" if ok else "NO")
        rows.append(row)

    headers = ["case", "port", "nginx", "config",
               "expect 123007", "actual 123007",
               "expect 123633", "actual 123633", "match"]
    print("RESULTS")
    print(render_table(headers, rows))
    print()

    print("SUMMARY")
    matched = sum(1 for r in rows if r[-1] == "yes")
    print("  %d of %d cases matched the expected results." % (matched, len(rows)))
    if likely_123633:
        print("  %d case(s) returned LIKELY VULNERABLE where UNKNOWN was expected." % likely_123633)
    if mismatches:
        print()
        print("  MISMATCHES")
        for case, port, cve, exp, act in mismatches:
            print("    case %s (port %s) %s: expected %s, got %s" % (case, port, cve, exp, act))
    print()

    print("SERVICE DETECTION")
    svc_rows = [[p, scan[p]["service"], scan[p]["cpe"]]
                for p in sorted(scan, key=lambda x: int(x))]
    print(render_table(["port", "service", "cpe"], svc_rows))
    print()

    if full_path and os.path.exists(full_path):
        print(rule("-"))
        print("FULL NMAP OUTPUT")
        print(rule("-"))
        with open(full_path, encoding="utf-8", errors="replace") as fh:
            sys.stdout.write(fh.read())

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
