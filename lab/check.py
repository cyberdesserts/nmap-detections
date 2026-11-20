#!/usr/bin/env python3
"""Compare an Nmap XML scan with the expected states in a cases file.

The cases file is tab separated. Its header line starts with "#case" and names
the columns: case, port, then any descriptive columns, then one column per
CVE (any column whose name starts with "CVE-"). Each row gives the state the
script should report for that CVE on that port.

Exit code 0 if every case matches, 1 if any does not. Standard library only.

Usage: check.py <scan.xml> <cases.tsv>
"""

import sys
import xml.etree.ElementTree as ET


def normalise(state):
    return (state or "").replace("(unable to test)", "").strip() or "NO OUTPUT"


def read_cases(path):
    header, rows = None, []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#case"):
                header = line.lstrip("#").split("\t")
            elif line.startswith("#") or not line.strip():
                continue
            else:
                rows.append(line.split("\t"))
    if header is None:
        sys.exit("cases file has no '#case' header line")
    cves = [h for h in header if h.startswith("CVE-")]
    return header, cves, [dict(zip(header, r)) for r in rows]


def read_states(path):
    states = {}
    for port in ET.parse(path).getroot().iter("port"):
        pid = port.get("portid")
        for script in port.iter("script"):
            for tbl in script.findall("table"):
                key = tbl.get("key") or ""
                if not key.startswith("CVE-"):
                    continue
                for elem in tbl.findall("elem"):
                    if elem.get("key") == "state":
                        states[(pid, key)] = normalise(elem.text)
    return states


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    _, cves, cases = read_cases(sys.argv[2])
    states = read_states(sys.argv[1])
    failed = 0
    widths = [6, 6] + [max(len(c), 18) for c in cves for _ in (0, 1)]
    head = ["case", "port"]
    for c in cves:
        head += ["expect " + c[-6:], "actual " + c[-6:]]
    print("  ".join(h.ljust(w) for h, w in zip(head + ["match"], widths + [5])))
    for row in cases:
        line, ok = [row["case"], row["port"]], True
        for c in cves:
            want = normalise(row.get(c))
            got = states.get((row["port"], c), "NO OUTPUT")
            line += [want, got]
            ok = ok and want == got
        failed += 0 if ok else 1
        print("  ".join(v.ljust(w) for v, w in zip(line + ["yes" if ok else "NO"], widths + [5])))
    print()
    print("%d of %d cases matched." % (len(cases) - failed, len(cases)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
