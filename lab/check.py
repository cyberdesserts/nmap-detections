#!/usr/bin/env python3
"""Compare Nmap XML scans with the expected states in a cases file.

The cases file is tab separated. Its header line starts with "#case" and names
the columns: case, port, then any descriptive columns, then one column per
CVE (any column whose name starts with "CVE-"). Each row gives the state the
script should report for that CVE on that port.

An optional last column named "args" carries extra --script-args for that row.
Rows sharing an args value are scanned together, so the same port can appear
more than once with different arguments. That is how a virtual host case is
expressed: one row scanned plainly, one scanned with tls.servername.

The manifest is tab separated, one line per scan: <scan.xml> <args>, where
args is empty for the plain scan. run-tests.sh writes it.

Exit code 0 if every case matches, 1 if any does not. Standard library only.

Usage: check.py <cases.tsv> <manifest.tsv>
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
    cases = []
    for r in rows:
        # a row may omit the trailing args column
        r = r + [""] * (len(header) - len(r))
        cases.append(dict(zip(header, r)))
    return cves, cases


def read_states(xml_path, args):
    """Returns {(args, port, cve): state} for one scan."""
    states = {}
    for port in ET.parse(xml_path).getroot().iter("port"):
        pid = port.get("portid")
        for script in port.iter("script"):
            for tbl in script.findall("table"):
                key = tbl.get("key") or ""
                if not key.startswith("CVE-"):
                    continue
                for elem in tbl.findall("elem"):
                    if elem.get("key") == "state":
                        states[(args, pid, key)] = normalise(elem.text)
    return states


def read_manifest(path):
    scans = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            scans.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return scans


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    cves, cases = read_cases(sys.argv[1])
    states = {}
    for xml_path, args in read_manifest(sys.argv[2]):
        states.update(read_states(xml_path, args))

    show_args = any(c.get("args") for c in cases)
    head = ["case", "port"]
    widths = [max(6, max(len(c["case"]) for c in cases)), 6]
    if show_args:
        head.append("scan args")
        widths.append(max(9, max(len(c.get("args", "")) or 4 for c in cases)))
    for c in cves:
        head += ["expect " + c[-6:], "actual " + c[-6:]]
        widths += [18, 18]
    print("  ".join(h.ljust(w) for h, w in zip(head + ["match"], widths + [5])))

    failed = 0
    for row in cases:
        args = row.get("args", "")
        line = [row["case"], row["port"]]
        if show_args:
            line.append(args or "none")
        ok = True
        for c in cves:
            want = normalise(row.get(c))
            got = states.get((args, row["port"], c), "NO OUTPUT")
            line += [want, got]
            ok = ok and want == got
        failed += 0 if ok else 1
        print("  ".join(v.ljust(w) for v, w in
                        zip(line + ["yes" if ok else "NO"], widths + [5])))
    print()
    print("%d of %d cases matched." % (len(cases) - failed, len(cases)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
