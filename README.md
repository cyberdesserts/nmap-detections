# nmap-detections

[![lab](https://github.com/cyberdesserts/nmap-detections/actions/workflows/lab.yml/badge.svg)](https://github.com/cyberdesserts/nmap-detections/actions/workflows/lab.yml) [![scope: detection only](https://img.shields.io/badge/scope-detection%20only-informational)](SECURITY.md) [![licence: MIT](https://img.shields.io/github/license/cyberdesserts/nmap-detections)](LICENSE) [![article](https://img.shields.io/badge/article-how%20this%20was%20built-informational)](https://blog.cyberdesserts.com/write-nmap-nse-vulnerability-script/)

Nmap NSE checks for newly disclosed vulnerabilities, written and tested by [CyberDesserts](https://blog.cyberdesserts.com/). Each check ships with a reproducible lab and the results it was tested against.

The first check covers the nginx2root HTTP/2 flaws in NGINX, and it is also the worked example: a vulnerability whose exploitability depends on configuration, not just on a version number. The lab, the template and the test record all exist to show how a check for that kind of flaw is built and proved. [Write Your Own Nmap Vulnerability Script](https://blog.cyberdesserts.com/write-nmap-nse-vulnerability-script/) walks through building this one from the advisory up.

Every check here is **detection only**. None sends an exploit, malformed input or anything intended to trigger the flaw it looks for.

**Three things you can do here:**

| | What | Who it is for |
|---|---|---|
| **1** | [Scan your own servers](#1-scan-your-own-servers) | Run a check against your own infrastructure, now |
| **2** | [Learn how a check works](#2-learn-how-a-check-works) | Spin up deliberately vulnerable containers and watch the check decide |
| **3** | [Write a check for another CVE](#3-write-a-check-for-another-cve) | Start from a template and its lab skeleton |

Reference material for the check published so far is in [the check in detail](#the-check-in-detail).

---

## 1. Scan your own servers

**Scan only systems you own or have written authorisation to test.** Scanning someone else's infrastructure without permission is unlawful in many jurisdictions, including under the UK Computer Misuse Act 1990. A detection check is still a scan.

Two ways to run the same check. Option A needs Nmap and python3; option B needs Nmap alone. Tested on Nmap 7.993, and on 7.98 in continuous integration.

### Option A: the wrapper

Clone the repository, then:

```sh
./scan.sh www.example.com                   # defaults to ports 80,443
./scan.sh www.example.com 80,443,8443       # pick the ports
./scan.sh 10.0.0.5 443 app.example.com      # scanning by address, name the vhost
```

It prints a findings table, a summary and what to do next.

### Option B: Nmap on its own

The check is one file with no dependencies beyond Nmap, so this works anywhere Nmap runs:

```sh
curl -O https://raw.githubusercontent.com/cyberdesserts/nmap-detections/main/nse/http-vuln-cve2026-123007.nse

# standard ports
nmap -Pn -p 80,443 --script ./http-vuln-cve2026-123007.nse www.example.com

# show NOT VULNERABLE and UNKNOWN results too
nmap -Pn -p 443 --script ./http-vuln-cve2026-123007.nse \
  --script-args vulns.showall www.example.com

# non-standard ports need -sV so the HTTP port rule matches
nmap -Pn -sV -p 8443 --script ./http-vuln-cve2026-123007.nse www.example.com
```

### Reading the result

Read the `State:` line, **not** the `VULNERABLE:` heading above it. Nmap's `vulns` library prints UNKNOWN results under that heading too.

| State | What it means and what to do |
|---|---|
| LIKELY VULNERABLE | Affected version, and HTTP/2 negotiated on this port and name. Upgrade to 1.30.7 or 1.31.9 and **restart**: a reload leaves the old binary running. Check your distribution's advisory first, since backported fixes keep the old version string |
| NOT VULNERABLE | Fixed version, or HTTP/2 not offered for the name scanned. Other names on the same port can differ |
| UNKNOWN | A condition could not be seen from the network. Not a clean bill of health: confirm on the host with `nginx -v` and `nginx -T` |

CVE-2026-123633 is never reported LIKELY VULNERABLE, because two of its conditions are invisible to a scan. The same upgrade fixes both CVEs.

### What LIKELY VULNERABLE does not tell you

It confirms two things: the banner reports an affected version, and HTTP/2 is live on the port and name scanned. It does not tell you the host can be exploited.

- **The version came from a banner.** Debian, Ubuntu and others backport fixes without changing it, so a patched package still reports an affected version. Check your distribution's advisory before raising a finding.
- **Reaching the flaw is not the same as exploiting it.** F5 gives the impact of CVE-2026-123007 as a crash of the NGINX worker process, or corruption of its memory. Code execution is possible only "on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR".
- **CVE-2026-123633 needs more than the check can see**, and no scan can see it: NGINX proxying to a backend, and a worker process running short of `worker_connections`.

Read LIKELY VULNERABLE as "this host is in scope for the patch", not as "this host is exploitable today".

### Getting an accurate answer

**Scan by hostname, not by address.** An address works, but it selects the server's default virtual host, and HTTP/2 is set per virtual host. Measured against two virtual hosts on one address and port, the default with HTTP/2 off and `app.example.com` with it on:

| How it was scanned | Result |
|---|---|
| By address, no server name | NOT VULNERABLE |
| By address, `--script-args tls.servername=app.example.com` | LIKELY VULNERABLE |

Same address, same port, opposite answers: the scan by address missed the exposed site. Scan each hostname you serve, or pass `tls.servername` when you only have an address.

**Pass `-Pn`.** It skips host discovery and scans the port regardless. Without it Nmap probes the host first and reports "Host seems down" when those probes are filtered, which is common on hardened and internet-facing servers. It changes no result, only whether the scan happens at all. `scan.sh` passes it for you.

**Scan the origin, not what sits in front of it.** A CDN, load balancer or WAF supplies its own banner and terminates TLS, so the check would be reading the front end rather than NGINX.

---

## 2. Learn how a check works

[`lab/nginx2root`](lab/nginx2root) runs **eleven deliberately vulnerable NGINX containers**, giving **twelve test cases**: one container serves two virtual hosts and is scanned twice, once by address and once with a server name.

The check reports LIKELY VULNERABLE only when two things hold at once: the version is in an affected range, and HTTP/2 is on for the port and name scanned. The lab isolates each one.

**Cases 1 and 3** run the same version, 1.31.8, and differ only in HTTP/2. They return LIKELY VULNERABLE and NOT VULNERABLE. `nmap -sV` reports identical product, version and CPE for both, so a check reading the version alone must give them the same answer and is wrong about one.

**Cases 1 and 2** both have HTTP/2 on and differ only in the fix, 1.31.8 against 1.31.9 on the same mainline branch. They return LIKELY VULNERABLE and NOT VULNERABLE, so the check is not just reporting that HTTP/2 is enabled. Cases 5 and 6 are the same pair on the stable branch, 1.30.6 against 1.30.7.

The remaining cases cover what a scan cannot resolve:

- a hidden version
- a TLS 1.3 listener that conceals the protocol choice
- a port whose answer depends on which virtual host is addressed
- a host that proxies to a backend, which reports the same as one that does not

```sh
cd lab/nginx2root && ./gen-cert.sh && docker compose up -d && cd -
lab/run-tests.sh nse/http-vuln-cve2026-123007.nse lab/nginx2root/cases.tsv
cd lab/nginx2root && docker compose down
```

The expected result for every case is in [`lab/nginx2root/cases.tsv`](lab/nginx2root/cases.tsv), and the command exits non-zero if any case disagrees with it. Recorded results, including what the same ports look like to a version-only check, are in [`tests/`](tests).

Needs Docker, Nmap and python3. Every port binds to 127.0.0.1, and the containers run unpatched builds, so keep them off any network you do not control.

---

## 3. Write a check for another CVE

[`templates/`](templates) holds a check template with four marked edit blocks, a four-case lab skeleton that needs no certificate, and the four questions an advisory has to answer before a network check is possible at all.

---

## Checks

| Check | Vulnerability | Type | Lab |
|---|---|---|---|
| [`nse/http-vuln-cve2026-123007.nse`](nse/http-vuln-cve2026-123007.nse) | nginx2root HTTP/2 flaws in NGINX Open Source: CVE-2026-123007 and CVE-2026-123633 | Nmap NSE | [`lab/nginx2root`](lab/nginx2root) |

## The check in detail

### What it checks

F5 fixed CVE-2026-123007 (memory corruption in HTTP/2 flow control) and CVE-2026-123633 (use-after-free in HTTP/2) on 18 November 2026. Both are fixed in NGINX Open Source 1.30.7 (stable) and 1.31.9 (mainline).

| CVE | Affected NGINX Open Source |
|---|---|
| CVE-2026-123007 | 1.9.5 to 1.30.6, and 1.31.0 to 1.31.8 |
| CVE-2026-123633 | 1.19.7 to 1.30.6, and 1.31.0 to 1.31.8 |

Both flaws are reachable only where HTTP/2 is enabled. A version banner alone flags every affected server, including the ones with HTTP/2 switched off. CVE-2026-123633 also needs NGINX to be proxying requests to a backend with a worker process running short of `worker_connections`, which cannot be seen from the network. This check tests the two conditions that can be seen:

1. **Version.** Reads the NGINX version from the `Server` header.
2. **HTTP/2.** On TLS ports, offers `h2` and `http/1.1` in a TLS 1.2 ClientHello and reads which protocol the server selects (ALPN). On cleartext ports, sends the HTTP/2 connection preface and looks for a SETTINGS frame in reply (h2c with prior knowledge).

| Version in range | HTTP/2 | CVE-2026-123007 | CVE-2026-123633 |
|---|---|---|---|
| Yes | Negotiated | LIKELY VULNERABLE | UNKNOWN (proxy conditions not visible) |
| Yes | Not offered | NOT VULNERABLE (on this port and name) | NOT VULNERABLE (on this port and name) |
| Yes | Could not tell | UNKNOWN | UNKNOWN |
| Hidden | Negotiated or could not tell | UNKNOWN | UNKNOWN |
| No | Any | NOT VULNERABLE | NOT VULNERABLE |

The state is LIKELY VULNERABLE rather than VULNERABLE because the version comes from a banner.

### Further options

```sh
# Scanning by address but need a specific virtual host
nmap -Pn -p 443 --script ./nse/http-vuln-cve2026-123007.nse \
  --script-args tls.servername=app.example.com 10.0.0.5

# A path other than / for the request that reads the Server header
nmap -Pn -p 443 --script ./nse/http-vuln-cve2026-123007.nse \
  --script-args http-vuln-cve2026-123007.path=/healthz www.example.com
```

To install it alongside the bundled scripts, copy it into your Nmap `scripts` directory and run `nmap --script-updatedb`.

### Limitations

- **Backported fixes.** Distribution packages often patch without changing the upstream version string. A patched Debian or Ubuntu build can still report LIKELY VULNERABLE. Check the distribution's own advisory for the package version.
- **Hidden version.** With `server_tokens off` the banner reads `nginx` with no version. The check reports UNKNOWN when HTTP/2 is on, rather than guessing.
- **Other products.** NGINX Plus, OpenResty, Angie and other forks use their own version schemes and are skipped. A load balancer or CDN in front of NGINX replaces the banner and the TLS endpoint, so the check sees the front end, not the origin.
- **Virtual hosts.** HTTP/2 is set per server block. A NOT VULNERABLE result applies to the name tested; other names on the same port may have HTTP/2 on.
- **TLS 1.3 only.** In TLS 1.3 the selected ALPN protocol travels in encrypted extensions. Against a TLS 1.3-only listener the HTTP/2 status is UNKNOWN.
- **h2c.** Cleartext HTTP/2 is detected by prior knowledge (tested on NGINX 1.31.8). NGINX ignores an `Upgrade: h2c` request, so the check does not use one.
- **CVE-2026-123633 conditions.** Proxying to a backend and `worker_connections` pressure cannot be seen from the network, so this CVE is reported UNKNOWN rather than LIKELY VULNERABLE.
- **Other nginx2root CVEs.** CVE-2026-121810 (HTTP/3), CVE-2026-123634 (resolver) and CVE-2026-113425 (mail proxy) depend on configuration that is not visible from the network in the same way and are not checked.

Patching needs a full restart of NGINX. A configuration reload leaves the vulnerable binary running.

## Licence

MIT. Free to use, modify and redistribute, with no warranty. See [LICENSE](LICENSE).
