# nmap-detections

[![lab](https://github.com/cyberdesserts/nmap-detections/actions/workflows/lab.yml/badge.svg)](https://github.com/cyberdesserts/nmap-detections/actions/workflows/lab.yml)

Nmap NSE checks for newly disclosed vulnerabilities, written and tested by [CyberDesserts](https://blog.cyberdesserts.com/). Each check ships with a reproducible lab and the results it was tested against.

Every check here is **detection only**. None sends an exploit, malformed input or anything intended to trigger the flaw it looks for.

## Scan your own servers

**Scan only systems you own or have written authorisation to test.** Scanning
someone else's infrastructure without permission is unlawful in many
jurisdictions, including under the UK Computer Misuse Act 1990. A detection
check is still a scan.

Two ways to run the same check. Option 1 needs Nmap and python3. Option 2
needs Nmap alone. Tested on Nmap 7.993.

**Option 1, the wrapper.** Clone the repository and run:

```sh
./scan.sh www.example.com                   # defaults to ports 80,443
./scan.sh www.example.com 80,443,8443       # pick the ports
./scan.sh 10.0.0.5 443 app.example.com      # scanning by IP, name the vhost
```

It prints a findings table, a summary and what to do next. It is only a
convenience wrapper around option 2.

**Option 2, Nmap on its own.** The check is one file with no dependencies
beyond Nmap itself, so this works anywhere Nmap runs:

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

Read the `State:` line, not the `VULNERABLE:` heading above it: Nmap's `vulns`
library prints UNKNOWN results under that heading too.

### Scan by hostname, not by IP

An IP address works, but it selects the server's default virtual host, and
HTTP/2 is set per virtual host. A scan by IP can therefore clear a host whose
other names are exposed. Measured against two virtual hosts on one address and
port, the default with HTTP/2 off and `app.example.com` with it on:

| How it was scanned | Result |
|---|---|
| By IP, no server name | NOT VULNERABLE |
| By IP, `--script-args tls.servername=app.example.com` | LIKELY VULNERABLE |

Same address, same port, opposite answers. The scan by IP missed the exposed
site. Scan each hostname you serve, or pass `tls.servername` when you have to
work from an address.

### Why `-Pn`

`-Pn` skips host discovery and scans the port regardless. Without it Nmap
probes the host first and reports "Host seems down" if those probes are
filtered, which is common on hardened and internet-facing servers. Against a
host that does answer it changes nothing and costs nothing: the same result in
the same time, measured on the lab. `scan.sh` passes it for you.

## Checks

| Check | Vulnerability | Type | Lab |
|---|---|---|---|
| [`nse/http-vuln-cve2026-123007.nse`](nse/http-vuln-cve2026-123007.nse) | nginx2root HTTP/2 flaws in NGINX Open Source: CVE-2026-123007 and CVE-2026-123633 | Nmap NSE | [`lab/nginx2root`](lab/nginx2root) |

## http-vuln-cve2026-123007.nse

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

The state is LIKELY VULNERABLE rather than VULNERABLE because the version comes from a banner. CVE-2026-123633 is never reported as LIKELY VULNERABLE, because two of its conditions cannot be checked from the network. The same upgrade fixes both.

Nmap's `vulns` library prints UNKNOWN results under a "VULNERABLE:" heading. Read the `State:` line, not the heading.

### Usage

Tested on Nmap 7.993. See [Scan your own servers](#scan-your-own-servers) for
the two ways to run it. Further options:

```sh
# Scanning by IP but need a specific virtual host
nmap -Pn -p 443 --script ./nse/http-vuln-cve2026-123007.nse \
  --script-args tls.servername=app.example.com 10.0.0.5

# A path other than / for the request that reads the Server header
nmap -Pn -p 443 --script ./nse/http-vuln-cve2026-123007.nse \
  --script-args http-vuln-cve2026-123007.path=/healthz www.example.com
```

To install it alongside the bundled scripts, copy it into your Nmap `scripts` directory and run `nmap --script-updatedb`.

Scan only systems you own or are authorised to test.

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

### Testing

[`lab/nginx2root`](lab/nginx2root) runs nine NGINX containers covering each branch of the table above. Results are kept in [`tests/`](tests).

## Licence

MIT. Free to use, modify and redistribute, with no warranty. See [LICENSE](LICENSE).

The scripts call Nmap's own libraries (`http`, `tls`, `vulns`, `shortport`) but contain no code copied from Nmap's bundled scripts.
