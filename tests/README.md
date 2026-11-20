# Test results

All results here are from **Nmap 7.993** (Homebrew, arm64) on macOS, against the nine NGINX containers in `lab/nginx2root`, every port bound to 127.0.0.1. Docker 29.8.0, Docker Compose v5.5.1. Run date: 20 November 2026.

Raw output: `lab-run-2026-11-20-run4-raw.txt`.

## Images

All four tags are on Docker Hub. Each was checked with `nginx -v` inside the image before the run.

| Tag | Cases |
|---|---|
| `nginx:1.31.8` | 1, 3, 4, 7, 8, 9 |
| `nginx:1.31.9` | 2 |
| `nginx:1.30.6` | 5 |
| `nginx:1.30.7` | 6 |

The 1.31.8 image is built with `--with-http_ssl_module`, `--with-http_v2_module` and `--with-http_v3_module`.

## Results

| Case | Port | NGINX | Config | CVE-2026-123007 expected | Actual | CVE-2026-123633 expected | Actual | Match |
|---|---|---|---|---|---|---|---|---|
| 1 | 8441 | 1.31.8 | TLS, HTTP/2 on | LIKELY VULNERABLE | LIKELY VULNERABLE | UNKNOWN | UNKNOWN | Yes |
| 2 | 8442 | 1.31.9 | TLS, HTTP/2 on | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | Yes |
| 3 | 8443 | 1.31.8 | TLS, HTTP/2 off | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | Yes |
| 4 | 8444 | 1.31.8 | TLS, HTTP/2 on, `server_tokens off` | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Yes |
| 5 | 8445 | 1.30.6 | TLS, HTTP/2 on | LIKELY VULNERABLE | LIKELY VULNERABLE | UNKNOWN | UNKNOWN | Yes |
| 6 | 8446 | 1.30.7 | TLS, HTTP/2 on | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | NOT VULNERABLE | Yes |
| 7 | 8080 | 1.31.8 | Cleartext, `http2 on` | LIKELY VULNERABLE | LIKELY VULNERABLE | UNKNOWN | UNKNOWN | Yes |
| 8 | 8448 | 1.31.8 | TLS, ECDHE AEAD ciphers only | LIKELY VULNERABLE | LIKELY VULNERABLE | UNKNOWN | UNKNOWN | Yes |
| 9 | 8449 | 1.31.8 | TLS 1.3 only | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Yes |

All nine matched. CVE-2026-123633 was reported LIKELY VULNERABLE zero times, because two of its conditions cannot be seen from the network (see below).

Detection-only properties checked against the script used: categories `{"vuln", "safe"}`; the only traffic is one HTTP GET, one TLS ClientHello, or the HTTP/2 connection preface with an empty SETTINGS frame. It compiles under `luac -p`.

### Notes on individual cases

- **Case 3** read the version as 1.31.8, found it in range, and saw HTTP/2 positively absent. An independent `openssl s_client -alpn h2,http/1.1` check agrees the port selects `http/1.1`. It did not reach NOT VULNERABLE by failing to read the banner.
- **Case 7.** With `listen 80` and `http2 on`, NGINX 1.31.8 serves HTTP/1.1 normally (so the `Server` header is readable) and answers an HTTP/2 prior-knowledge preface with a SETTINGS frame on stream 0 (`000018040000000000`). It ignores an `Upgrade: h2c` request and answers HTTP/1.1, so the script uses prior knowledge, not Upgrade.
- **Case 8** completed the handshake and read `h2` against a server that allows only ECDHE with AEAD ciphers.
- **Case 9** is TLS 1.3 only and does negotiate `h2`, but the script's TLS 1.2 ClientHello draws a `protocol_version` alert, so ALPN is never seen and the result is UNKNOWN. This is the documented TLS 1.3 limitation.

## The banner-only comparison

Case 1 (port 8441) has HTTP/2 on and is in range for CVE-2026-123007. Case 3 (port 8443) has HTTP/2 off and is not reachable through it. Both run 1.31.8. What `nmap -sV` reports for them on 7.993 is identical:

| Port | Case | HTTP/2 | product | version | CPE |
|---|---|---|---|---|---|
| 8441 | 1 | on | nginx | 1.31.8 | `cpe:/a:igor_sysoev:nginx:1.31.8` |
| 8443 | 3 | off | nginx | 1.31.8 | `cpe:/a:igor_sysoev:nginx:1.31.8` |

Diffing the two service records returns no differences. Any check that consumes only product, version and CPE must return the same verdict for both, so it is wrong about one of them. This script separates them because it reads ALPN on the port as well as the banner.

## Vendor wording, confirmed at source

F5 is the CNA for both CVEs. CVE-2026-123007 was read in F5 advisory K000163926. CVE-2026-123633 was read from the F5-assigned CVE record at `cveawg.mitre.org/api/cve/CVE-2026-123633`.

CVE-2026-123633, F5's wording:

> When NGINX Plus or NGINX Open Source is configured to use HTTP/2 for client connections and proxy client requests to a backend, a specially crafted request can result in use-after-free in the worker process, if this process is running low on worker_connections.

CVE-2026-123007 names no such conditions, only "configurations that use HTTP/2", which is why the two CVEs are reported differently.

Both records give CVSS 4.0 base 9.2 and CVSS 3.1 base 8.1, both with attack complexity High, and both state that code execution is possible "on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR".

Affected ranges in the records: `version 1.31.0, lessThan 1.31.9` and `version 1.30.0, lessThan 1.30.7`, with a floor of 1.9.5 (CVE-2026-123007) or 1.19.7 (CVE-2026-123633). `lessThan` is exclusive, giving 1.31.0 to 1.31.8 and up to 1.30.6, as the script uses.

## Not yet covered

- Real NGINX builds at the lower edges of the ranges (1.9.5 and 1.19.7).
- A TLS 1.3-only listener where HTTP/2 status could be read. That needs a TLS 1.3 ClientHello, which the script does not send.
- IPv6 targets, and NGINX behind a load balancer, CDN or WAF.
- NGINX Plus, OpenResty, Angie and other forks, which the script skips.
- Distribution packages with backported fixes, which report an affected upstream version.
- A 1.30.6 listener with `http2 off`, to pair with case 5 the way case 3 pairs with case 1.
