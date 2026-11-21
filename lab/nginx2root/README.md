# nginx2root lab

Eleven NGINX containers giving twelve test cases for `nse/http-vuln-cve2026-123007.nse`: case 10 serves two virtual hosts from one container and is scanned twice. Ports bind to 127.0.0.1 only. Every container on an affected version is deliberately vulnerable, so keep it off any network you do not control.

Needs Docker, Nmap and python3. `lab/run-tests.sh` compares every case against `cases.tsv` and exits non-zero if any one does not match.

Run from the repository root:

```sh
cd lab/nginx2root && ./gen-cert.sh && docker compose up -d && cd -
lab/run-tests.sh nse/http-vuln-cve2026-123007.nse lab/nginx2root/cases.tsv
cd lab/nginx2root && docker compose down
```

| Case | Port | NGINX | Config | CVE-2026-123007 | CVE-2026-123633 |
|---|---|---|---|---|---|
| 1 | 8441 | 1.31.8 | TLS, HTTP/2 on | LIKELY VULNERABLE | UNKNOWN |
| 2 | 8442 | 1.31.9 | TLS, HTTP/2 on | NOT VULNERABLE | NOT VULNERABLE |
| 3 | 8443 | 1.31.8 | TLS, HTTP/2 off | NOT VULNERABLE | NOT VULNERABLE |
| 4 | 8444 | 1.31.8 | TLS, HTTP/2 on, `server_tokens off` | UNKNOWN | UNKNOWN |
| 5 | 8445 | 1.30.6 | TLS, HTTP/2 on | LIKELY VULNERABLE | UNKNOWN |
| 6 | 8446 | 1.30.7 | TLS, HTTP/2 on | NOT VULNERABLE | NOT VULNERABLE |
| 7 | 8080 | 1.31.8 | Cleartext, `http2 on` | LIKELY VULNERABLE | UNKNOWN |
| 8 | 8448 | 1.31.8 | TLS, ECDHE AEAD ciphers only | LIKELY VULNERABLE | UNKNOWN |
| 9 | 8449 | 1.31.8 | TLS 1.3 only | UNKNOWN | UNKNOWN |
| 10a | 8450 | 1.31.8 | Two vhosts, scanned by address | NOT VULNERABLE | NOT VULNERABLE |
| 10b | 8450 | 1.31.8 | Two vhosts, `tls.servername=app.example.com` | LIKELY VULNERABLE | UNKNOWN |
| 11 | 8451 | 1.31.8 | TLS, HTTP/2 on, proxies to a backend | LIKELY VULNERABLE | UNKNOWN |

## What each case covers

The check reads two conditions from the network:

1. Is the version in an affected range?
2. Is HTTP/2 on for the port and name scanned?

It reports **LIKELY VULNERABLE** only when both are met and both could be read. If a condition could be read and is not met, the answer is **NOT VULNERABLE**. If a condition could not be read at all, the answer is **UNKNOWN**.

### Both conditions readable

| Case | Version in range | HTTP/2 | Result |
|---|---|---|---|
| 1 | Yes, 1.31.8 | On | LIKELY VULNERABLE |
| 5 | Yes, 1.30.6 | On | LIKELY VULNERABLE |
| 7 | Yes, 1.31.8 | On, cleartext | LIKELY VULNERABLE |
| 8 | Yes, 1.31.8 | On | LIKELY VULNERABLE |
| 11 | Yes, 1.31.8 | On | LIKELY VULNERABLE |
| 3 | Yes, 1.31.8 | **Off** | NOT VULNERABLE |
| 2 | **No, 1.31.9 is fixed** | On | NOT VULNERABLE |
| 6 | **No, 1.30.7 is fixed** | On | NOT VULNERABLE |

The bold cell is the condition that fails. Case 3 fails on HTTP/2, cases 2 and 6 on the version.

### A condition cannot be read

| Case | What cannot be read | Result |
|---|---|---|
| 4 | The version. `server_tokens off` leaves the banner reading `nginx` with no number | UNKNOWN |
| 9 | HTTP/2. TLS 1.3 carries the chosen protocol in encrypted extensions, so ALPN is not visible | UNKNOWN |

UNKNOWN is not a clean bill of health. Case 9 does negotiate HTTP/2. The check cannot see it.

### The answer depends on how the port is scanned

| Case | How it was scanned | Result |
|---|---|---|
| 10a | By address, no server name | NOT VULNERABLE |
| 10b | With `tls.servername=app.example.com` | LIKELY VULNERABLE |

One container, two server blocks on one port: the default with HTTP/2 off, `app.example.com` with it on. The same port appears twice in `cases.tsv`, which is what its `args` column is for. `app.example.com` is a documentation name from RFC 2606 and never resolves, because NGINX selects the server block from the TLS server name extension rather than from DNS.

### Why these cases

**Case 3** is the one a version-only check misreports. Its banner is identical to case 1, so a check reading the version alone flags a port that neither CVE can be reached through.

**Cases 2 and 6** are the opposite control. Both run a fixed version with HTTP/2 on, so a check reporting whenever HTTP/2 is enabled would flag them.

**Case 5** covers the stable branch: 1.30.6 is the last affected stable release, where 1.31.8 is the last affected mainline one.

**Case 7** is cleartext. With `http2 on` and no TLS, NGINX 1.31.8 answers both HTTP/1.1 and an HTTP/2 prior-knowledge preface on the same port. It ignores `Upgrade: h2c`, so the check uses prior knowledge instead.

**Case 8** accepts only ECDHE with AEAD ciphers. The check sends its own cipher list rather than relying on the installed Nmap's default, so the handshake completes and ALPN is read.

## CVE-2026-123633

Wherever CVE-2026-123007 is LIKELY VULNERABLE, CVE-2026-123633 is UNKNOWN. It needs two conditions beyond the two the check reads: NGINX proxying to a backend, and a worker process short of `worker_connections`. Neither is visible to a client.

**Case 11 shows why that matters.** It is case 1 with one difference, a `proxy_pass` to a backend, so one of those further conditions is met. The check returns the same two states for both ports. A client cannot tell them apart, so reporting LIKELY VULNERABLE for CVE-2026-123633 would be a guess rather than a finding.

The conditions themselves come from F5, which assigned both CVEs. The wording is quoted in [`tests/`](../../tests).

## Images

If an image tag is missing from Docker Hub, build that version from the official source tarball at nginx.org and change `image:` in `docker-compose.yml`.

Recorded results are in [`tests/`](../../tests).
