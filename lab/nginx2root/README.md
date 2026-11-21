# nginx2root lab

Ten NGINX containers giving eleven test cases for `nse/http-vuln-cve2026-123007.nse`: case 10 serves two virtual hosts from one container and is scanned twice. Ports bind to 127.0.0.1 only. Every container on an affected version is deliberately vulnerable, so keep it off any network you do not control.

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

## What each case covers

**Cases 1, 2, 3 and 6: the two conditions.** Case 1 is affected 1.31.8 with HTTP/2 on, so both conditions hold. Case 3 is the same version with HTTP/2 off, and case 6 is fixed 1.30.7 with HTTP/2 on, so each drops one condition. Case 2 is fixed 1.31.9 on the mainline branch.

Case 3 is the one a version-only check misreports. Its banner is identical to case 1, so a check reading the version alone flags a port that neither CVE can be reached through.

**Case 4: hidden version.** `server_tokens off` leaves the banner reading `nginx` with no number, so the version cannot be placed in or out of range.

**Case 5: the stable branch.** 1.30.6 is the last affected stable release, where 1.31.8 is the last affected mainline one.

**Case 7: cleartext.** With `http2 on` and no TLS, NGINX 1.31.8 answers both HTTP/1.1 and an HTTP/2 prior-knowledge preface on the same port. It ignores `Upgrade: h2c`, so the check uses prior knowledge instead.

**Case 8: modern ciphers.** The server accepts only ECDHE with AEAD ciphers. The check's own cipher list is accepted, so the ALPN answer is read.

**Case 9: TLS 1.3 only.** The protocol chosen by ALPN travels in encrypted extensions, so the check cannot see it and reports UNKNOWN. The port does negotiate HTTP/2.

**Case 10: virtual hosts.** One container, two server blocks on one port: the default with HTTP/2 off, `app.example.com` with it on. Scanned by address the default answers; scanned with `tls.servername` the named one does. The same port appears twice in `cases.tsv`, which is what its `args` column is for. `app.example.com` is a documentation name from RFC 2606 and never resolves, because NGINX selects the server block from the TLS server name extension rather than from DNS.

## CVE-2026-123633

Wherever CVE-2026-123007 is LIKELY VULNERABLE, CVE-2026-123633 is UNKNOWN. It needs two further conditions that a scan cannot see: NGINX proxying to a backend, and a worker process short of `worker_connections`. No config here proxies to a backend.

## Images

If an image tag is missing from Docker Hub, build that version from the official source tarball at nginx.org and change `image:` in `docker-compose.yml`.

Recorded results are in [`tests/`](../../tests).
