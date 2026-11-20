# nginx2root lab

Nine NGINX containers, one per test case for `nse/http-vuln-cve2026-123007.nse`. Ports bind to 127.0.0.1 only. Every container on an affected version is deliberately vulnerable, so keep it off any network you do not control.

Needs Docker, Nmap and python3. `lab/run-tests.sh` compares every case against `cases.tsv` and exits non-zero if any one does not match.

Run from the repository root:

```sh
cd lab/nginx2root && ./gen-cert.sh && docker compose up -d && cd -
lab/run-tests.sh nse/http-vuln-cve2026-123007.nse lab/nginx2root/cases.tsv
cd lab/nginx2root && docker compose down
```

If an image tag is missing from Docker Hub, build that version from the official source tarball at nginx.org and change `image:` in `docker-compose.yml`.

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

CVE-2026-123633 is UNKNOWN wherever CVE-2026-123007 is LIKELY VULNERABLE, because it also needs proxy conditions the network cannot show. None of the lab configs proxy to a backend.

Case 3 is the one a version-only check gets wrong. Case 8 confirms the script's TLS handshake is accepted by a server that allows only ECDHE with AEAD ciphers.

Case 7: on a cleartext listener with `http2 on`, NGINX 1.31.8 answers both HTTP/1.1 and an HTTP/2 prior-knowledge preface on the same port. It ignores `Upgrade: h2c`, so the check uses prior knowledge. Recorded in [`tests/`](../../tests).
