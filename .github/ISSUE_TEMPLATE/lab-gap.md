---
name: Result from a build the lab does not cover
about: Report what a check reported against an NGINX build, distribution or front end the lab has no case for
title: "Result: NGINX <version> on <platform>"
labels: results
---

**Target**

- NGINX version, from `nginx -v` on the host if you have access:
- How it was installed (distribution package, official nginx.org package, container, built from source):
- HTTP/2 on or off, and TLS or cleartext:
- Anything in front of it (CDN, load balancer, WAF), or none:

**Scan**

- Nmap version, from `nmap --version`:
- The exact command you ran:

**What the check reported**

Paste the output. Use `--script-args vulns.showall` so NOT VULNERABLE and UNKNOWN results appear.

**What you expected, and why**

If you know the host's real state, say how you know: the distribution's advisory, `nginx -T`, or a configuration you can see.

Scan only systems you own or are authorised to test. Do not paste hostnames or addresses you would rather not publish.
