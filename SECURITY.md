# Security policy

## What is in this repository

Detection checks only. Nothing here sends an exploit, malformed input or
anything intended to trigger the flaw it looks for. Each check states the
traffic it sends in its own header and in the README.

## Scanning authorisation

Scan only systems you own or have written authorisation to test. Scanning
someone else's infrastructure without permission is unlawful in many
jurisdictions, including under the UK Computer Misuse Act 1990.

## The lab is deliberately vulnerable

`lab/nginx2root` runs NGINX builds with known unpatched flaws. Every port binds
to 127.0.0.1 and nothing is exposed to a network. Do not change those bindings,
and do not run the lab on a host reachable from an untrusted network.

## Reporting a problem with a check

Open an issue describing what you scanned, what the check reported and what you
expected. Include the Nmap version and the target's NGINX version.

A check reporting the wrong state is a correctness bug, not a vulnerability, so
please report it in the open. If you believe something here is genuinely unsafe
to run, say so in the issue and leave out any detail that would help misuse it.
