# Contributing

## Results from builds the lab does not cover

The most useful contribution. The lab covers nine cases on four NGINX versions.
Results from other builds, other distributions or NGINX behind a front end are
welcome as issues. Include the Nmap version, the NGINX version, how the port is
configured, and what the check reported.

## Changing a check

Every check is detection only. A change that sends malformed input, or anything
intended to trigger the flaw, will not be merged. Keep `categories` as
`{"vuln", "safe"}`.

Before opening a pull request (needs Docker, Nmap and python3):

1. Start the lab and run the checks, from the repository root:

   ```sh
   cd lab/nginx2root && ./gen-cert.sh && docker compose up -d && cd -
   lab/run-tests.sh nse/http-vuln-cve2026-123007.nse lab/nginx2root/cases.tsv
   ```

2. `lab/run-tests.sh` exits non-zero if any case does not match its cases file. It must exit zero.
   A third argument writes a full report to that path, which is what goes in `tests/` when recording a run.
3. If you change what a case should report, change `cases.tsv` and
   `lab/nginx2root/README.md` together, and say why in the pull request.
4. `docker compose down` when you are finished.

## Adding a check

A new check needs a lab with a case for every state it can report, including
the negative ones, and a results file in `tests/`.
