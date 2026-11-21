# Templates: version plus condition

A starting point for writing your own detection check when a new CVE lands without one. It follows the pattern used by `nse/http-vuln-cve2026-123007.nse`: read the product version, test a condition the flaw needs, and report one of three states per CVE.

A check built from this template reads two things, and reports **LIKELY VULNERABLE** only when both are met and both could be read:

1. Is the version in an affected range?
2. Is the condition the flaw needs present?

| State | When |
|---|---|
| LIKELY VULNERABLE | Both read, both met |
| NOT VULNERABLE | Both read, at least one not met |
| UNKNOWN | Either could not be read, or the CVE needs a further condition the network cannot show |

UNKNOWN says the check could not answer, not that the host is safe.

Everything here is detection only. A condition probe must observe the condition without sending anything that could trigger the flaw. If the only way to test a condition is to send the input that triggers the bug, that is an exploit, not a check: report the version and UNKNOWN instead.

## What is here

| File | What it is |
|---|---|
| `templates/http-vuln-version-condition.nse` | The check template, filled in with the nginx2root values so it can be tested |
| `templates/lab/docker-compose.yml` | A four-case lab skeleton: affected with the condition on, affected with it off, fixed, version hidden |
| `templates/lab/conf/` | The NGINX configs the skeleton uses to switch the condition on and off |
| `templates/lab/cases.tsv` | Expected results for the skeleton, one row per case, one column per CVE |

The test harness is not here. `lab/run-tests.sh` and `lab/check.py` serve every lab in this repository, including this skeleton.

## Before you start: four questions

The vendor advisory or CVE record needs to answer all four. Each answer is one edit in the template.

| Question | Edit |
|---|---|
| How does the product identify itself on the network, and what does its version string look like? | `EDIT 1`: `VERSION_PATTERN` and `PRODUCT_ONLY_PATTERN` |
| Which versions are affected, and which fix each branch? | `EDIT 2`: `ranges` per CVE, as `{first affected, first fixed}` pairs |
| What condition does the flaw need: a feature on, a module loaded, a setting? | `EDIT 3`: the `condition()` function, returning true, false or nil |
| Which conditions can a client see without triggering the flaw? | `EDIT 2`: set `unseen` on any CVE that also needs conditions the network cannot show. It will then stop at UNKNOWN |

`EDIT 4` is the check's name, author and references.

If the advisory only says "versions before X", the check can only ever be a version match. Leave `condition()` returning `nil`, and every in-range result will be UNKNOWN, which is the honest answer.

## Workflow

1. Copy `http-vuln-version-condition.nse` to `nse/http-vuln-cveYYYY-NNNNN.nse` and work through the four EDIT blocks.
2. Copy `templates/lab/` to `lab/<name>/`. Set the images to the product's vulnerable and fixed builds and the configs to switch the condition on and off. Add a case for every result the check can return.
3. Write the expected state for every case in `lab/<name>/cases.tsv` before running anything.
4. Start the lab and run the check against it:

   ```sh
   cd lab/<name> && docker compose up -d && cd -
   lab/run-tests.sh nse/http-vuln-cveYYYY-NNNNN.nse lab/<name>/cases.tsv
   ```

5. Fix the script, not the expectations, until every case matches. Change an expectation only when the vendor's own data says it was wrong.

Two cases belong in every lab, because between them they pin down both halves of the check:

- **Affected version, condition switched off.** A version-only check flags this host; yours should not. This is the false positive the condition test exists to avoid.
- **Fixed version, condition switched on.** Both checks clear this host. It proves yours is reading the version too, rather than reporting whenever the condition is present.

## Testing the template itself

As shipped, the template holds the nginx2root values, so it must give the same results as the published check on the nginx2root lab:

```sh
cd lab/nginx2root && ./gen-cert.sh && docker compose up -d && cd -
lab/run-tests.sh templates/http-vuln-version-condition.nse lab/nginx2root/cases.tsv
```

And on its own four-case skeleton:

```sh
cd templates/lab && docker compose up -d && cd -
lab/run-tests.sh templates/http-vuln-version-condition.nse templates/lab/cases.tsv
```

Both runs, and the published check against the nginx2root lab, run in CI on
every push, so the template cannot drift away from the check it is modelled
on without the build failing.

Scan only systems you own or are authorised to test.
