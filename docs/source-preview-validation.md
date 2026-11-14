# Source-preview validation — 2026-11-14

Scope: experimental **0.1.0-preview.1**, source-only. The reviewed working tree
is based on sanitized `main` commit `96ff559`; the preview changes are not yet
committed. These results do not establish appliance-image acceptance.

## PASS

- Apache 2.0 license text verified against the Apache Software Foundation's
  canonical text after whitespace normalization. `NOTICE` names the approved
  copyright holder, Lawrence Wagle Jr. The four licensing guides agree; see
  [third-party source review](third-party-notices.md).
- All supported application and payload commands listed in
  [source-preview scope](source-preview.md) passed on Python **3.14.4** and
  Node.js **22.22.1**: **269 Python checks and 42 browser checks**. The distinct
  cross-identity permission case was skipped and is BLOCKED below, not passed.
- Four additional manifest checks in `tests/image/test-offline-inputs.py`
  passed without a cache. Its cache-dependent integration class was skipped;
  no genuine cache-integration result is claimed.
- The documented `dashboard/server.py --demo` command passed an isolated smoke
  check: page, session, overview and AI-disabled status returned successfully,
  and the listener bound only to loopback inside the private network namespace.
- Regression coverage includes lossless Pi-hole binary text, deadline-safe
  batches, genuine I/O errors, gzip cleanup/restart/retry without evidence loss,
  incomplete transfers, real synthetic SQLite WAL readers on every exit path,
  catch-up gating, completed device snapshots, and rsync rotation/mode behavior.
- Python files parse with the Python 3.13 grammar. This is a syntax check only.
- Publication files and every stored Git object were reviewed for credential
  patterns, known private deployment markers, artifact paths and attribution.
  No credential token, complete private key, operational database/log/archive,
  unwanted binary or known private deployment marker was detected. Manual
  matches are fictional fixtures, generic addresses/ranges, example commit
  identities and a key-header format check. Unknown private strings remain a
  limitation of the review.
- Local publication file permissions were normalized to `0644`, or `0755` for
  existing Git executables; source directories use `0755`. The checkout root
  remains private. Git represents the executable bit, not group-write bits:
  correcting local `0664` files therefore creates no Git mode change.

## Isolation used

Only reviewed files were exported to a disposable source directory, with no Git
directory, private deployment state or operational evidence. Bubblewrap provided
private user, mount, network, PID, IPC and UTS namespaces. The runtime had a
read-only source mount and `/usr`, zero effective capabilities, only a loopback
interface, no IPv4 routes, an empty home and temporary directory, and synthetic
passwd/group/NSS/hosts files. Host home directories, credentials and service
sockets were absent. The boundary was audited before any source suite ran.

The Codex execution sandbox initially denied namespace creation. The same
namespace isolation was established through the approved external execution
path; no kernel policy, trusted tool, guard, test or namespace requirement was
changed. Raw validation logs, hash inventories and scratch exports remain under
the ignored `reports/` tree and are excluded from publication.

## BLOCKED

| Check | Current reason | Requirement to finish |
| --- | --- | --- |
| Python 3.13 runtime compatibility | Interpreter unavailable in the checked runtime locations | Run the supported source commands on Python 3.13 in the same isolated environment before claiming support. |
| Distinct publisher/collector discretionary access | Only one usable mapped identity; no supported additional UID mapping | Run the documented synthetic DAC case on a disposable host with real distinct mapped identities. Same-UID rsync metadata checks do not substitute. |
| Strict installer lifecycle harness | Original harness fails writing `/proc/self/uid_map` with `Operation not permitted` | Use a supported host on which the unchanged harness can establish its required mapping. |
| Strict security-results harness | Original harness rejects symlinked `/usr/bin/env` as a boundary tool | Use an unmodified supported runtime with the required trusted tools; do not replace a system tool to force a pass. |

There are no unexpected source-suite failures in the successful isolated run.
The previously intermittent onboarding lock-release assertion passed in this run;
the prior observed failure has not been erased or reclassified as impossible.
Retain these BLOCKED labels in any preview release notes. Full validation and
Python 3.13 support must not be claimed while their checks remain blocked.

## Deferred appliance work

Shipping image inventories, installer content, protected source anchors and
verification pins remain unchanged. Changed application bytes intentionally
disagree with the shipping dashboard inventory. Content-inventory review,
clean-source preflight, genuine cached-input integration, native ARM64 builds,
reproducibility, fresh-card boot, recovery and signing remain separate image
gates; source-suite results do not satisfy them.
The unchanged stager was rerun against the real shipping manifest and correctly
rejected the current tree with `DASHBOARD_CONTENT_MISMATCH_devices.py`.

## Publication checkpoint

Keep the validated source, license, notice, guides and tests together. The root
README, changelog, `.gitignore` and protected command-layer baseline are preserved.
The existing ignore rules are not an exhaustive secret/artifact filter; use the
reviewed explicit path list and inspect the staged diff during a separately
authorized Git operation. No staging, commit, remote configuration, push or
publication is part of this preparation.
