# Public source review

This repository is a separate sanitized distribution with fresh Git history.
The original development repository and deployed appliance are not included.

## Distribution policy

Only reviewed tracked source, tests, examples, and documentation were copied.
Household deployment notes and incident narratives were replaced with general
release status. Device examples and demo data are fictional. The legacy
household-specific push helper and tunnel services were excluded. No credentials,
telemetry database, downloaded report, build cache, installation image, Git remote,
or prior Git history was imported. Commit identity is OMEGA Project with a
non-deliverable example address, not a personal address.

The image builder has a fresh protected-content anchor and approved README
commit. Its exact blob/mode checks, clean-source requirement, upstream input
verification, and native architecture gate remain enabled. This is a new source
baseline; it does not claim historical continuity with private development commits.

The subsequent expanded project README credits Security Architect Lawrence Wagle Jr
and documents the source-preview features and license. It differs from the
builder's authorized README blob. The existing exact-blob checks remain enabled;
image source-trust preflight requires a separate reviewed README authorization.
No protected installer content, image inventory or verification pin was changed
for this documentation update.

## Verification

The original sanitized revision passed 169 Python checks and both browser-logic suites.
The builder passed 91 foundation checks and 45 trust checks, including offline
preflight against the pinned inputs. Initial socket tests required permission to
bind loopback; their reruns passed. These are historical software checks, not acceptance of subsequent edits or hardware.
The current cache lifecycle and background reader changes passed the isolated
regressions recorded in [source-preview validation](source-preview-validation.md).
That report distinguishes supported source checks, blocked checks and deferred
appliance acceptance. The older counts above describe the original baseline.

Private-key header text in the identity helper checks a file format; it is not
key material. Password literals in tests are synthetic fixtures. Private-range
addresses in tests/demo are fictional; generic private-range network definitions
and public resolver addresses are functional constants.

Before publishing, inspect staged changes and maintain this separation: never
copy a running appliance filesystem, local credentials, user evidence, or private
Git objects into this repository. A scan cannot prove absence of every possible
identifier. This sanitized distribution has no Git remote configured at this checkpoint.
That statement does not describe any separate development repository or its
publication history. Recheck all refs and the proposed publication tree before
configuring a destination.

A release image must still be constructed from clean inputs and independently
checked for generated credentials, machine identity, logs, and first-boot behavior.

## Current source-preview preparation

Version 0.1.0-preview.1 is experimental and source-only, not an accepted appliance
image. OMEGA source is licensed under the [Apache License 2.0](../LICENSE),
unless otherwise noted. Copyright 2026 Lawrence Wagle Jr; see [NOTICE](../NOTICE).
Third-party components retain their own license terms and notices. Historical
pass counts above do not validate new edits. Consult the public
[validation summary](source-preview-validation.md) for current pass/fail/blocked
results. Private raw logs and operational reports are excluded from publication.
Every proposed new/untracked file must be scanned in addition to tracked content
and all stored Git objects. No Git operation or publication is authorized by the
preparation process. See [source-preview scope](source-preview.md) and
[third-party notices review](third-party-notices.md).
