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

## Verification

The sanitized application passed 169 Python checks and both browser-logic suites.
The builder passed 91 foundation checks and 45 trust checks, including offline
preflight against the pinned inputs. Initial socket tests required permission to
bind loopback; their reruns passed. These are software checks, not hardware acceptance.

Private-key header text in the identity helper checks a file format; it is not
key material. Password literals in tests are synthetic fixtures. Private-range
addresses in tests/demo are fictional; generic private-range network definitions
and public resolver addresses are functional constants.

Before publishing, inspect staged changes and maintain this separation: never
copy a running appliance filesystem, local credentials, user evidence, or private
Git objects into this repository. A scan cannot prove absence of every possible
identifier. GitHub is not yet configured and nothing has been uploaded.

A release image must still be constructed from clean inputs and independently
checked for generated credentials, machine identity, logs, and first-boot behavior.
