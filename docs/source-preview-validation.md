# Source-preview validation — 2026-11-14

Scope: experimental **0.1.0-preview.1**, source-only, Linux amd64. This follow-up
started from clean `main` commit `3381009fd3c251e1118c885c43b734c81f3c3c09`.
Concurrent documentation/media commits advanced HEAD through `548141c` to
`8ef721e`; they were preserved. The application and test files still match the
executed candidate. The validation source fixes and guide updates are included in this source
update. They do not establish Raspberry Pi/ARM64 appliance-image acceptance.

## Current results

| Previously documented gap | Result | Evidence |
| --- | --- | --- |
| Python 3.13 runtime compatibility | **PASS** on Debian Python **3.13.5** | Full application/browser run plus the completed zstd-dependent payload suite; this is execution, not a grammar-only claim. |
| Distinct publisher/collector UID permissions | **PASS**, two tests, no skips in the mapped-identity run | Publisher UID 2001 and collector UID 2002, shared supplementary GID 2100, explicit 0–65535 UID/GID maps; every reading/writing child has zero effective capabilities. |
| Strict installer lifecycle harness | **PASS**, 365 assertions, zero failures; final isolation audit PASS | Original `tests/test-install-lifecycle.sh`, unchanged. |
| Strict security-results harness | **PASS**, 3669 assertions, zero failures; final isolation gate PASS | Original `tests/test-security-results.sh`, unchanged; full security-only run completed in 2956.54 seconds. |

The source checks cover **272 distinct Python tests** across the ordinary source
run, the zstd supplement, and the separate mapped-UID run, plus **42 browser-logic
checks**. In the ordinary single-identity sandbox the DAC case reports unavailable;
it is validated separately with two genuinely different unprivileged identities.
The same-UID rsync case is not used as proof of the collector's access.
The initial image omitted zstd and therefore skipped 22 AI-payload tests. Debian's
zstd package was then installed in the disposable image and all 22 ran and passed
without skips. Those initial skips are not counted as passes.

Runtime versions: Linux **6.12.117+deb13-amd64**, Python **3.13.5**
(`3.13.5-2+deb13u5`), Node.js **20.19.2**, Bubblewrap **0.12.0**,
util-linux **2.41.5**, GNU coreutils **9.7**, rsync **3.5.0**, ACL tools **2.3.2**,
and zstd **1.5.7**. This validates the exercised workload on this runtime; it does
not prove all Python versions, platforms, native ARM64 code or live integrations.

## Evidence and commands

All paths below are local, ignored preparation artifacts under
`reports/source-preview-validation-20261114/`; none are publication inputs.

- `attempt-354f129a/python313-application.log`: all 17 application, payload and
  browser commands, exact outcomes and the initially skipped zstd-dependent cases.
- `attempt-354f129a/distinct-uids.log`: both permission tests passed, no skips.
- `attempt-c398b8f8/test-install-lifecycle.log`: 365 passes, zero failures,
  complete command-guard and namespace audit.
- `attempt-4f36ef15/python313-application.log`: all 22 AI-payload cases with zstd.
- `attempt-4f36ef15/test-security-results-root.log`: incomplete 1200-second
  security run, retained as FAIL (timeout).
- `attempt-59afd722/test-security-results-root.log`: completed strict security
  run, 3669 passes, zero failures, isolation gate PASS; see its `summary.json`.
- Each successful attempt includes `source-sha256.json`, `runtime-versions.log`,
  `guest-boundary.json`, `container-boundary.json`, `summary.json` and `serial.log`.
- `build-context/`, `launch-vm.py` and `final-tested-source-sha256.json` retain
  the exact disposable driver, package recipe and exported candidate bytes.

Host preparation used this digest-pinned official Debian base:
`debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`.
Packages came from the image's signed Debian repositories. Exact host build/run
commands, from the publication checkout, were:

```bash
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --progress=plain \
  --iidfile reports/source-preview-validation-20261114/vm-image-id \
  -f reports/source-preview-validation-20261114/build-context/Dockerfile.vm \
  reports/source-preview-validation-20261114/build-context
python3 -B reports/source-preview-validation-20261114/launch-vm.py
```

The retained launcher creates a fresh outer container with `--network=none`,
`--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, an 8 GiB memory
limit, four CPUs, the KVM device, and one new private `/work` volume. There are no
host directory binds. Docker's socket is used only by the host management client;
it is never mounted in the container or guest. QEMU uses `-accel kvm -cpu host
-smp 2 -m 6144 -nic none`; the guest has only loopback and no external route.
The laptop's namespace policy, system binaries and security profiles are unchanged.

The following commands ran **inside that disposable guest**, never against the
laptop root or appliance. The permission command uses a fresh full identity map:

```bash
unshare --user --map-users=0:0:65536 --map-groups=0:0:65536 --setgroups=allow --net \
  /usr/bin/python3 -B /source/tests/test-wazuh-permissions.py -v
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --no-new-privs \
  /bin/sh /repo/tests/test-install-lifecycle.sh
/bin/sh /repo/tests/test-security-results.sh
```

The final security command starts as root of the disposable guest, not host root.
The unchanged harness then establishes its own private namespaces, single-UID map,
read-only repository, private `/etc`, `/var` and `/tmp`, capability removal,
trusted-tool checks, command guards and signal-handling assertions.

Application commands are the full list in [source-preview scope](source-preview.md),
using `python3 -B <test> -v` and `node <browser-test>`. They ran as guest UID 1000 in
additional private user/mount/network/PID/IPC/UTS namespaces, with a read-only
source mount, zero capabilities, empty temporary/home directories and synthetic
passwd/group/NSS/hosts files. Host homes, credentials, service sockets, operational
evidence and private development history were absent. The application export had
no Git directory. Only the installer fixture also received a bundle of this
sanitized repository's `main`, to support its unchanged `git show main:<path>`
checks; no private repository or configuration was imported.

## Failures investigated and fixes

The failed attempts are retained; they are not retrospectively labeled passing.

1. An early 2 GiB software-emulated guest provided less than the application's
   required 2 GiB free temporary space. Report generation and setup correctly
   refused. A fresh 6 GiB guest provided sufficient real capacity. No free-space
   threshold or test assertion was reduced or mocked to force a pass.
2. On a freshly booted system, a zero analysis timestamp incorrectly delayed the
   first correlation until uptime exceeded five minutes. The collector now starts
   the first analysis immediately after catch-up, while preserving the interval
   after a completed analysis. A fixed-clock regression covers both conditions.
3. A coarse filesystem mtime could place a known rotated log before collection
   start, skipping unread bytes despite a committed cursor. Known uncompressed
   log identities now retain their cursors through rotation; unknown historical
   files retain the prior exclusion. The regression sets the rounded mtime
   explicitly and still requires every post-start record after restart.
4. The previously intermittent onboarding failure reproduced: an identity response
   could reach the client before the operation lock was released in `finally`.
   The response is now sent after lock release, on both success and failure.
   A direct response-write assertion and the original recovery/privacy assertions
   pass. The earlier failure has not been suppressed.
5. The first unprivileged strict security attempt exceeded its 900-second driver
   limit. A root-guest attempt also exceeded its 1200-second driver limit after
   more than 1000 passing assertions and no observed failed assertion. Both are
   retained as **FAIL (timeout)**, not successful full runs. A fresh security-only
   run used a 3600-second driver budget and finished in 2956.54 seconds, retaining
   every original case, internal timeout, guard and assertion. Streaming logs
   prevented incomplete output from being mistaken for successful validation.

Initial driver-only setup and shutdown errors are also retained in the attempt
logs. The final driver uses BusyBox shutdown and fails if any recorded check fails.

## Preserved boundaries and deferred appliance work

The protected installer, command-layer source, fixtures and both strict harnesses
are unchanged. `LICENSE` remains Apache 2.0 and `NOTICE` remains unchanged. The
README's two credits now read **Founder & Security Architect: Lawrence Wagle Jr**.
No host tools were replaced, no security policy was changed, and no assertion was
waived. Logs, virtual disks, build inputs and scratch files are excluded by the
existing `reports/` ignore rule.

Image inventories, source-trust anchors, approved exceptions and verification pins
are unchanged. The root README already differed from its authorized image-builder
blob before this follow-up; the approved credit edit does not repin that blob.
Changed dashboard and onboarding application bytes require separate inventory
review. Image source-trust preflight, genuine build-input integration, native
ARM64 builds, reproducibility, spare-card boot, recovery and signing remain
separate gates. A fixture payload test pass is not shipping image acceptance.
Final verification without a destination reran the unchanged stagers against the
shipping manifests. They correctly returned `DASHBOARD_CONTENT_MISMATCH_devices.py`
and `ONBOARDING_CONTENT_MISMATCH_server.py`. The exact commands and outcomes are
retained in `shipping-inventory-gates.json`; `final-integrity.json` records source,
protected-path, license/notice, Git staging and documentation-link verification.

## Historical checkpoint

The original source preview at `1ea69ef39101a5487426d647e57f76613e1c6920` recorded
269 Python checks, 42 browser-logic checks, four optional manifest checks, and a
Python 3.14.4 demo smoke check with Node.js 22.22.1. Its four host-environment gaps
and Python 3.13 grammar-only result describe that earlier checkpoint. Subsequent
README documentation commits did not themselves rerun application tests.
The current results above supersede those runtime gaps only where explicitly
marked PASS. No new appliance acceptance is claimed.

## Source-review readiness

All four original source-validation gaps are resolved for the tested Linux amd64
environment. At completion of the validation task, the local experimental source candidate
was ready for final publication review, with the separate image limitations above.
The later demo/media/inquiry documentation commits were preserved; the recorded
application suites do not constitute a visual or operational review of that new
content. No staging, commit, push, tag, release or visibility change was performed
by this validation task. A read-only GitHub check reported that the repository
was already public; that external state was left untouched.
