# OMEGA Phase 4 master image

This directory contains the reproducible, credential-free OMEGA master-image
builder for a Raspberry Pi 5 with 8 GB RAM. It targets Raspberry Pi OS Lite
64-bit on Debian 13 Trixie and produces a sparse 32 GiB SD-card image with a
512 MiB FAT boot partition and a 31 GiB ext4 root partition. Phase 5 expands
the filesystem and applies device and site identity.

## Current build contract

- Builder: authenticated `rpi-image-gen` v2.8.0 source at commit
  `262d4df5a9f9d4133370465399a7958a7c22cdc7` and tree
  `b4d841718ae5436dd17ed7712cec47d010853ccd`.
- Builder plan: 34 exact layers with normalized SHA-256
  `c3f8efcccbed085eb6c38334e19568389e730641eb25bcca81a4dfd93cba796f`.
- Debian base: local `copy://` repository generated from 313 verified package
  objects. The builder cannot reach an external APT source.
- Containers: exact arm64 Pi-hole `2026.07.2` and EveBox `0.28.0` images,
  reconstructed as a deterministic Docker archive for first-device import.
- Host-tool sources: exact bdebstrap 0.7.0, genimage 20, and libconfuse 3.3
  archives supplied through the same content-addressed input cache.
- Dashboard: the ten application files pinned in `locks/dashboard.manifest`,
  including persistent telemetry collection, correlation, and full reports.
- Offline AI: Ollama 0.33.3 arm64 CPU runtime and `qwen3:1.7b`, pinned in
  `locks/ai.manifest.json`. The upstream runtime archive, license, model
  manifest, and five blobs use the same verified input cache. GPU libraries
  are excluded from the staged runtime.
- Reproducibility environment: UTC, `C.UTF-8`, umask `0022`, and
  `SOURCE_DATE_EPOCH=1787801458`.
- Fixed image identifiers: MBR signature `0xbd67750e`, FAT ID `BD67-750E`,
  and ext4 UUID `bd67750e-9777-5c69-b79e-ee0d454fbe92`.
- Output: `omega-rpi5-trixie-arm64-omega-v1.img.xz`, builder metadata,
  deterministic SPDX 2.3 JSON, provenance JSON, and `SHA256SUMS`.

The source archive and repository trust decisions retain their documented
residual risks. Future identity, signature, digest, plan, or content mismatch
fails closed.

## Image behavior

The image contains the protected OMEGA commands plus Suricata, Docker, Wazuh
Agent, Tailscale, Pi-hole, EveBox, the dashboard, and local AI. Pi-hole and EveBox run from the pinned
container archive. All managed services are disabled in the master image.

No hostname unique to a customer, machine ID, SSH host key, credential,
enrollment token, API password, network policy, or site configuration is
included. Phase 5 creates `/etc/omega/pihole.env` and
`/etc/omega/evebox.env`, enrolls Wazuh and Tailscale, configures Suricata and
networking, and enables the approved services. Secure-boot OTP programming and
device-bound encryption also belong to Phase 5.

The dashboard and AI bind only to loopback. They require fresh private
configuration and an explicit activation marker. The offline operator helper
`/usr/libexec/omega/configure-dashboard` checks an otherwise provisioned
appliance before creating its first dashboard password and configuration;
it neither configures the router/sensors nor starts services. See
[the first-boot contract](../docs/dashboard-first-boot.md). The paired browser
wizard at `/usr/libexec/omega/start-setup` guides these checks, password setup,
separate service activation, and fresh-evidence/local-AI verification. The
packaged Wazuh mirror connects directly using a device-owned SSH key and verified
manager host key after a manager administrator grants restricted reader access.
Device identity, network/sensor provisioning, and production browser access
remain prerequisites or follow-up release work.
An image containing these components still requires a native build and fresh
hardware acceptance tests before release.

## Verify and build

The external cache must have this layout:

```text
cache/objects/sha256/<lowercase-sha256>
```

For the AI inputs, use the exact HTTPS source URLs, sizes, and SHA-256 values
recorded in `locks/ai.manifest.json`. Input acquisition happens before the
offline build; no tool downloads a model at boot or during construction.
`stage-ai.py` verifies every cache object, verifies the model's blob references,
and during staging checks the selected runtime files against their individual
hashes. It creates only the reviewed runtime, model tree, and receipt. Service
users receive ownership of private model files inside the target image.

Validate tracked locks, payload files, the authenticated builder, all cached
objects, and the exact builder plan:

```bash
./image/scripts/verify.sh --require-build-readiness
./image/scripts/build.sh \
  --check-service-cache /absolute/path/to/input-cache
OMEGA_NETWORK_MODE=offline ./image/scripts/build.sh \
  --preflight --input-cache-root /absolute/path/to/input-cache
```

Create the release on a native arm64 Debian 13 build host:

```bash
OMEGA_NETWORK_MODE=offline ./image/scripts/build.sh \
  --build \
  --input-cache-root /absolute/path/to/input-cache \
  --output-dir /absolute/new/output-directory
```

The output directory must not exist. The native host must satisfy the pinned
builder's dependencies, include `newuidmap`, `newgidmap`, and the
`python3-ruamel.yaml` module and `zstd`, and provide subordinate UID/GID ranges. The full
construction runs in user and mount namespaces that map those ranges and in a
network namespace with only loopback and no IPv4 route.

Run the focused tests with:

```bash
./tests/image/test-builder-foundation.sh
./tests/image/test-builder-trust-enforcement.py \
  --input-cache-root /absolute/path/to/input-cache
python3 -B tests/image/test-offline-inputs.py \
  --input-cache-root /absolute/path/to/input-cache
python3 -B tests/image/test-release-payload.py
python3 -B tests/image/test-dashboard-payload.py
python3 -B tests/image/test-ai-payload.py
python3 -B tests/image/test-dashboard-setup.py
```

## Trust and source policy

Commit `4eeafcf1caffc4223055e32b33bc83067d72e20e` is the protected-content
anchor. A build source must be a clean descendant and preserve every anchored
Git blob, type, and mode. The only approved change to anchored content is the
README release-policy commit `5179f3595f0b9e1c61417ee76d660fb05c7f102b`,
whose parent, changed path, and resulting blob are verified exactly.

Lock files use strict, versioned schemas (the AI inventory uses JSON). Verification rejects blank
or malformed lock lines, duplicate or unknown keys, non-ASCII bytes, unsafe
paths, symbolic links, mutable references, unexpected ownership or modes, and
object replacement during validation. Cache verification does not execute the
builder or service payloads.

Release checksums, SPDX, and provenance are created by the builder. A detached
release signature still requires an OMEGA release-signing key and is performed
as a controlled release operation after the native build.
