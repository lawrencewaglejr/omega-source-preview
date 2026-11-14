# Third-party review for the source preview

OMEGA 0.1.0-preview.1 is a source-only distribution. The project grant is the
[Apache License, Version 2.0](../LICENSE), with the approved copyright holder in
[NOTICE](../NOTICE). The license text matches the
[Apache Software Foundation text](https://www.apache.org/licenses/LICENSE-2.0.txt)
after whitespace normalization; its appendix is part of that standard text.

The reviewed publication files contain application source, project-authored
scripts and browser assets, configuration examples, synthetic fixtures, tests,
documentation, and dependency descriptions. No vendored dependency library,
downloaded runtime, model, container, operating-system package, font, icon pack,
or other third-party binary was identified in the source tree or stored history.
The dashboard/demo uses the Python standard library and local modules, and the
browser code has no bundled npm dependencies. Test credential literals are
synthetic. A key-header format check contains no private key material.

The following references are dependency boundaries, not additional components
included in this source preview:

| Component | Source-preview treatment | Later redistribution requirement |
| --- | --- | --- |
| Python, Node.js, Bash, GNU tools, jq, rsync, OpenSSH, Bubblewrap | External development or integration prerequisites | Preserve the licenses of any runtimes/tools actually redistributed. |
| Debian/Raspberry Pi packages, Suricata, Wazuh, Tailscale | Build locks, configuration and integration code only | Review each actual package's copyright and license metadata when assembling an image. |
| Pi-hole and EveBox containers | Pinned image descriptions and startup configuration only | Review the actual container payloads and retain applicable upstream notices. |
| Raspberry Pi image builder and build-tool sources | Pinned source identities and verification helpers only | Preserve notices of the actual upstream source archives and build tools. |
| Ollama and Qwen model | Manifest descriptions and staging helpers only | Retain the separately pinned runtime license, bundled library notices and model license blob; see [offline AI inputs](offline-ai-inputs.md). |

The project license does not relicense these external components or grant rights
to their trademarks. No existing third-party attribution notice was removed.
This file records the inspected source boundary; it is not an image license
inventory or a claim that all future bundled software is Apache-licensed.

Before adding a dependency or copied asset, record its origin and license and
retain the required notices. Review any future binaries and appliance image
separately from this source preview.
