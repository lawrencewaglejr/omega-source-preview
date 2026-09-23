# OMEGA

OMEGA is a local network-security appliance development project. It combines
Suricata, Wazuh, and Pi-hole observations with device labels, retained evidence,
reports, and local AI explanations. Observations do not prove complete network
coverage, device identity, compromise, or safety.

## Development preview

Run `python3 -B dashboard/server.py --demo` and open http://127.0.0.1:8088.
The preview uses fictional sample data. It does not inspect your network.

## Installation and release status

The image source targets Raspberry Pi 5 with 8 GB RAM and an ARM64 Debian 13
build host. A finished hardware-validated installation image is not yet released.
Use a separate test card; do not overwrite a working appliance or its evidence.

- [Dashboard](dashboard/README.md)
- [First setup](docs/dashboard-first-boot.md)
- [Wazuh manager connection](docs/wazuh-manager-setup.md)
- [Image build](image/README.md)
- [Configuration](docs/configuration.md)

Optional protection preferences do not currently enforce filtering. Local AI
reviews aggregates and selected evidence, and can be wrong. Source availability
and collection boundaries must accompany any assessment.

## Privacy

This release repository starts with fresh history. Private deployment notes,
collected logs, reports, keys, passwords, and real household identifiers are not
part of the distribution. Configure credentials and device labels locally.
Example credentials in tests are deliberately fictional and must not be used.

The image builder verifies this sanitized baseline and its approved README update.
