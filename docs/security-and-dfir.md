# Defense and DFIR examples

OMEGA is an experimental source preview. The following examples describe how a
properly configured deployment could support defense and investigation; they are
illustrations, not reports of attacks stopped by this project or demonstrations
of accepted Raspberry Pi hardware. The public demo uses fictional data.

**DFIR means Digital Forensics and Incident Response.** OMEGA brings available
observations, retained evidence and operator tools together to support triage,
investigation and handoff. Blocking depends on separately configured controls;
the dashboard and AI do not execute containment actions.

## Practical examples

| Example | How the configured stack could help | Investigation value |
| --- | --- | --- |
| **Repeated SSH password guessing** | An externally configured Fail2ban jail can temporarily ban an address after repeated failed logins. Wazuh can report collected authentication events through its separate manager. [Fail2ban documentation](https://github.com/fail2ban/fail2ban). | Review recorded attempts, targeted accounts, timestamps and any subsequent successful login, where those events were collected and retained. |
| **A device requests a blocked malicious domain** | Pi-hole can refuse DNS resolution when a domain matches configured blocking rules and the device uses that resolver. OMEGA can show collected DNS observations and device context. [Pi-hole examples](https://docs.pi-hole.net/group_management/example/). | Identify which observed device requested the domain and when. A blocked lookup alone does not establish infection. |
| **Scanning or suspicious network traffic** | Suricata can alert when traffic visible to its sensor matches configured detection rules. EveBox offers another event-review interface. An operator can investigate and use separately managed containment controls. [Suricata event output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html). | Examine available addresses, ports, signatures, protocol details and timing. OMEGA does not automatically block these connections. |
| **Unexpected changes to important files** | Configured Wazuh file-integrity monitoring can alert on changes to monitored files. The Pi agent covers its configured sources; other endpoints need their own agents or collection. [Wazuh file-integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html). | Investigate the reported file change and available hashes, attributes and timestamps. The manager must supply the relevant events to OMEGA. |
| **Exposed administration services** | Properly configured Tailscale access controls can restrict administration to authorized users and devices, reducing the need to expose services publicly. [Tailscale access controls](https://tailscale.com/docs/features/access-control). | Reduce an access path while investigating through an authorized private connection. This does not establish that OMEGA collects Tailscale audit logs. |
| **Malicious text or unsafe paths aimed at OMEGA** | Synthetic adversarial tests exercise command injection, forged result markers, unsafe paths and hostile text handling to catch failures in how the software treats untrusted input. [OMEGA test source](https://github.com/lawrencewaglejr/omega-source-preview/tree/main/tests). | More reliable handling helps distinguish collected content from trusted application output. These are software checks, not evidence that a live attack was stopped. |

Fail2ban is externally installed/configured and is not packaged or activated by
this preview. Pi-hole blocking depends on the client's DNS path and configured
rules; it does not inspect every connection. Suricata coverage depends on sensor
placement, rules and visible traffic, including limits on encrypted payloads.
Wazuh coverage depends on agent collection, manager configuration and available
alerts/archives. See the [manager connection guide](wazuh-manager-setup.md).

## A fictional investigation sequence

Suppose the following events are actually collected from a monitored laptop:

1. **10:01:** A DNS observation records a request for a suspicious domain.
2. **10:02:** Suricata records a network alert involving the laptop's observed address.
3. **10:03:** Wazuh reports a change to a monitored startup file.

An investigator can compare the available records, check device/address mappings
and timestamps, examine the original collected details, and decide which system
and evidence to preserve next. Shared timing or an address suggests a lead; it
does not prove causation or a compromised identity. A Suricata event relayed by
Wazuh is not independent corroboration of that same event.

## Evidence and handoff

On a configured live collector, completed full-report ZIP exports can include:

- `OMEGA-report.html`: the readable assessment, evidence references and limitations.
- `coverage-and-correlations.json`: coverage and correlation candidates.
- `events.jsonl`: retained normalized events from a consistent snapshot.
- `source-events.jsonl`: original collected sensor records for that snapshot.
- Device context for interpreting available observations.

Exports cover retained collected evidence, subject to configured retention and
event limits. They do not reconstruct missing upstream history or provide a
complete packet capture, disk image or memory acquisition. Original collected
records are not a promise of byte-for-byte preservation of every upstream file.

Formal forensic work still requires appropriate acquisition tools, preserved
originals, verified timestamps, evidence handling and a documented chain of
custody. The current store and report export are not immutable evidence storage.
Local AI reviews aggregates and selected examples; investigators must verify its
explanations against source evidence. Keep real incident records and private
reports outside public GitHub Issues and this repository.

## Adversarial and failure-mode testing

The public test source includes checks for hostile input and command injection,
forged result markers, authentication/origin/CSRF handling, session expiry,
symlinks and unsafe paths, distinct-identity permissions, interrupted operations,
rollback, concurrency and evidence preservation. Image-source and payload tests
also exercise tampering rejection; their presence is not shipping-image acceptance.

Recorded source validation uses different units:

| Suite | Recorded result |
| --- | --- |
| Python tests | 272 distinct tests |
| Browser logic | 42 checks |
| Strict installer lifecycle | 365 assertions; isolation audit passed |
| Command-layer security results | 3,669 assertions; isolation gate passed |

These totals are not counts of distinct attacks, and not every test is an
adversarial case. Synthetic adversarial and regression checks are not an
independent penetration test or proof of protection against all attacks.

See the [dated validation report](source-preview-validation.md),
[source-preview scope and commands](source-preview.md),
[public test source](../tests/), and
[report-export implementation](../dashboard/report_jobs.py) for exact boundaries.
Native ARM64 builds, shipping inventories, fresh-card boot, recovery and signing
remain separate appliance acceptance work.
