# Design decisions

- Security scanners remain authoritative detectors; GateShield orchestrates and normalizes them.
- Gate decisions are deterministic. No AI component exists in this release.
- Raw tool data and normalized reports are separate artifacts.
- Findings are not operational errors. Scanner failures are not interpreted as a clean scan.
- External gate mode exists specifically for organizations that want GateShield evidence but maintain an internal policy engine.
- Baselines allow legacy applications to adopt gates without hiding historical debt.
- DAST never manages application lifecycle and is constrained by explicit target allowlists.
- CodeQL remains a native/external integration in 0.0.1.
