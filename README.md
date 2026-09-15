# Linux-Recon-X

A read-only Linux security enumeration and privilege-escalation research assistant. It collects local evidence, identifies security-relevant conditions, correlates findings, prioritizes risk, and recommends contextual verification and research steps.

## Goals

Linux-Recon-X combines broad host enumeration with an analysis workflow:

**DISCOVER → COLLECT EVIDENCE → NORMALIZE → ANALYZE → CORRELATE → RESEARCH → PRIORITIZE → NEXT STEP → REPORT**

The project is inspired by established Linux security enumeration methodologies, including LinPEAS, LinEnum, Linux Smart Enumeration, linux-exploit-suggester, pspy-style process analysis, SUID/capability analysis and GTFOBins research. It is implemented independently.

## LinPEAS-inspired extended mode

The repository now contains an extended feature layer based on the public LinPEAS feature/check model. The exact release URL supplied for the 2026-09-14 artifact was unavailable from the GitHub connector, so this implementation is based on the accessible upstream `linPEAS` repository structure and documented check families rather than claiming byte-for-byte coverage of that unavailable artifact.

Use:

```bash
chmod +x linux-recon-x.py linux-recon-x-plus.py
./linux-recon-x.py
./linux-recon-x-plus.py --extended --expert
```

The extended layer adds independent read-only checks for:

- Environment and library-loading variables
- Writable PATH components
- Sensitive filesystem permissions
- Root-owned writable files
- Interesting application/configuration files
- Temporary/world-writable paths
- Mount options
- NFS exports
- Samba configuration
- systemd service definitions
- Interfaces, routes, neighbors and DNS
- Local firewall posture
- Deeper SSH access-control settings
- Web-server/application footprints
- Database footprints
- Development and diagnostic tools
- Kernel hardening/security-control indicators
- Container/runtime indicators
- Interactive accounts and shadow-file access posture
- Shell/application history artifacts

See `FEATURE_MATRIX.md` for the complete mapping and explicit scope decisions.

## Safety model

The default mode is **read-only enumeration/research**. The tool does not automatically exploit findings, create persistence, open reverse shells, exfiltrate credentials, or perform destructive actions. Potential secret values are redacted by default.

Use only on systems you own or are explicitly authorized to assess.

## Core usage

```bash
chmod +x linux-recon-x.py
./linux-recon-x.py
./linux-recon-x.py --expert
./linux-recon-x.py --json report.json
./linux-recon-x.py --markdown report.md
./linux-recon-x.py --no-secrets
./linux-recon-x.py --only sudo --only suid
./linux-recon-x.py --skip secrets
```

## Extended usage

```bash
./linux-recon-x-plus.py --extended
./linux-recon-x-plus.py --extended --expert
./linux-recon-x-plus.py --extended --json report.json --markdown report.md
```

The wrapper loads the existing core engine and the independent `linpeas_features.py` module. It does not require LinPEAS itself.

## Finding model

Each meaningful finding contains evidence, severity, confidence, score, explanation, safe verification guidance, research direction, relevant tools and next steps. Scores are **Tool Assessment Scores**, not authoritative CVSS scores.

CVE/version research should distinguish possible, likely and locally confirmed conditions. A version match alone is not proof of exploitability.

## Roadmap

1. Expand distribution/package coverage.
2. Add a structured offline knowledge database for configuration and vulnerability patterns.
3. Improve service/cron dependency correlation.
4. Add stronger application, filesystem and container analysis.
5. Add optional, clearly controlled online vulnerability research providers.
6. Add a comprehensive automated test suite across Linux distributions and restricted environments.
7. Improve JSON schema stability and report visualization.

## License

Choose and add an appropriate open-source license before publishing a stable release.
