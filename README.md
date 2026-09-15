# Linux-Recon-X

A read-only Linux security enumeration and privilege-escalation research assistant. It collects local evidence, identifies security-relevant conditions, correlates findings, prioritizes risk, and recommends contextual verification and research steps.

## Goals

Linux-Recon-X combines broad host enumeration with an analysis workflow:

**DISCOVER → COLLECT EVIDENCE → NORMALIZE → ANALYZE → CORRELATE → RESEARCH → PRIORITIZE → NEXT STEP → REPORT**

The project is inspired by established Linux security enumeration methodologies, including LinPEAS, LinEnum, Linux Smart Enumeration, linux-exploit-suggester, pspy-style process analysis, SUID/capability analysis and GTFOBins research. It is implemented independently.

## Safety model

The default mode is **read-only enumeration/research**. The tool does not automatically exploit findings, create persistence, open reverse shells, exfiltrate credentials, or perform destructive actions. Potential secret values are redacted by default.

Use only on systems you own or are explicitly authorized to assess.

## Usage

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

Run `./linux-recon-x.py --help` for all options.

## Current checks

- OS, kernel, architecture and identity
- Administrative group and sudo posture
- SUID/SGID-oriented discovery
- Linux file capabilities
- Writable privileged configuration/script candidates
- Cron and systemd timer indicators
- Processes and listening sockets
- Package/application discovery
- SSH configuration posture
- Docker socket and cloud-runtime indicators
- Potential secret-bearing configuration artifacts with redaction
- Finding correlation and tool-assessment scoring
- JSON, CSV and Markdown reports

## Finding model

Each meaningful finding contains evidence, severity, confidence, score, explanation, safe verification guidance, research direction, relevant tools and next steps. Scores are **Tool Assessment Scores**, not authoritative CVSS scores.

CVE/version research should distinguish possible, likely and locally confirmed conditions. A version match alone is not proof of exploitability.

## Roadmap

1. Expand distribution/package coverage.
2. Add a structured offline knowledge database for configuration and vulnerability patterns.
3. Improve service/cron dependency correlation.
4. Add stronger application and container analysis.
5. Add optional, clearly controlled online vulnerability research providers.
6. Add a comprehensive automated test suite across Linux distributions and restricted environments.
7. Improve JSON schema stability and report visualization.

## License

Choose and add an appropriate open-source license before publishing a stable release.
