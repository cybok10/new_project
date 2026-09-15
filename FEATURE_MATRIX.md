# Linux-Recon-X Feature Matrix

This document maps the Linux-Recon-X roadmap to the feature families documented by upstream LinPEAS. The upstream project is used as a behavioral reference; this project does not copy LinPEAS source code.

## Coverage plan

| LinPEAS feature family | Linux-Recon-X plan | Status |
|---|---|---|
| System information | OS, kernel, arch, hostname, uptime, identity | Core |
| Container detection | Docker/Podman/LXC/LXD/Kubernetes indicators | Core/expand |
| Cloud detection | AWS/GCP/Azure local indicators | Core/expand |
| Processes | Processes, owners, command lines, privileged context | Core |
| Cron/timers/services/sockets | Cron, systemd timers/services, listeners | Core |
| Network information | Interfaces, routes, DNS, neighbors, sockets, firewall posture | Expand |
| Users information | Users, groups, shells, account/security posture | Core |
| Software information | Package managers, versions, security-sensitive components | Core |
| Interesting files | Permissions, backups, configs, artifacts and sensitive paths | Core/expand |
| API key/credential regexes | Redacted secret indicators and configurable pattern engine | Core/expand |
| SUID/SGID | Privileged file discovery and correlation | Core |
| Linux capabilities | Security-sensitive capabilities | Core |
| Sudo | Effective sudo policy and contextual analysis | Core |
| PATH/environment | Writable PATH and environment risk analysis | Expand |
| SSH | Effective configuration and key/artifact posture | Core |
| NFS/Samba/mounts | Filesystem/network-share posture | Expand |
| Web applications | Local web/service technology discovery | Core/expand |
| Databases | Local database/service discovery and configuration posture | Expand |
| Kernel/CVE research | Version/platform candidate research with confidence | Framework |
| Binary analysis | file/readelf/strings/ldd context recommendations | Core |
| Process monitoring | Optional read-only process observation | Roadmap |
| Firmware folder analysis | Analyze a supplied filesystem tree without executing firmware | Roadmap |
| Local host discovery | Explicit opt-in network discovery | Roadmap |
| Local port scanning | Explicit opt-in target scanning | Roadmap |
| Port forwarding | Not part of the default security-assessment assistant | Excluded |
| Password brute forcing | Not part of default behavior | Excluded |
| Exploit execution | Never automatic | Excluded |

## Important scope decisions

Linux-Recon-X intentionally differs from LinPEAS in a few areas. It is designed as an investigation assistant rather than a direct clone. Network scanning, password guessing, port forwarding, exploit execution, credential exfiltration and AV-evasion workflows are not default capabilities.

## Future implementation modules

Planned module identifiers:

- `system_information`
- `container`
- `cloud`
- `procs_crons_timers_srvcs_sockets`
- `network_information`
- `users_information`
- `software_information`
- `interesting_files`
- `interesting_perms_files`
- `api_keys_regex`
- `sudo_analysis`
- `suid_sgid`
- `capabilities`
- `path_environment`
- `ssh_analysis`
- `mounts_nfs_samba`
- `web_application`
- `database`
- `kernel_research`
- `process_monitor`
- `firmware`

The CLI should permit selecting individual modules, analogous to the upstream project's targeted-check concept, while preserving a safe default configuration.
