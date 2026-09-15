#!/usr/bin/env python3
"""Linux-Recon-X Plus.

Runs the core Linux-Recon-X engine plus the extended, read-only enumeration
families mapped from the public LinPEAS feature model. This is an independent
implementation and never executes exploitation or credential-exfiltration
workflows.
"""
import sys
import linux_recon_x_loader

if __name__ == "__main__":
    linux_recon_x_loader.main()
