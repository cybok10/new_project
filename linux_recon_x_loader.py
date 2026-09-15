"""Loader for the extended Linux-Recon-X mode.

The core and extension files use hyphen/underscore names that are not
importable with a normal Python import.  When loading them dynamically we
must register each module in sys.modules before executing it.  Python 3.13's
dataclasses implementation relies on that registration while processing
@dataclass classes.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to create import specification for {path}")

    module = importlib.util.module_from_spec(spec)
    # Required for decorators such as @dataclass on Python 3.13.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        # Avoid leaving a half-initialized module behind after a failed load.
        sys.modules.pop(name, None)
        raise
    return module


base = load_module("linux_recon_x_core", ROOT / "linux-recon-x.py")
ext = load_module("linux_recon_x_extended", ROOT / "linpeas_features.py")


class ExtendedEngine(base.Engine):
    def run(self):
        modules = {
            "system": self.system,
            "users": self.users,
            "sudo": self.sudo,
            "suid": self.suid_caps,
            "filesystem": self.writable_privileged,
            "cron": self.cron_services,
            "process": self.processes_network,
            "packages": self.packages_apps,
            "ssh": self.ssh_container_cloud,
            "secrets": self.secrets,
        }
        extended = ext.register(self)
        modules.update(extended)

        selected = self.args.only or list(modules)
        skipped = set(self.args.skip)
        for name in selected:
            if name in modules and name not in skipped:
                try:
                    modules[name]()
                except Exception as exc:
                    print(
                        f"{base.C.YELLOW}[WARN]{base.C.RESET} "
                        f"module {name} failed safely: {exc}",
                        file=sys.stderr,
                    )

        self.correlate()
        self.render()


def main():
    argv = list(sys.argv[1:])
    if "--extended" in argv:
        argv.remove("--extended")
    sys.argv = [sys.argv[0]] + argv
    args = base.parse()
    print(f"{base.C.BOLD}Extended LinPEAS-inspired coverage enabled{base.C.RESET}")
    ExtendedEngine(args).run()


if __name__ == "__main__":
    main()
