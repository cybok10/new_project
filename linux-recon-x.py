#!/usr/bin/env python3
"""Linux-Recon-X: read-only Linux security enumeration and research assistant.

Designed for authorized security assessment, CTFs, labs and defensive auditing.
The default behavior collects local evidence, correlates findings and recommends
safe verification/research steps. It does not exploit, persist, exfiltrate or
modify the host.
"""
from __future__ import annotations

import argparse, csv, json, os, platform, re, shutil, socket, stat, subprocess, sys, time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

VERSION = "0.1.0"

class C:
    RESET="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"; CYAN="\033[96m"; MAGENTA="\033[95m"; BLUE="\033[94m"

@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: str = "INFO"
    confidence: str = "MEDIUM"
    score: int = 0
    evidence: list[str] = field(default_factory=list)
    affected_component: str = ""
    version: str = ""
    why_it_matters: str = ""
    verification: list[str] = field(default_factory=list)
    research: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

class Engine:
    def __init__(self, args: argparse.Namespace):
        self.args=args; self.findings=[]; self.cache={}; self.start=time.time()
        self.redact=not args.no_secrets

    def run_cmd(self, argv: list[str], timeout: int|None=None) -> str:
        if not argv or shutil.which(argv[0]) is None: return ""
        try:
            p=subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=timeout or self.args.timeout, check=False)
            return p.stdout[: self.args.max_output]
        except (OSError, subprocess.TimeoutExpired): return ""

    def read(self, path: str, limit: int=65536) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f: return f.read(limit)
        except (OSError, UnicodeError): return ""

    def add(self, **kw): self.findings.append(Finding(**kw))

    def system(self):
        osr=self.read("/etc/os-release")
        pretty=""
        for line in osr.splitlines():
            if line.startswith("PRETTY_NAME="): pretty=line.split("=",1)[1].strip().strip('"'); break
        kernel=platform.release(); arch=platform.machine(); user=self.run_cmd(["id"]).strip()
        self.cache.update(os=pretty or platform.system(), kernel=kernel, arch=arch, user=user)
        print(f"{C.CYAN}[INFO]{C.RESET} {pretty or platform.system()} | kernel {kernel} | {arch}")
        print(f"{C.CYAN}[INFO]{C.RESET} {user or 'identity unavailable'}")
        virt=self.run_cmd(["systemd-detect-virt","--quiet"]) if shutil.which("systemd-detect-virt") else ""
        indicators=[]
        if Path("/.dockerenv").exists(): indicators.append("Docker")
        if Path("/run/.containerenv").exists(): indicators.append("Podman")
        if virt=="":
            v=self.run_cmd(["systemd-detect-virt"]).strip()
            if v and v != "none": indicators.append(v)
        if indicators: print(f"{C.YELLOW}[WARN]{C.RESET} Virtualization/container indicators: {', '.join(indicators)}")

    def users(self):
        passwd=self.read("/etc/passwd"); homes=[]
        for row in passwd.splitlines():
            p=row.split(":")
            if len(p)>=7 and p[5].startswith("/"):
                homes.append(p[5])
        groups=self.run_cmd(["id","-Gn"]).strip()
        if any(x in ("sudo","wheel") for x in groups.split()):
            self.add(id="USR-001",category="privileges",title="Current user has administrative group membership",severity="MEDIUM",confidence="HIGH",score=55,evidence=[groups],why_it_matters="Membership in sudo/wheel can provide administrative execution depending on policy.",verification=["id -Gn","sudo -l"],research=["Review the applicable sudoers policy and least-privilege design."],recommended_tools=["sudo"],next_steps=["Review sudo privileges and identify which commands are permitted."])
        if passwd:
            self.cache["homes"]=sorted(set(homes))

    def sudo(self):
        out=self.run_cmd(["sudo","-n","-l"])
        if not out:
            out=self.run_cmd(["sudo","-l"])
        if out and ("NOPASSWD" in out or "(ALL" in out or "(root" in out):
            self.add(id="SUDO-001",category="privileges",title="Sudo policy grants potentially elevated command execution",severity="HIGH",confidence="HIGH",score=82,evidence=[self.redact_text(out)],why_it_matters="The current account appears to have one or more elevated sudo permissions. Actual risk depends on command arguments and policy details.",verification=["sudo -l"],research=["Review each permitted command against the official sudoers documentation and current GTFOBins research where applicable."],recommended_tools=["sudo"],next_steps=["Inspect each permitted command for scope, arguments, environment and writable dependencies."],references=["https://www.sudo.ws/docs/"])

    def suid_caps(self):
        roots=[]
        for base in ("/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin","/opt"):
            if not os.path.isdir(base): continue
            try:
                for root,dirs,files in os.walk(base):
                    dirs[:]=[d for d in dirs if d not in {"proc","sys","dev"}]
                    for name in files:
                        p=os.path.join(root,name)
                        try:
                            st=os.stat(p,follow_symlinks=False)
                            if st.st_mode & stat.S_ISUID: roots.append(p)
                        except OSError: pass
                    if len(roots)>200: break
            except OSError: pass
        if roots:
            common={"/usr/bin/passwd","/usr/bin/su","/usr/bin/sudo","/usr/bin/mount","/usr/bin/umount","/usr/bin/chsh","/usr/bin/chfn"}
            unusual=[p for p in roots if p not in common]
            if unusual:
                self.add(id="SUID-001",category="privileges",title="Unusual SUID binaries detected",severity="HIGH",confidence="MEDIUM",score=78,evidence=unusual[:30],why_it_matters="SUID programs execute with the file owner's effective privileges; unusual entries deserve review for intended use, version and controllability.",verification=["find / -perm -4000 -type f 2>/dev/null","ls -la <binary>","file <binary>","readelf -h <binary>"],research=["Check the binary and version against vendor advisories and GTFOBins-style documentation. Do not assume presence equals exploitability."],recommended_tools=["file","readelf","strings","ldd"],next_steps=["Prioritize unusual SUID binaries and inspect ownership, dependencies and user-controllable inputs."])

        caps=self.run_cmd(["getcap","-r","/","2>/dev/null"])
        # getcap accepts shell redirection only with a shell, so retry with standard known roots.
        if not caps and shutil.which("getcap"):
            for d in ("/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin"):
                x=self.run_cmd(["getcap","-r",d]); caps += x
        if caps.strip():
            interesting=[x for x in caps.splitlines() if any(k in x.lower() for k in ("cap_setuid","cap_dac_override","cap_sys_admin","cap_net_raw"))]
            if interesting:
                self.add(id="CAP-001",category="privileges",title="Security-sensitive file capabilities detected",severity="HIGH",confidence="HIGH",score=80,evidence=interesting[:30],why_it_matters="Linux capabilities can grant privileged operations without traditional SUID bits. Impact depends on the capability, binary behavior and execution context.",verification=["getcap -r /bin /sbin /usr/bin /usr/sbin 2>/dev/null"],research=["Review Linux capabilities documentation and the specific binary's security model."],recommended_tools=["getcap","getpcaps","readelf"],next_steps=["Inspect each capability-bearing binary and determine whether an unprivileged user can invoke it."])

    def writable_privileged(self):
        candidates=[]
        for d in ("/etc/systemd/system","/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/etc/cron.weekly","/etc/cron.monthly"):
            if not os.path.isdir(d): continue
            try:
                for p in Path(d).rglob("*"):
                    try:
                        if p.is_file() and os.access(p,os.W_OK): candidates.append(str(p))
                    except OSError: pass
            except OSError: pass
        if candidates:
            self.add(id="WRITE-001",category="filesystem",title="Writable privileged configuration/script candidate",severity="HIGH",confidence="HIGH",score=88,evidence=candidates[:40],why_it_matters="A user-writable service or scheduled-task file may influence privileged execution. The execution path must be verified before treating this as exploitable.",verification=["stat <path>","ls -la <path>","systemctl cat <service>"],research=["Determine the execution account, trigger, referenced files and package ownership."],recommended_tools=["stat","systemctl","namei"],next_steps=["Trace each writable file to the service/timer/cron job that consumes it and confirm the execution context."])

    def cron_services(self):
        cron=self.read("/etc/crontab")
        if cron and re.search(r"(?m)^\s*[^#].*\broot\b",cron):
            self.add(id="CRON-001",category="cron",title="Root cron configuration is present and should be reviewed",severity="MEDIUM",confidence="HIGH",score=52,evidence=["/etc/crontab contains root-owned scheduled entries"],why_it_matters="Scheduled root execution creates an important audit surface, especially when referenced scripts or directories are writable.",verification=["cat /etc/crontab","ls -la /etc/cron.d","systemctl list-timers --all"],research=["Review ownership, permissions, PATH usage and package provenance of each root task."],recommended_tools=["systemctl","stat"],next_steps=["Inspect root scheduled commands and trace every referenced path for user controllability."])
        timers=self.run_cmd(["systemctl","list-timers","--all","--no-pager"])
        self.cache["timers"]=bool(timers.strip())

    def processes_network(self):
        ps=self.run_cmd(["ps","-eo","user,pid,ppid,args","--sort=user"])
        if ps: self.cache["processes"]=ps
        ss=self.run_cmd(["ss","-lntup"])
        if ss: self.cache["listeners"]=ss
        if ss and len(ss.splitlines())>1:
            self.add(id="NET-001",category="network",title="Local listening services detected",severity="INFO",confidence="HIGH",score=20,evidence=ss.splitlines()[:30],why_it_matters="Listening services expand the local attack surface and should be mapped to expected applications and configurations.",verification=["ss -lntup","systemctl --type=service --state=running"],research=["Identify service versions and compare them with current vendor/distribution advisories."],recommended_tools=["ss","lsof"],next_steps=["Map unexpected listeners to owning processes and review their configuration."])

    def packages_apps(self):
        commands=[("dpkg-query","-W","-f=${Package} ${Version}\\n"),("rpm","-qa"),("apk","info")]
        pkg=""
        for c in commands:
            if shutil.which(c[0]): pkg=self.run_cmd(list(c)); self.cache["package_manager"]=c[0]; break
        if pkg:
            focus=[]
            for line in pkg.splitlines():
                if re.search(r"\b(sudo|polkit|pkexec|openssh|openssl|systemd|docker|containerd|nginx|apache2|httpd)\b",line,re.I): focus.append(line)
            self.cache["packages"]=focus[:100]
        for name in ("apache2","httpd","nginx","sshd","docker","containerd","redis-server","mysqld","postgres"):
            if shutil.which(name):
                v=self.run_cmd([name,"--version"]) or self.run_cmd([name,"-V"])
                if v: self.cache.setdefault("apps",[]).append(v.strip().splitlines()[0][:200])

    def ssh_container_cloud(self):
        ssh=self.read("/etc/ssh/sshd_config")
        if ssh:
            bad=[]
            for key in ("PermitRootLogin","PasswordAuthentication","PermitEmptyPasswords"):
                m=re.search(rf"(?im)^\s*{key}\s+(\S+)",ssh)
                if m: bad.append(f"{key}={m.group(1)}")
            if bad:
                self.add(id="SSH-001",category="ssh",title="SSH authentication posture requires review",severity="MEDIUM",confidence="HIGH",score=45,evidence=bad,why_it_matters="SSH authentication settings influence remote access exposure and credential attack surface.",verification=["sshd -T"],research=["Compare effective sshd settings with organizational hardening guidance."],recommended_tools=["sshd"],next_steps=["Review effective SSH configuration and confirm only intended authentication methods are enabled."])
        if Path("/var/run/docker.sock").exists():
            self.add(id="CONT-001",category="container",title="Docker socket is present",severity="HIGH",confidence="HIGH",score=76,evidence=["/var/run/docker.sock"],why_it_matters="Access to the Docker daemon can confer substantial control over containers and potentially host resources; actual impact depends on socket permissions and group membership.",verification=["stat /var/run/docker.sock","id -Gn"],research=["Review Docker daemon access controls and official container security guidance."],recommended_tools=["docker","stat"],next_steps=["Check socket ownership/permissions and whether the current account can access the daemon."])
        env=[]
        for k in ("AWS_EXECUTION_ENV","AWS_REGION","GOOGLE_CLOUD_PROJECT","AZURE_HTTP_USER_AGENT"):
            if os.environ.get(k): env.append(k)
        if env:
            self.add(id="CLOUD-001",category="cloud",title="Cloud environment indicators detected",severity="INFO",confidence="MEDIUM",score=15,evidence=env,why_it_matters="Cloud runtime indicators can change the security model and warrant identity, agent and metadata-access review.",verification=["env | grep -E '^(AWS|GOOGLE|AZURE)_'"],research=["Use the cloud provider's official workload identity and metadata security guidance."],recommended_tools=["env"],next_steps=["Identify the workload identity mechanism and review its least-privilege permissions."])

    def secrets(self):
        if self.args.no_secrets: return
        hits=[]
        patterns=[re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[^\s]+"),re.compile(r"AKIA[0-9A-Z]{16}")]
        for base in ("/etc","/opt"):
            if not os.path.isdir(base): continue
            try:
                for p in Path(base).rglob("*"):
                    if len(hits)>=30: break
                    try:
                        if p.is_file() and p.stat().st_size<2_000_000:
                            txt=self.read(str(p),32768)
                            if any(rx.search(txt) for rx in patterns): hits.append(str(p))
                    except OSError: pass
            except OSError: pass
        if hits:
            self.add(id="SECRET-001",category="secrets",title="Potential secret-bearing configuration artifacts found",severity="HIGH",confidence="MEDIUM",score=74,evidence=[f"{p} [REDACTED CONTENT]" for p in hits],why_it_matters="Configuration artifacts may contain credentials or tokens. The tool intentionally does not print secret values.",verification=["stat <path>","grep -nE 'api[_-]?key|secret|password|token' <path>  # inspect locally and securely"],research=["Identify the owning application, rotate exposed credentials when appropriate and review file permissions."],recommended_tools=["stat","grep"],next_steps=["Validate whether the indicators are real credentials, then secure/rotate them according to the application's process."])

    def correlate(self):
        ids={f.id for f in self.findings}
        if "SUID-001" in ids and "WRITE-001" in ids:
            self.add(id="CORR-001",category="correlation",title="Multiple privilege-escalation surfaces reinforce each other",severity="CRITICAL",confidence="MEDIUM",score=94,evidence=["Unusual SUID binaries","Writable privileged configuration/script candidate"],why_it_matters="Independent high-risk surfaces can form a stronger privilege-escalation candidate when the execution paths intersect. Correlation is a research signal, not proof of exploitability.",verification=["Review the specific SUID binary and writable privileged path independently.","Trace ownership and execution flow."],research=["Validate whether a common execution path exists and whether user-controlled input reaches privileged code."],recommended_tools=["file","readelf","stat","namei"],next_steps=["Trace the two findings for a concrete, authorized attack path without executing payloads."])
        if "CAP-001" in ids and "SUDO-001" in ids:
            self.add(id="CORR-002",category="correlation",title="Administrative policy and capability findings overlap",severity="HIGH",confidence="MEDIUM",score=89,evidence=["Sudo elevation candidate","Security-sensitive file capability"],why_it_matters="Multiple privilege mechanisms may materially increase impact when they are reachable by the same account.",verification=["sudo -l","getcap -r /bin /sbin /usr/bin /usr/sbin 2>/dev/null"],research=["Assess reachability and intended administrative controls for each mechanism."],recommended_tools=["sudo","getcap"],next_steps=["Establish the minimal privilege path supported by local evidence."])

    def redact_text(self,s):
        if not self.redact: return s
        return re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+",r"\1=[REDACTED]",s)

    def run(self):
        modules={"system":self.system,"users":self.users,"sudo":self.sudo,"suid":self.suid_caps,"filesystem":self.writable_privileged,"cron":self.cron_services,"process":self.processes_network,"packages":self.packages_apps,"ssh":self.ssh_container_cloud,"secrets":self.secrets}
        selected=self.args.only or list(modules); skipped=set(self.args.skip)
        for name in selected:
            if name in modules and name not in skipped:
                try: modules[name]()
                except Exception as e:
                    print(f"{C.YELLOW}[WARN]{C.RESET} module {name} failed safely: {e}",file=sys.stderr)
        self.correlate(); self.render()

    def render(self):
        order={"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}; fs=sorted(self.findings,key=lambda x:(-order.get(x.severity,0),-x.score))
        print(f"\n{C.BOLD}=== LINUX-RECON-X SECURITY ASSESSMENT ==={C.RESET}")
        print(f"Findings: {len(fs)} | Runtime: {time.time()-self.start:.1f}s")
        for f in fs:
            col={"CRITICAL":C.RED,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.BLUE,"INFO":C.CYAN}.get(f.severity,C.RESET)
            print(f"\n{col}[{f.severity}]{C.RESET} {f.title}  | score={f.score}/100 | confidence={f.confidence}")
            if self.args.expert or f.severity!="INFO":
                print("  Evidence:"); [print("   -",x) for x in f.evidence[:10]]
                print("  Why:",f.why_it_matters)
                print("  Verify:"); [print("   -",x) for x in f.verification[:5]]
                print("  Research:"); [print("   -",x) for x in f.research[:4]]
                print("  Tools:",", ".join(f.recommended_tools) or "none")
                print("  Next:"); [print("   -",x) for x in f.next_steps[:4]]
        counts={s:sum(f.severity==s for f in fs) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
        print("\n"+C.BOLD+"=== RECOMMENDED NEXT STEPS ==="+C.RESET)
        seen=[]
        for f in fs:
            for step in f.next_steps:
                if step not in seen: seen.append(step)
        for i,s in enumerate(seen[:5],1): print(f"[{i}] {s}")
        print(f"\nSummary: "+" | ".join(f"{k}: {v}" for k,v in counts.items()))
        if self.args.json_file: self.write_json(fs)
        if self.args.csv_file: self.write_csv(fs)
        if self.args.markdown_file: self.write_md(fs)

    def write_json(self,fs):
        Path(self.args.json_file).write_text(json.dumps({"tool":"Linux-Recon-X","version":VERSION,"host":self.cache,"findings":[asdict(f) for f in fs]},indent=2),encoding="utf-8")
    def write_csv(self,fs):
        with open(self.args.csv_file,"w",newline="",encoding="utf-8") as h:
            w=csv.writer(h); w.writerow(["id","category","title","severity","confidence","score","evidence"])
            for f in fs: w.writerow([f.id,f.category,f.title,f.severity,f.confidence,f.score," | ".join(f.evidence)])
    def write_md(self,fs):
        lines=[f"# Linux-Recon-X Assessment\n",f"Version: {VERSION}\n",f"Host context: `{self.cache}`\n"]
        for f in fs:
            lines += [f"## [{f.severity}] {f.title}",f"**Score:** {f.score}/100  **Confidence:** {f.confidence}","","### Evidence"]+[f"- {x}" for x in f.evidence[:20]]+["","### Why it matters",f.why_it_matters,"","### Verification"]+[f"- `{x}`" for x in f.verification]+["","### Research"]+[f"- {x}" for x in f.research]+["","### Next steps"]+[f"- {x}" for x in f.next_steps]+[""]
        Path(self.args.markdown_file).write_text("\n".join(lines),encoding="utf-8")

def parse():
    p=argparse.ArgumentParser(description="Linux-Recon-X: read-only Linux security enumeration and research assistant")
    p.add_argument("--quiet",action="store_true"); p.add_argument("--verbose",action="store_true"); p.add_argument("--expert",action="store_true")
    p.add_argument("--json",dest="json_file"); p.add_argument("--csv",dest="csv_file"); p.add_argument("--markdown",dest="markdown_file")
    p.add_argument("--offline",action="store_true",help="disable Internet research; core mode is offline by default")
    p.add_argument("--research",action="store_true",help="reserved for optional future vulnerability research providers")
    p.add_argument("--no-network",action="store_true"); p.add_argument("--no-secrets",action="store_true"); p.add_argument("--no-color",action="store_true")
    p.add_argument("--timeout",type=int,default=4); p.add_argument("--only",action="append",choices=["system","users","sudo","suid","filesystem","cron","process","packages","ssh","secrets"])
    p.add_argument("--skip",action="append",default=[]); p.add_argument("--max-output",type=int,default=65536); p.add_argument("--version",action="version",version=VERSION)
    return p.parse_args()

def main():
    global C
    args=parse()
    if args.no_color or not sys.stdout.isatty():
        for k in ("RESET","BOLD","RED","YELLOW","GREEN","CYAN","MAGENTA","BLUE"): setattr(C,k,"")
    if os.geteuid()!=0: print(f"{C.YELLOW}[WARN]{C.RESET} Running unprivileged; some checks will be incomplete.")
    print(f"{C.BOLD}Linux-Recon-X v{VERSION}{C.RESET} | read-only enumeration / research")
    Engine(args).run()
if __name__=="__main__": main()
