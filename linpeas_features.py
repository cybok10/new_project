"""Extended Linux-Recon-X enumeration modules.

Behavioral coverage inspired by public LinPEAS documentation/check families,
implemented independently and kept read-only. No exploit execution or secret
exfiltration is performed.
"""
from pathlib import Path
import os, re, shutil, stat
from typing import Any


def register(engine):
    return {
        "environment": lambda: environment(engine),
        "filesystem": lambda: filesystem(engine),
        "interesting_files": lambda: interesting_files(engine),
        "permissions": lambda: permissions(engine),
        "path": lambda: path_environment(engine),
        "mounts": lambda: mounts(engine),
        "nfs_samba": lambda: nfs_samba(engine),
        "systemd": lambda: systemd(engine),
        "network": lambda: network(engine),
        "firewall": lambda: firewall(engine),
        "ssh_deep": lambda: ssh_deep(engine),
        "web": lambda: web(engine),
        "databases": lambda: databases(engine),
        "dev_tools": lambda: dev_tools(engine),
        "kernel_security": lambda: kernel_security(engine),
        "container_deep": lambda: container_deep(engine),
        "accounts": lambda: accounts(engine),
        "history": lambda: history(engine),
    }


def add(e, **kw): e.add(**kw)
def cmd(e, *a): return e.run_cmd(list(a))
def read(e, p, n=65536): return e.read(p, n)


def environment(e):
    env=[]
    for k,v in os.environ.items():
        if re.search(r"(?i)(pass|secret|token|key|credential)", k): env.append(k+"=[REDACTED]")
        elif k in ("PATH","LD_PRELOAD","LD_LIBRARY_PATH","PYTHONPATH","PERL5LIB","RUBYLIB"): env.append(k+"="+v[:500])
    if env:
        add(e,id="ENV-001",category="environment",title="Security-relevant environment variables",severity="MEDIUM",confidence="HIGH",score=40,evidence=env,why_it_matters="Environment variables can alter command resolution, library loading or application behavior. Values resembling credentials are redacted.",verification=["env","printf '%s\\n' \"$PATH\""],research=["Review writable PATH components and whether privileged programs inherit risky environment variables."],recommended_tools=["env","namei"],next_steps=["Check whether any privileged execution context inherits user-controlled environment state."])


def filesystem(e):
    paths=[]
    for p in ("/etc/passwd","/etc/shadow","/etc/group","/etc/gshadow","/etc/sudoers","/etc/sudoers.d"):
        try:
            st=os.stat(p); paths.append(f"{p} mode={oct(st.st_mode & 0o7777)} owner={st.st_uid}:{st.st_gid}")
        except OSError: pass
    if paths: e.cache["sensitive_permissions"]=paths
    world=[]
    for base in ("/tmp","/var/tmp","/dev/shm"):
        if not os.path.isdir(base): continue
        try:
            for p in Path(base).iterdir():
                try:
                    st=p.stat();
                    if st.st_mode & stat.S_IWOTH: world.append(str(p))
                except OSError: pass
        except OSError: pass
    if world:
        add(e,id="FS-001",category="filesystem",title="World-writable temporary files/directories detected",severity="LOW",confidence="HIGH",score=28,evidence=world[:50],why_it_matters="World-writable paths can create race, tampering or unsafe temporary-file conditions depending on how applications use them.",verification=["ls -ld <path>","stat <path>"],research=["Determine whether privileged processes consume files from these locations."],recommended_tools=["stat","namei"],next_steps=["Trace suspicious temporary paths to consuming services or privileged jobs."])


def interesting_files(e):
    hits=[]
    names={".env",".env.local",".env.production","config.php","wp-config.php","database.yml","credentials","credentials.json","config.json","settings.py"}
    for base in ("/etc","/opt","/var/www","/srv"):
        if not os.path.isdir(base): continue
        try:
            for p in Path(base).rglob("*"):
                if len(hits)>=80: break
                try:
                    if p.is_file() and p.name in names and p.stat().st_size<5_000_000: hits.append(str(p))
                except OSError: pass
        except OSError: pass
    if hits:
        add(e,id="FILE-001",category="files",title="Interesting application/configuration files found",severity="MEDIUM",confidence="MEDIUM",score=48,evidence=hits,why_it_matters="Application configuration and environment files frequently contain security-sensitive settings or credentials and should be reviewed with appropriate access controls.",verification=["stat <path>","ls -la <path>"],research=["Identify the application owner, package provenance and whether secrets are required at runtime."],recommended_tools=["stat","grep"],next_steps=["Review permissions and secret indicators without exposing values in reports."])


def permissions(e):
    writable=[]
    for base in ("/etc","/usr/local/bin","/usr/local/sbin","/opt"):
        if not os.path.isdir(base): continue
        try:
            for p in Path(base).rglob("*"):
                if len(writable)>=100: break
                try:
                    if p.is_file() and os.access(p,os.W_OK) and p.stat().st_uid==0: writable.append(str(p))
                except OSError: pass
        except OSError: pass
    if writable:
        add(e,id="PERM-001",category="permissions",title="Root-owned writable files detected",severity="HIGH",confidence="HIGH",score=84,evidence=writable[:60],why_it_matters="A non-root user able to modify root-owned files may influence privileged programs, services or configuration.",verification=["stat <path>","namei -l <path>"],research=["Determine whether each file is executed, sourced, loaded or parsed by a privileged process."],recommended_tools=["stat","namei","lsof"],next_steps=["Prioritize files referenced by root services, timers, cron jobs and privileged binaries."])


def path_environment(e):
    path=os.environ.get("PATH","").split(":")
    writable=[]
    for p in path:
        if not p: p="."
        try:
            if os.path.isdir(p) and os.access(p,os.W_OK): writable.append(p)
        except OSError: pass
    if writable:
        add(e,id="PATH-001",category="environment",title="Writable PATH component",severity="MEDIUM",confidence="HIGH",score=58,evidence=writable,why_it_matters="A writable PATH directory can affect command resolution in contexts that rely on PATH without secure absolute paths.",verification=["printf '%s\\n' \"$PATH\"","ls -ld <directory>"],research=["Check whether privileged scripts or services invoke commands without absolute paths."],recommended_tools=["namei","grep"],next_steps=["Trace writable PATH components to privileged scripts before treating the condition as exploitable."])


def mounts(e):
    out=cmd(e,"findmnt","-rn") or read(e,"/proc/mounts")
    if out: e.cache["mounts"]=out[:50000]
    risky=[]
    for line in out.splitlines():
        if re.search(r"\\b(suid|dev|exec)\\b",line) and re.search(r"/tmp|/home|/mnt|/opt",line): risky.append(line)
    if risky:
        add(e,id="MOUNT-001",category="mounts",title="Security-relevant mount options detected",severity="LOW",confidence="MEDIUM",score=30,evidence=risky[:30],why_it_matters="Mount flags such as nosuid, nodev and noexec materially change execution and privilege boundaries.",verification=["findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS"],research=["Review whether sensitive mounts have the intended nosuid/nodev/noexec controls."],recommended_tools=["findmnt","mount"],next_steps=["Review unusual writable mounts and their consumers."])


def nfs_samba(e):
    out=read(e,"/etc/exports")
    if out and re.search(r"(?m)^\\s*[^#]",out):
        add(e,id="NFS-001",category="nfs",title="NFS export configuration present",severity="MEDIUM",confidence="HIGH",score=42,evidence=["/etc/exports contains active entries"],why_it_matters="Network filesystem exports can expose data and trust relationships depending on host restrictions and options.",verification=["cat /etc/exports","exportfs -v"],research=["Review host allowlists, root_squash and export permissions."],recommended_tools=["exportfs","showmount"],next_steps=["Audit every export for least privilege and appropriate root-squashing behavior."])
    smb=read(e,"/etc/samba/smb.conf")
    if smb:
        add(e,id="SMB-001",category="samba",title="Samba configuration present",severity="INFO",confidence="HIGH",score=20,evidence=["/etc/samba/smb.conf"],why_it_matters="SMB services expand the local and network attack surface and require configuration review.",verification=["testparm -s"],research=["Review share permissions, guest access and protocol settings."],recommended_tools=["testparm","smbclient"],next_steps=["Map shares to intended users and verify access controls."])


def systemd(e):
    out=cmd(e,"systemctl","list-units","--type=service","--all","--no-pager")
    if out:
        e.cache["services"]=out[:50000]
    unitdir=Path("/etc/systemd/system")
    writable=[]
    if unitdir.is_dir():
        try:
            for p in unitdir.rglob("*.service"):
                try:
                    if p.is_file() and os.access(p,os.W_OK): writable.append(str(p))
                except OSError: pass
        except OSError: pass
    if writable:
        add(e,id="SYSTEMD-001",category="services",title="Writable systemd service definitions",severity="HIGH",confidence="HIGH",score=88,evidence=writable,why_it_matters="Writable service definitions can influence the commands and environment used when a service starts.",verification=["systemctl cat <service>","stat <unit>"],research=["Trace ExecStart, User, EnvironmentFile and referenced paths."],recommended_tools=["systemctl","systemd-analyze","stat"],next_steps=["Review each writable unit's execution account and referenced files."])


def network(e):
    data={"interfaces":cmd(e,"ip","-br","addr"),"routes":cmd(e,"ip","route"),"neighbors":cmd(e,"ip","neigh"),"dns":read(e,"/etc/resolv.conf")}
    e.cache["network"]=data
    if data["interfaces"] or data["routes"]:
        add(e,id="NET-002",category="network",title="Host network configuration collected",severity="INFO",confidence="HIGH",score=10,evidence=[x for x in (data["interfaces"],data["routes"]) if x][:2],why_it_matters="Interfaces, routes and local services define the system's reachable attack surface.",verification=["ip -br addr","ip route","ss -lntup"],research=["Identify unexpected interfaces, routes and listeners."],recommended_tools=["ip","ss","lsof"],next_steps=["Map listeners to processes and verify that exposed services are intentional."])


def firewall(e):
    outputs=[]
    for c in (("nft","list","ruleset"),("iptables","-S"),("ufw","status")):
        x=cmd(e,*c)
        if x: outputs.append(x[:12000])
    if outputs:
        add(e,id="FW-001",category="firewall",title="Local firewall configuration detected",severity="INFO",confidence="HIGH",score=15,evidence=[x[:3000] for x in outputs],why_it_matters="Firewall policy determines which local services are reachable from network peers.",verification=["nft list ruleset","iptables -S","ufw status"],research=["Review policy against the expected host role and exposed services."],recommended_tools=["nft","iptables","ufw"],next_steps=["Identify listeners not covered by intended firewall policy."])


def ssh_deep(e):
    for p in ("/etc/ssh/sshd_config","/etc/ssh/ssh_config"):
        txt=read(e,p)
        if txt and re.search(r"(?im)^\\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups|PubkeyAuthentication|X11Forwarding|PermitUserEnvironment)",txt):
            add(e,id="SSH-002",category="ssh",title="Detailed SSH access-control settings found",severity="INFO",confidence="HIGH",score=20,evidence=[p],why_it_matters="SSH access-control directives affect remote authentication and session security.",verification=["sshd -T"],research=["Review effective settings and authorized-key permissions."],recommended_tools=["sshd","ssh-keygen"],next_steps=["Confirm remote access is limited to intended users and authentication methods."])


def web(e):
    found=[]
    for p in ("/etc/nginx","/etc/apache2","/etc/httpd","/var/www","/srv/www"):
        if os.path.exists(p): found.append(p)
    if found:
        add(e,id="WEB-001",category="web",title="Local web-server/application footprint detected",severity="INFO",confidence="HIGH",score=20,evidence=found,why_it_matters="Web applications introduce configuration, dependency and secret-management attack surfaces.",verification=["ss -lntup","nginx -T","apachectl -S"],research=["Identify server versions, virtual hosts, writable application paths and configuration secrets."],recommended_tools=["nginx","apachectl","curl"],next_steps=["Map web roots to listeners and review ownership and deployment configuration."])


def databases(e):
    found=[]
    for p in ("/etc/mysql","/etc/postgresql","/etc/redis","/var/lib/mysql","/var/lib/postgresql"):
        if os.path.exists(p): found.append(p)
    if found:
        add(e,id="DB-001",category="databases",title="Local database footprint detected",severity="INFO",confidence="HIGH",score=20,evidence=found,why_it_matters="Database services and configuration can expose sensitive data or credentials if misconfigured.",verification=["ss -lntup","systemctl --type=service --state=running"],research=["Review bind addresses, authentication, file permissions and service accounts."],recommended_tools=["ss","mysql","psql","redis-cli"],next_steps=["Identify database listeners and verify they are restricted to intended clients."])


def dev_tools(e):
    tools=[x for x in ("gcc","g++","make","python3","perl","ruby","php","java","go","rustc","gdb","strace","ltrace","git","curl","wget","nmap","nc") if shutil.which(x)]
    if tools:
        add(e,id="DEV-001",category="software",title="Development/diagnostic tools installed",severity="INFO",confidence="HIGH",score=10,evidence=tools,why_it_matters="Compilers, interpreters and diagnostic utilities affect the host's security and incident-response surface.",verification=["command -v <tool>","<tool> --version"],research=["Review whether privileged workflows expose these tools to untrusted users."],recommended_tools=tools[:12],next_steps=["Identify security-sensitive tools that are available to unprivileged accounts and determine whether that is intended."])


def kernel_security(e):
    mitigations=[]
    for p in ("/sys/devices/system/cpu/vulnerabilities","/sys/kernel/security/lsm","/proc/sys/kernel/kptr_restrict","/proc/sys/kernel/dmesg_restrict","/proc/sys/kernel/yama/ptrace_scope"):
        if os.path.isfile(p): mitigations.append(f"{p}: {read(e,p,2000).strip()}")
        elif os.path.isdir(p):
            try:
                for x in Path(p).iterdir(): mitigations.append(f"{x}: {read(e,str(x),500).strip()}")
            except OSError: pass
    if mitigations:
        add(e,id="KSEC-001",category="kernel",title="Kernel security-control posture collected",severity="INFO",confidence="HIGH",score=15,evidence=mitigations[:40],why_it_matters="Kernel hardening controls can materially affect exploitability and process isolation.",verification=["cat /proc/sys/kernel/kptr_restrict","cat /proc/sys/kernel/yama/ptrace_scope"],research=["Compare effective settings with distribution and organizational hardening guidance."],recommended_tools=["sysctl"],next_steps=["Review weak or absent kernel hardening controls where relevant to the host role."])


def container_deep(e):
    indicators=[]
    for p in ("/.dockerenv","/run/.containerenv","/var/run/docker.sock","/run/containerd/containerd.sock"):
        if os.path.exists(p): indicators.append(p)
    cgroup=read(e,"/proc/1/cgroup")
    if any(x in cgroup.lower() for x in ("docker","kubepods","containerd","lxc")): indicators.append("/proc/1/cgroup indicates container runtime")
    if indicators:
        add(e,id="CONT-002",category="container",title="Container/runtime security indicators",severity="MEDIUM",confidence="HIGH",score=45,evidence=indicators,why_it_matters="Container boundaries, runtime sockets and namespace configuration affect isolation and host exposure.",verification=["cat /proc/1/cgroup","cat /proc/self/status","stat /var/run/docker.sock"],research=["Review capabilities, mounts, namespaces, runtime socket permissions and Kubernetes service-account exposure."],recommended_tools=["docker","nsenter","capsh"],next_steps=["Determine whether the process is containerized and review runtime privileges without attempting escape."])


def accounts(e):
    passwd=read(e,"/etc/passwd"); shells=read(e,"/etc/shells")
    valid=set(x.strip() for x in shells.splitlines() if x and not x.startswith("#"))
    users=[]
    for line in passwd.splitlines():
        p=line.split(":")
        if len(p)>=7 and p[6] in valid and p[0] not in ("root",): users.append(p[0])
    if users:
        e.cache["interactive_users"]=users
    shadow=read(e,"/etc/shadow",2000)
    if shadow and os.access("/etc/shadow",os.R_OK):
        add(e,id="ACCT-001",category="accounts",title="Current user can read /etc/shadow",severity="CRITICAL",confidence="HIGH",score=96,evidence=["/etc/shadow is readable by the current process"],why_it_matters="Password-hash database access is highly sensitive and may enable credential compromise depending on password policy and hash strength.",verification=["test -r /etc/shadow && stat /etc/shadow"],research=["Treat shadow database access as a high-priority access-control failure; do not copy or disclose hashes."],recommended_tools=["stat"],next_steps=["Restrict access to /etc/shadow and investigate why the current account can read it."])


def history(e):
    paths=[]
    for home in e.cache.get("homes",[]):
        for name in (".bash_history",".zsh_history",".mysql_history",".psql_history",".python_history"):
            p=Path(home)/name
            try:
                if p.is_file() and os.access(p,os.R_OK): paths.append(str(p))
            except OSError: pass
    if paths:
        add(e,id="HIST-001",category="artifacts",title="Readable shell/application history files",severity="MEDIUM",confidence="HIGH",score=50,evidence=paths[:50],why_it_matters="History files can contain commands, hostnames or accidental credential material and should have appropriate permissions.",verification=["ls -la <history-file>","stat <history-file>"],research=["Review for sensitive material without exporting it to assessment reports."],recommended_tools=["stat","grep"],next_steps=["Audit history permissions and securely handle any discovered sensitive entries."])
