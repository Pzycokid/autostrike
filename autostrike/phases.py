"""The five kill-chain phases. Each one reads the Engagement produced so far and adds to it."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from importlib import resources
from typing import Iterable

from autostrike.fingerprint import guess_os, identify, version_tuple
from autostrike.models import Engagement, Finding, Host, PostStep, Service
from autostrike.transport import Transport

# Ports used to decide whether a host is alive (TCP connect, no ICMP needed).
DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 21, 23, 53, 88, 139, 3306, 8080]

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 1433, 3306,
    3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 9200,
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FOOTHOLD_TECHNIQUES = {"T1190", "T1078.001", "T1210"}


def load_json(name: str):
    return json.loads(resources.files("autostrike.data").joinpath(name).read_text(encoding="utf-8"))


@dataclass
class RunOptions:
    targets: Iterable[str] = ()
    ports: list[int] = field(default_factory=lambda: list(TOP_PORTS))
    workers: int = 32


class Phase:
    name = "phase"

    def run(self, eng: Engagement, transport: Transport | None, opts: RunOptions) -> str:
        raise NotImplementedError


class ReconPhase(Phase):
    """Host discovery across the authorised scope (ATT&CK T1595.001)."""

    name = "recon"

    def run(self, eng, transport, opts):
        targets = list(opts.targets)

        def alive(ip: str) -> str | None:
            for port in DISCOVERY_PORTS:
                if transport.probe(ip, port):
                    return ip
            return None

        with ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool:
            found = [ip for ip in pool.map(alive, targets) if ip]
        eng.live_hosts = sorted(found, key=_ip_key)
        return f"{len(eng.live_hosts)} live host(s) out of {len(targets)} address(es) probed"


class EnumerationPhase(Phase):
    """Port scan and banner grab on every live host (ATT&CK T1046)."""

    name = "enumeration"

    def run(self, eng, transport, opts):
        def scan(ip: str) -> Host:
            host = Host(ip=ip, hostname=transport.hostname(ip))
            for port in opts.ports:
                if transport.probe(ip, port):
                    host.services.append(identify(port, transport.banner(ip, port)))
            host.os_guess = guess_os(host)
            return host

        with ThreadPoolExecutor(max_workers=max(1, min(opts.workers, 8))) as pool:
            eng.hosts = list(pool.map(scan, eng.live_hosts))
        n = sum(len(h.services) for h in eng.hosts)
        return f"{n} open service(s) fingerprinted on {len(eng.hosts)} host(s)"


class ExploitSimPhase(Phase):
    """Match fingerprinted services to known weaknesses. Nothing is exploited: this phase only
    reasons about what an attacker could do, using the rules in data/vuln_rules.json."""

    name = "exploitation-sim"

    def __init__(self, rules: list[dict] | None = None) -> None:
        self.rules = rules if rules is not None else load_json("vuln_rules.json")

    def run(self, eng, transport, opts):
        eng.findings = []
        for host in eng.hosts:
            for svc in host.services:
                for rule in self.rules:
                    if rule_matches(rule["match"], svc):
                        eng.findings.append(
                            Finding(
                                rule_id=rule["id"],
                                host=host.ip,
                                port=svc.port,
                                title=rule["title"],
                                severity=rule["severity"],
                                technique=rule["technique"],
                                description=rule["description"],
                                remediation=rule["remediation"],
                                evidence=_evidence(svc),
                                cve=rule.get("cve"),
                            )
                        )
        eng.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), _ip_key(f.host), f.port))
        crit = sum(f.severity == "critical" for f in eng.findings)
        return f"{len(eng.findings)} finding(s), {crit} critical"


class PostExploitSimPhase(Phase):
    """Plan, but never execute, what an operator would do after each foothold."""

    name = "post-exploitation-sim"

    def run(self, eng, transport, opts):
        eng.post_plan = []
        footholds = {}
        for f in eng.findings:
            if f.technique in FOOTHOLD_TECHNIQUES and f.severity in ("critical", "high"):
                footholds.setdefault(f.host, f)
        for ip, finding in footholds.items():
            host = eng.host(ip)
            eng.post_plan.extend(plan_for(host, finding, eng.hosts))
        return f"{len(eng.post_plan)} simulated step(s) across {len(footholds)} foothold(s)"


class ReportPhase(Phase):
    name = "reporting"

    def __init__(self, outdir) -> None:
        self.outdir = outdir

    def run(self, eng, transport, opts):
        from autostrike.report import write_reports

        paths = write_reports(eng, self.outdir)
        return "wrote " + ", ".join(p.name for p in paths)


def rule_matches(match: dict, svc: Service) -> bool:
    if "product" in match and match["product"].lower() != svc.product.lower():
        return False
    if "name" in match and match["name"] != svc.name:
        return False
    if "banner_contains" in match and match["banner_contains"].lower() not in svc.banner.lower():
        return False
    version_keys = [k for k in match if k.startswith("version_")]
    if version_keys:
        if not svc.version:
            return False
        v = version_tuple(svc.version)
        for key in version_keys:
            ref = version_tuple(match[key])
            ok = {
                "version_eq": v == ref,
                "version_lt": v < ref,
                "version_lte": v <= ref,
                "version_gte": v >= ref,
            }.get(key, False)
            if not ok:
                return False
    return True


def plan_for(host: Host, finding: Finding, all_hosts: list[Host]) -> list[PostStep]:
    windows = host.os_guess == "windows"
    steps = [
        ("Discovery", "T1082",
         "Collect OS, patch level and architecture" + (" (systeminfo)" if windows else " (uname -a, /etc/os-release)"),
         f"Foothold via {finding.title}; confirms what privilege-escalation paths apply"),
        ("Discovery", "T1083",
         "List user profiles, web roots and backup folders for interesting files",
         "Locates configuration files that commonly hold credentials"),
        ("Credential Access", "T1552.001",
         "Search config files (.env, web.config, *.ini) for stored passwords",
         "Cheapest route to credentials before touching memory"),
        ("Credential Access", "T1003.001" if windows else "T1003.008",
         "Dump LSASS memory" if windows else "Read /etc/shadow if privileges allow",
         "Harvests hashes for offline cracking or pass-the-hash"),
        ("Persistence", "T1053.005" if windows else "T1053.003",
         "Register a scheduled task" if windows else "Add a cron entry",
         "Keeps access across reboots; defenders should alert on new tasks/cron jobs"),
    ]
    for other in all_hosts:
        if other.ip == host.ip:
            continue
        ports = other.ports()
        if 445 in ports:
            steps.append(("Lateral Movement", "T1021.002",
                          f"Reuse harvested credentials against {other.ip} over SMB admin shares",
                          f"{other.ip} exposes TCP 445"))
        elif 22 in ports:
            steps.append(("Lateral Movement", "T1021.004",
                          f"Try harvested keys/passwords on {other.ip} over SSH",
                          f"{other.ip} exposes TCP 22"))
        elif 3389 in ports:
            steps.append(("Lateral Movement", "T1021.001",
                          f"Attempt RDP to {other.ip} with harvested credentials",
                          f"{other.ip} exposes TCP 3389"))
    steps.append(("Collection", "T1005", "Stage data of interest locally for the report (simulated only)",
                  "Shows impact without moving real data"))
    return [
        PostStep(host=host.ip, order=i + 1, tactic=t, technique=tech, action=a, rationale=r)
        for i, (t, tech, a, r) in enumerate(steps)
    ]


def _evidence(svc: Service) -> str:
    ident = " ".join(x for x in (svc.product, svc.version) if x) or svc.name
    first_line = svc.banner.splitlines()[0] if svc.banner else ""
    return f"{svc.port}/{svc.proto} {ident}" + (f" | banner: {first_line[:80]}" if first_line else "")


def _ip_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (999, ip)
