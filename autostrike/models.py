"""Engagement state shared between phases and persisted as JSON after every phase."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Host:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)

    def ports(self) -> set[int]:
        return {s.port for s in self.services}


@dataclass
class Finding:
    rule_id: str
    host: str
    port: int
    title: str
    severity: str
    technique: str
    description: str
    remediation: str
    evidence: str
    cve: Optional[str] = None


@dataclass
class PostStep:
    host: str
    order: int
    tactic: str
    technique: str
    action: str
    rationale: str


@dataclass
class PhaseRecord:
    name: str
    started: str
    finished: str
    summary: str


@dataclass
class Engagement:
    name: str
    mode: str  # "demo", "live" or "import"
    scope: list[str]
    live_hosts: list[str] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    post_plan: list[PostStep] = field(default_factory=list)
    phases: list[PhaseRecord] = field(default_factory=list)

    def host(self, ip: str) -> Optional[Host]:
        return next((h for h in self.hosts if h.ip == ip), None)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict) -> "Engagement":
        hosts = [
            Host(**{**h, "services": [Service(**s) for s in h.get("services", [])]})
            for h in data.get("hosts", [])
        ]
        return cls(
            name=data["name"],
            mode=data["mode"],
            scope=list(data.get("scope", [])),
            live_hosts=list(data.get("live_hosts", [])),
            hosts=hosts,
            findings=[Finding(**f) for f in data.get("findings", [])],
            post_plan=[PostStep(**p) for p in data.get("post_plan", [])],
            phases=[PhaseRecord(**p) for p in data.get("phases", [])],
        )

    @classmethod
    def load(cls, path: str | Path) -> "Engagement":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
