"""How phases talk to targets.

LiveTransport uses plain TCP connect probes (no raw packets, no admin rights) and refuses any
address outside the engagement scope. SimTransport replays a JSON description of a lab network,
so the whole kill chain can be demonstrated and tested offline.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Protocol

from autostrike.scope import Scope

# Ports where the server waits for the client to speak first, and what we send.
PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"PING\r\n",
}


class Transport(Protocol):
    def probe(self, ip: str, port: int) -> bool: ...

    def banner(self, ip: str, port: int) -> str: ...

    def hostname(self, ip: str) -> str: ...


class LiveTransport:
    def __init__(self, scope: Scope, timeout: float = 0.6) -> None:
        self.scope = scope
        self.timeout = timeout

    def probe(self, ip: str, port: int) -> bool:
        self.scope.require(ip)
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def banner(self, ip: str, port: int) -> str:
        self.scope.require(ip)
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout * 2)
                if port in PROBES:
                    sock.sendall(PROBES[port])
                data = sock.recv(2048)
        except OSError:
            return ""
        return data.decode("latin-1", "replace").strip()

    def hostname(self, ip: str) -> str:
        self.scope.require(ip)
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""


class SimTransport:
    """Replays a lab network described in JSON: {"hosts": [{"ip", "hostname", "ports": {port: banner}}]}."""

    def __init__(self, network: dict) -> None:
        self.name = network.get("name", "simulated lab")
        self._hosts: dict[str, dict] = {}
        for h in network.get("hosts", []):
            self._hosts[h["ip"]] = {
                "hostname": h.get("hostname", ""),
                "ports": {int(p): b for p, b in h.get("ports", {}).items()},
            }

    @classmethod
    def from_file(cls, path: str | Path) -> "SimTransport":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def known_ips(self) -> list[str]:
        return list(self._hosts)

    def probe(self, ip: str, port: int) -> bool:
        return port in self._hosts.get(ip, {}).get("ports", {})

    def banner(self, ip: str, port: int) -> str:
        return self._hosts.get(ip, {}).get("ports", {}).get(port, "")

    def hostname(self, ip: str) -> str:
        return self._hosts.get(ip, {}).get("hostname", "")
