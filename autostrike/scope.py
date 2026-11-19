"""Engagement scope: the only addresses Auto Strike is ever allowed to touch."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable, Iterator

MAX_SCOPE_ADDRESSES = 4096


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope or the scope is unsafe."""


class Scope:
    def __init__(self, entries: Iterable[str], allow_public: bool = False) -> None:
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in entries:
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ScopeError(f"invalid scope entry {entry!r}: {exc}") from exc
            if not allow_public and not (net.is_private or net.is_loopback):
                raise ScopeError(
                    f"{entry} is a public range. Only test systems you own or have written "
                    "permission to test, and pass --allow-public explicitly."
                )
            self.networks.append(net)
        if not self.networks:
            raise ScopeError("scope is empty")
        total = sum(n.num_addresses for n in self.networks)
        if total > MAX_SCOPE_ADDRESSES:
            raise ScopeError(
                f"scope covers {total} addresses (limit {MAX_SCOPE_ADDRESSES}); split the engagement"
            )

    @classmethod
    def from_file(cls, path: str | Path, allow_public: bool = False) -> "Scope":
        return cls(Path(path).read_text(encoding="utf-8").splitlines(), allow_public=allow_public)

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def require(self, ip: str) -> None:
        if not self.contains(ip):
            raise ScopeError(f"{ip} is outside the authorised scope")

    def addresses(self) -> Iterator[str]:
        seen: set[str] = set()
        for net in self.networks:
            candidates = net if net.num_addresses <= 2 else net.hosts()
            for addr in candidates:
                s = str(addr)
                if s not in seen:
                    seen.add(s)
                    yield s

    def __str__(self) -> str:
        return ", ".join(str(n) for n in self.networks)
