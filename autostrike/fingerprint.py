"""Turn open ports and raw banners into named services with product and version."""
from __future__ import annotations

import re

from autostrike.models import Host, Service

PORT_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8000: "http", 8080: "http", 8443: "https", 9200: "elasticsearch",
}

# (regex, service name, product, port restriction or None). First match wins.
SIGNATURES: list[tuple[str, str, str, int | None]] = [
    (r"SSH-[\d.]+-OpenSSH_([\w.]+)", "ssh", "OpenSSH", None),
    (r"\(vsFTPd ([\d.]+)\)", "ftp", "vsftpd", None),
    (r"ProFTPD ([\d.]+)", "ftp", "ProFTPD", None),
    (r"Apache Tomcat/([\d.]+)", "http", "Apache Tomcat", None),
    (r"Server: Apache/([\d.]+)", "http", "Apache httpd", None),
    (r"Server: nginx/([\d.]+)", "http", "nginx", None),
    (r"Microsoft-IIS/([\d.]+)", "http", "Microsoft IIS", None),
    (r"Samba ([\d.]+)", "smb", "Samba", None),
    (r"SMBv1", "smb", "SMBv1", None),
    (r"^\+PONG", "redis", "Redis", 6379),
    (r"^-NOAUTH", "redis", "Redis", 6379),
    (r"(\d+\.\d+\.\d+)", "mysql", "MySQL", 3306),
]

WINDOWS_HINTS = {135, 139, 445, 3389, 5985}


def identify(port: int, banner: str) -> Service:
    svc = Service(port=port, name=PORT_NAMES.get(port, "unknown"), banner=banner[:300])
    for pattern, name, product, only_port in SIGNATURES:
        if only_port is not None and port != only_port:
            continue
        m = re.search(pattern, banner, re.MULTILINE)
        if m:
            svc.name = name
            svc.product = product
            svc.version = next((g for g in m.groups() if g), "") if m.groups() else ""
            break
    return svc


def guess_os(host: Host) -> str:
    banners = " ".join(s.banner for s in host.services).lower()
    # Banner evidence beats port heuristics (e.g. xrdp on Linux still opens 3389).
    if "windows" in banners:
        return "windows"
    if any(k in banners for k in ("ubuntu", "debian", "centos", "linux", "unix")):
        return "linux"
    if host.ports() & WINDOWS_HINTS:
        return "windows"
    if "openssh" in banners:
        return "linux"
    return "unknown"


def version_tuple(version: str) -> tuple[int, ...]:
    """'7.4p1' -> (7, 4, 1); used for range checks in the vulnerability rules."""
    return tuple(int(x) for x in re.findall(r"\d+", version))
