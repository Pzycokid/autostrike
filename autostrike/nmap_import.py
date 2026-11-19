"""Import an existing `nmap -sV -oX` scan so recon/enumeration can be skipped.

Only import XML you generated yourself: the standard-library parser is used, which is fine for
trusted local files but is not hardened against hostile XML.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from autostrike.fingerprint import guess_os
from autostrike.models import Host, Service

PRODUCT_ALIASES = {
    "samba smbd": "Samba",
    "openssh": "OpenSSH",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "apache httpd": "Apache httpd",
    "apache tomcat": "Apache Tomcat",
    "mysql": "MySQL",
    "redis key-value store": "Redis",
    "nginx": "nginx",
    "microsoft iis httpd": "Microsoft IIS",
}

NAME_ALIASES = {"microsoft-ds": "smb", "ms-wbt-server": "rdp", "netbios-ssn": "netbios-ssn", "http-proxy": "http"}


def normalise_product(product: str) -> str:
    return PRODUCT_ALIASES.get(product.strip().lower(), product.strip())


def parse_nmap_xml(path: str | Path) -> list[Host]:
    root = ET.parse(path).getroot()
    hosts: list[Host] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = h.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = h.find("address")
        if addr is None:
            continue
        hn = h.find("hostnames/hostname")
        host = Host(ip=addr.get("addr", ""), hostname=hn.get("name", "") if hn is not None else "")
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            s = p.find("service")
            name = s.get("name", "") if s is not None else ""
            product = s.get("product", "") if s is not None else ""
            extra = " ".join(filter(None, [s.get("extrainfo", ""), s.get("ostype", "")])) if s is not None else ""
            host.services.append(
                Service(
                    port=int(p.get("portid", "0")),
                    proto=p.get("protocol", "tcp"),
                    name=NAME_ALIASES.get(name, name),
                    product=normalise_product(product),
                    version=s.get("version", "") if s is not None else "",
                    banner=" ".join(filter(None, [product, s.get("version", "") if s is not None else "", extra])),
                )
            )
        host.os_guess = guess_os(host)
        hosts.append(host)
    return hosts
