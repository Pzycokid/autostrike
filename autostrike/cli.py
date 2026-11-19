"""Command line: `autostrike demo`, `autostrike run`, `autostrike import-nmap`, `autostrike report`."""
from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path

from autostrike import __version__
from autostrike.models import Engagement
from autostrike.nmap_import import parse_nmap_xml
from autostrike.phases import TOP_PORTS, RunOptions
from autostrike.pipeline import run_pipeline
from autostrike.report import write_reports
from autostrike.scope import Scope, ScopeError
from autostrike.transport import LiveTransport, SimTransport

BANNER = f"Auto Strike {__version__} - automated red team pipeline (authorised lab use only)"


def parse_ports(value: str) -> list[int]:
    if value == "top":
        return list(TOP_PORTS)
    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad or not ports:
        raise argparse.ArgumentTypeError(f"invalid port list: {value}")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autostrike", description=BANNER)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run the full kill chain against the built-in simulated lab")
    d.add_argument("--out", default="autostrike-demo", help="output directory")
    d.add_argument("--lab", help="custom simulated lab JSON (defaults to the bundled demo lab)")

    r = sub.add_parser("run", help="live run against an authorised, in-scope lab network")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--scope", help="file with one CIDR/IP per line")
    g.add_argument("--target", action="append", help="CIDR or IP (repeatable)")
    r.add_argument("--authorized", action="store_true",
                   help="confirm you own these systems or have written permission to test them")
    r.add_argument("--allow-public", action="store_true", help="permit non-private ranges in scope")
    r.add_argument("--ports", type=parse_ports, default=list(TOP_PORTS), help="'top' or e.g. 22,80,8000-8100")
    r.add_argument("--workers", type=int, default=32)
    r.add_argument("--timeout", type=float, default=0.6, help="per-connection timeout in seconds")
    r.add_argument("--name", default="lab engagement")
    r.add_argument("--out", default="autostrike-run")

    i = sub.add_parser("import-nmap", help="skip recon/enumeration and analyse an nmap -sV -oX file")
    i.add_argument("xml")
    i.add_argument("--name", default="nmap import")
    i.add_argument("--out", default="autostrike-import")

    rep = sub.add_parser("report", help="re-render reports from a saved engagement.json")
    rep.add_argument("engagement")
    rep.add_argument("--out", default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(BANNER)
    try:
        if args.cmd == "demo":
            lab = Path(args.lab) if args.lab else resources.files("autostrike.data").joinpath("demo_lab.json")
            data = json.loads(lab.read_text(encoding="utf-8"))
            sim = SimTransport(data)
            scope = Scope(data.get("scope", ["10.10.10.0/24"]))
            eng = Engagement(name=sim.name, mode="demo", scope=[str(n) for n in scope.networks])
            run_pipeline(eng, sim, RunOptions(targets=list(scope.addresses())), args.out)

        elif args.cmd == "run":
            if not args.authorized:
                print("Refusing to run: pass --authorized to confirm you are permitted to test this scope.",
                      file=sys.stderr)
                return 2
            scope = (Scope.from_file(args.scope, args.allow_public) if args.scope
                     else Scope(args.target, args.allow_public))
            print(f"Scope: {scope}")
            eng = Engagement(name=args.name, mode="live", scope=[str(n) for n in scope.networks])
            opts = RunOptions(targets=list(scope.addresses()), ports=args.ports, workers=args.workers)
            run_pipeline(eng, LiveTransport(scope, timeout=args.timeout), opts, args.out)

        elif args.cmd == "import-nmap":
            hosts = parse_nmap_xml(args.xml)
            eng = Engagement(name=args.name, mode="import", scope=sorted({h.ip for h in hosts}),
                             live_hosts=[h.ip for h in hosts], hosts=hosts)
            run_pipeline(eng, None, RunOptions(), args.out, start_at="exploitation-sim")

        elif args.cmd == "report":
            eng = Engagement.load(args.engagement)
            out = args.out or str(Path(args.engagement).parent)
            for path in write_reports(eng, out):
                print(f"wrote {path}")
            return 0
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2
    print(f"Done. Reports are in {Path(args.out).resolve()}")
    return 0
