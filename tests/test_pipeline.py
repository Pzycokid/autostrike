import json
import socket
import threading
from pathlib import Path

from autostrike.cli import main
from autostrike.models import Engagement
from autostrike.nmap_import import parse_nmap_xml
from autostrike.phases import RunOptions, load_json
from autostrike.pipeline import PHASE_NAMES, run_pipeline
from autostrike.scope import Scope
from autostrike.transport import LiveTransport

FIXTURES = Path(__file__).parent / "fixtures"


def test_demo_kill_chain(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    eng = Engagement.load(tmp_path / "engagement.json")

    # every phase ran, in kill-chain order, each handing off to the next
    assert [p.name for p in eng.phases] == PHASE_NAMES
    assert eng.live_hosts == ["10.10.10.5", "10.10.10.12", "10.10.10.20", "10.10.10.30", "10.10.10.40"]
    assert [h.ip for h in eng.hosts] == eng.live_hosts

    cves = {f.cve for f in eng.findings}
    assert {"CVE-2011-2523", "CVE-2021-41773", "CVE-2017-0144", "CVE-2018-15473"} <= cves
    # the patched hosts produce no false positives
    assert not [f for f in eng.findings if f.host == "10.10.10.40"]
    assert not [f for f in eng.findings if f.host == "10.10.10.20" and f.port == 22]

    # findings are sorted critical first
    order = {"critical": 0, "high": 1, "medium": 2}
    assert [order[f.severity] for f in eng.findings] == sorted(order[f.severity] for f in eng.findings)

    # post-exploitation plan exists only for critical/high footholds and is ATT&CK mapped
    attack = load_json("attack.json")
    footholds = {s.host for s in eng.post_plan}
    assert footholds == {"10.10.10.5", "10.10.10.12", "10.10.10.20"}
    assert all(s.technique in attack for s in eng.post_plan)
    assert any(s.technique == "T1021.002" for s in eng.post_plan)

    for name in ("report.md", "report.html", "report.json"):
        assert (tmp_path / name).stat().st_size > 500
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert any(row[0] == "T1190" for row in report["attack_coverage"])


def test_resume_from_saved_engagement(tmp_path):
    main(["demo", "--out", str(tmp_path)])
    eng = Engagement.load(tmp_path / "engagement.json")
    eng.findings, eng.post_plan, eng.phases = [], [], eng.phases[:2]
    run_pipeline(eng, None, RunOptions(), tmp_path / "resumed", start_at="exploitation-sim", log=lambda _: None)
    assert len(eng.findings) == 9
    assert [p.name for p in eng.phases][-1] == "reporting"


def test_nmap_import(tmp_path):
    hosts = parse_nmap_xml(FIXTURES / "sample_nmap.xml")
    assert [h.ip for h in hosts] == ["192.168.56.101", "192.168.56.110"]  # down host skipped
    meta = hosts[0]
    assert meta.hostname == "metasploitable.lab"
    assert {s.port for s in meta.services} == {21, 22, 139, 2121}  # closed 8180 skipped
    assert next(s for s in meta.services if s.port == 139).product == "Samba"
    assert hosts[1].os_guess == "windows"

    assert main(["import-nmap", str(FIXTURES / "sample_nmap.xml"), "--out", str(tmp_path)]) == 0
    eng = Engagement.load(tmp_path / "engagement.json")
    assert {"CVE-2011-2523", "CVE-2007-2447", "CVE-2018-15473"} <= {f.cve for f in eng.findings}


def test_live_run_against_localhost(tmp_path):
    """Real sockets: a fake OpenSSH 7.4 server on 127.0.0.1 is discovered and flagged."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        scope = Scope(["127.0.0.1/32"])
        eng = Engagement(name="localhost", mode="live", scope=["127.0.0.1/32"])
        opts = RunOptions(targets=list(scope.addresses()), ports=[port], workers=2)
        import autostrike.phases as phases

        saved = phases.DISCOVERY_PORTS
        phases.DISCOVERY_PORTS = [port]
        try:
            run_pipeline(eng, LiveTransport(scope, timeout=1.0), opts, tmp_path, log=lambda _: None)
        finally:
            phases.DISCOVERY_PORTS = saved
    finally:
        stop.set()
        t.join(timeout=2)
        srv.close()

    assert eng.live_hosts == ["127.0.0.1"]
    svc = eng.hosts[0].services[0]
    assert (svc.port, svc.product, svc.version) == (port, "OpenSSH", "7.4")
    assert [f.cve for f in eng.findings] == ["CVE-2018-15473"]


def test_live_run_requires_authorization_flag(capsys):
    assert main(["run", "--target", "127.0.0.1/32"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_live_run_rejects_public_scope(capsys):
    assert main(["run", "--target", "1.1.1.0/30", "--authorized"]) == 2
    assert "public" in capsys.readouterr().err
