from autostrike.fingerprint import identify, version_tuple
from autostrike.models import Service
from autostrike.phases import load_json, rule_matches


def test_identify_common_banners():
    assert (identify(22, "SSH-2.0-OpenSSH_7.4").product, identify(22, "SSH-2.0-OpenSSH_7.4").version) == ("OpenSSH", "7.4")
    ftp = identify(21, "220 (vsFTPd 2.3.4)")
    assert (ftp.name, ftp.product, ftp.version) == ("ftp", "vsftpd", "2.3.4")
    web = identify(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)")
    assert (web.product, web.version) == ("Apache httpd", "2.4.49")
    assert identify(6379, "+PONG").product == "Redis"
    assert identify(3306, "J\x00\x00\x00\n5.5.62-0ubuntu0.14.04.1\x00").version == "5.5.62"


def test_unknown_banner_keeps_port_name():
    svc = identify(3389, "")
    assert svc.name == "rdp" and svc.product == ""


def test_version_tuple():
    assert version_tuple("7.4p1") == (7, 4, 1)
    assert version_tuple("2.4.49") < version_tuple("2.4.51")


def test_rule_ranges():
    rules = {r["id"]: r for r in load_json("vuln_rules.json")}
    old_ssh = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
    new_ssh = Service(port=22, name="ssh", product="OpenSSH", version="8.9p1")
    assert rule_matches(rules["AS-002"]["match"], old_ssh)
    assert not rule_matches(rules["AS-002"]["match"], new_ssh)
    samba = Service(port=139, name="smb", product="Samba", version="3.0.20")
    assert rule_matches(rules["AS-011"]["match"], samba)
    assert not rule_matches(rules["AS-011"]["match"], Service(port=139, product="Samba", version="4.15.0"))


def test_every_rule_is_well_formed():
    attack = load_json("attack.json")
    ids = set()
    for r in load_json("vuln_rules.json"):
        assert r["id"] not in ids
        ids.add(r["id"])
        assert r["severity"] in {"critical", "high", "medium", "low", "info"}
        assert r["technique"] in attack, r["technique"]
        assert r["match"], r["id"]
