import importlib

import pytest


@pytest.fixture()
def services(env):
    import app.services.keepalived as ksvc
    import app.services.metrics as msvc
    import app.services.alerting as alertsvc
    import app.services.logs as logsvc
    import app.services.ldapsvc as ldapsvc

    for mod in (ksvc, msvc, alertsvc, logsvc, ldapsvc):
        importlib.reload(mod)
    return {
        "ksvc": ksvc,
        "msvc": msvc,
        "alerting": alertsvc,
        "logs": logsvc,
        "ldap": ldapsvc,
    }


def test_keepalived_generate(env, cluster, services):
    ksvc = services["ksvc"]
    ksvc.save_cluster_config(
        cluster["cluster"]["id"],
        {"vip": "10.0.0.10/24", "iface": "eth0", "vr_id": 51, "auth_pass": "geheim"},
        [{"node_id": cluster["node"]["id"], "state": "MASTER", "priority": 101}],
    )
    cfg = ksvc.generate(cluster["cluster"], cluster["node"])
    assert "vrrp_instance" in cfg
    assert "state MASTER" in cfg
    assert "priority 101" in cfg
    assert "10.0.0.10/24" in cfg
    assert "auth_pass geheim" in cfg
    assert "virtual_router_id 51" in cfg


def test_keepalived_requires_vip(env, cluster, services):
    with pytest.raises(ValueError, match="VIP"):
        services["ksvc"].generate(cluster["cluster"], cluster["node"])


def test_alert_settings_roundtrip(services):
    svc = services["alerting"]
    svc.save_settings({"enabled": True, "webhook_url": "", "alert_node_down": True})
    st = svc.get_settings()
    assert st["enabled"] == 1
    assert st["alert_node_down"] == 1
    # Aktiviert, aber ohne Kanäle konfiguriert → kein Fehler, keine Empfänger
    assert svc.send("test") == []
    # Deaktiviert → Hinweis zurückgeben
    svc.save_settings({"enabled": False})
    assert svc.send("test") == ["Alerts sind deaktiviert"]


def test_metrics_parser(services):
    sample = (
        "cpu  1 2 3 90 4 0 0 0 0 0\n--MEM--\nMemTotal: 1048576 kB\n"
        "MemAvailable: 524288 kB\n--LOAD--\n0.10 0.20 0.30 1/100 123\n"
        "--DISK--\noverlay 10485760 5242880 0 50% /\ncpu  2 3 4 95 5 0 0 0 0 0"
    )
    r = services["msvc"]._parse_output(sample)
    assert r["mem"]["percent"] == 50.0
    assert r["mem"]["total_mb"] == 1024
    assert r["cpu_percent"] is not None
    assert r["load"].startswith("0.10")
    assert r["disk"]["percent"] == 50


def test_local_log_missing_file(env, cluster, services):
    txt = services["logs"].get_node_log(cluster["node"])
    assert isinstance(txt, str) and len(txt) > 0


def test_ldap_disabled_returns_none(env, services):
    assert services["ldap"].authenticate("user", "pw") is None
    ok, msg = services["ldap"].test_connection()
    assert ok is False


def test_ldap_settings_roundtrip(env, services):
    svc = services["ldap"]
    svc.save_settings(
        {"enabled": True, "server_uri": "ldaps://dc.example.com", "base_dn": "dc=example,dc=com"}
    )
    st = svc.get_settings()
    assert st["enabled"] == 1
    assert st["server_uri"] == "ldaps://dc.example.com"


def test_ldap_role_mapping(services):
    svc = services["ldap"]
    st = {
        "group_admin": "cn=admins,dc=x",
        "group_operator": "cn=ops,dc=x",
        "default_role": "viewer",
    }
    assert svc._role_from_groups(["CN=admins,DC=x"], st) == "admin"
    assert svc._role_from_groups(["cn=ops,dc=x"], st) == "operator"
    assert svc._role_from_groups(["cn=other,dc=x"], st) is None
    st2 = {"group_admin": "", "group_operator": "", "default_role": "operator"}
    assert svc._role_from_groups([], st2) == "operator"


def test_totp_roundtrip(env):
    import importlib
    import app.services.totp as totp
    importlib.reload(totp)
    db = env["db"]
    uid = db.one("SELECT id FROM users WHERE username='admin'")["id"]
    secret = totp.start_setup(uid)
    assert not totp.is_enabled(uid)
    code = totp._totp(secret)
    ok, msg = totp.confirm_setup(uid, code)
    assert ok, msg
    assert totp.is_enabled(uid)
    assert totp.verify(uid, totp._totp(secret))
    assert not totp.verify(uid, "000000")
    # Deaktivieren erfordert gültigen Code
    assert totp.verify(uid, totp._totp(secret))
    totp.disable(uid)
    assert not totp.is_enabled(uid)


def test_validate_module(env):
    from app.services import validate as v
    assert v.clean_name("lb-01.example_com") == "lb-01.example_com"
    assert v.clean_path("/etc/haproxy/haproxy.cfg")
    assert v.clean_domain("*.example.com")
    for bad in ["bad;name", "../etc", "a b", "x;rm -rf /", "$(evil)"]:
        for fn in (v.clean_name, v.clean_path, v.clean_domain, v.clean_host):
            try:
                fn(bad)
                raise AssertionError(f"{fn.__name__} akzeptierte {bad!r}")
            except ValueError:
                pass
    import pytest
    with pytest.raises(ValueError):
        v.no_newline("zeile1\nzeile2")


def test_secret_encryption(env):
    auth = env["auth"]
    enc = auth.encrypt_secret("geheim-token-123")
    assert enc.startswith("enc:")
    assert enc != "geheim-token-123"
    assert auth.decrypt_secret(enc) == "geheim-token-123"
    # Klartext-Altbestand bleibt lesbar
    assert auth.decrypt_secret("plain") == "plain"


def test_login_rate_limit(env):
    auth = env["auth"]
    key = "1.2.3.4|admin"
    for _ in range(auth.LOGIN_MAX):
        assert auth.login_rate_check(key)
        auth.login_failed(key)
    assert not auth.login_rate_check(key)  # jetzt gesperrt
    auth.login_succeeded(key)
    assert auth.login_rate_check(key)  # nach Erfolg wieder frei


def test_providers_include_technitium_and_manual(env):
    import importlib
    import app.services.certs as certsvc
    importlib.reload(certsvc)
    providers = certsvc.providers_public()
    assert "technitium" in providers
    assert "manual" in providers
    assert providers["technitium"]["env"][0][0] == "TECHNITIUM_SERVER"
    assert providers["manual"]["env"] == []


def test_technitium_env_validation(env):
    import importlib
    import app.services.certs as certsvc
    importlib.reload(certsvc)
    with pytest.raises(ValueError, match="TECHNITIUM"):
        certsvc._technitium_env({})
    env_map = certsvc._technitium_env(
        {"TECHNITIUM_SERVER": "http://10.0.0.5:5380/", "TECHNITIUM_TOKEN": "abc"}
    )
    assert env_map["TECHNITIUM_SERVER"] == "http://10.0.0.5:5380"
    assert env_map["TECHNITIUM_TOKEN"] == "abc"
    assert env_map["EXEC_PATH"].endswith("technitium_hook.sh")
    import os
    assert os.path.exists(env_map["EXEC_PATH"])


def test_manual_challenge_flow(env):
    import importlib
    import app.services.certs as certsvc
    importlib.reload(certsvc)
    db = env["db"]
    cid = db.execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES (?, ?, ?)",
        ("manual-test", '["example.com"]', "manual"),
    )
    cert = db.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    # Keine Challenge → None
    assert certsvc.get_pending_challenge(cert) is None
    # Records-Datei simulieren
    records_file, confirm_file = certsvc._manual_paths(cert)
    with open(records_file, "w") as f:
        f.write("_acme-challenge.example.com TOKEN123\n")
    pending = certsvc.get_pending_challenge(cert)
    assert pending == [{"domain": "_acme-challenge.example.com", "value": "TOKEN123"}]
    # Bestätigen
    ok, msg = certsvc.confirm_manual(cid)
    assert ok
    assert certsvc.get_pending_challenge(cert) is None  # Confirm-Datei existiert → fertig
    certsvc._cleanup_manual(cert)
