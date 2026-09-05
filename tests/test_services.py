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
