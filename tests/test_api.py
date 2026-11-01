import os
import subprocess
import sys
import time
import pytest
import requests

BASE_URL = "http://127.0.0.1:18180"


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    """Startet die FastAPI-App einmal pro Test-Session als echten Prozess."""
    data = tmp_path_factory.mktemp("data")
    env = dict(os.environ)
    env["HG_DATA"] = str(data)
    env["ADMIN_USER"] = "admin"
    env["ADMIN_PASSWORD"] = "test123"
    env["APP_SECRET"] = "test-app-secret"
    env["TRUSTED_PROXIES"] = ""
    env["ENABLE_API_DOCS"] = ""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", "18180", "--no-proxy-headers"],
        cwd=base, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            if requests.get(BASE_URL + "/", timeout=1).status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("Server startete nicht")
    yield BASE_URL
    proc.terminate()
    proc.wait(timeout=10)


def _login(server, username="admin", password="test123"):
    res = requests.post(
        server + "/api/auth/login", json={"username": username, "password": password}
    )
    assert res.status_code == 200, res.text
    return res.json()["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_index_and_static(server):
    res = requests.get(server + "/")
    assert res.status_code == 200
    assert "HAProxy" in res.text
    assert requests.get(server + "/static/app.js").status_code == 200
    assert requests.get(server + "/static/style.css").status_code == 200


def test_unauthenticated(server):
    assert requests.get(server + "/api/clusters").status_code == 401


def test_api_docs_disabled_by_default(server):
    assert requests.get(server + "/docs").status_code == 404
    assert requests.get(server + "/openapi.json").status_code == 404


def test_login_and_me(server):
    token = _login(server)
    me = requests.get(server + "/api/auth/me", headers=_h(token))
    assert me.json()["role"] == "admin"
    bad = requests.post(
        server + "/api/auth/login", json={"username": "admin", "password": "falsch"}
    )
    assert bad.status_code == 401


def test_login_rate_limit_ignores_untrusted_forwarded_for(server):
    endpoint = server + "/api/auth/login"
    username = "forwarded-for-check"
    statuses = []
    for index in range(5):
        response = requests.post(
            endpoint,
            headers={"X-Forwarded-For": f"2001:db8:1::{index + 1}"},
            json={"username": username, "password": "wrong"},
        )
        statuses.append(response.status_code)
        assert response.status_code == 401
    blocked = requests.post(
        endpoint,
        headers={"X-Forwarded-For": "198.51.100.10"},
        json={"username": username, "password": "wrong"},
    )
    assert blocked.status_code == 429, statuses + [blocked.status_code]


def test_seeded_local_cluster(server):
    token = _login(server)
    clusters = requests.get(server + "/api/clusters", headers=_h(token)).json()
    local = next(c for c in clusters if c["name"] == "Local")
    assert len(local["nodes"]) == 1
    assert local["nodes"][0]["is_local"] == 1


def test_viewer_cannot_modify(server):
    token = _login(server)
    requests.post(
        server + "/api/users", json={"username": "v1", "password": "pw12345", "role": "viewer"},
        headers=_h(token),
    )
    vtoken = _login(server, "v1", "pw12345")
    assert requests.get(server + "/api/clusters", headers=_h(vtoken)).status_code == 200
    res = requests.post(
        server + "/api/clusters", json={"name": "verboten"}, headers=_h(vtoken)
    )
    assert res.status_code == 403
    # Admin-Endpunkte auch für GET gesperrt
    assert requests.get(server + "/api/users", headers=_h(vtoken)).status_code == 403


def test_operator_token_cannot_manage_users(server):
    token = _login(server)
    res = requests.post(
        server + "/api/tokens", json={"name": "ci", "role": "operator"}, headers=_h(token)
    )
    api_token = res.json()["token"]
    assert api_token.startswith("hg_")
    assert requests.get(server + "/api/clusters", headers=_h(api_token)).status_code == 200
    assert requests.get(server + "/api/users", headers=_h(api_token)).status_code == 403


def test_crud_frontend_backend(server):
    token = _login(server)
    clusters = requests.get(server + "/api/clusters", headers=_h(token)).json()
    cid = clusters[0]["id"]
    be = requests.post(
        server + "/api/backends",
        json={"cluster_id": cid, "name": "t-web", "servers": [
            {"name": "s1", "host": "127.0.0.1", "port": 9000}]},
        headers=_h(token),
    )
    assert be.status_code == 200, be.text
    be_id = be.json()["id"]
    fe = requests.post(
        server + "/api/frontends",
        json={"cluster_id": cid, "name": "t-http", "port": 8080,
              "default_backend_id": be_id},
        headers=_h(token),
    )
    assert fe.status_code == 200, fe.text
    cfg = requests.get(
        server + f"/api/clusters/{cid}/config", headers=_h(token)
    )
    assert "frontend t-http" in cfg.text
    assert "server s1 127.0.0.1:9000 check" in cfg.text


def test_ipv6_node_and_dual_stack_frontend(server):
    token = _login(server)
    headers = _h(token)
    clusters = requests.get(server + "/api/clusters", headers=headers).json()
    cid = clusters[0]["id"]
    node = requests.post(
        server + "/api/nodes",
        json={
            "cluster_id": cid,
            "name": "ipv6-node",
            "host": "2001:db8::10",
            "socket_type": "tcp",
            "socket_host": "::1",
        },
        headers=headers,
    )
    assert node.status_code == 200, node.text
    backend = requests.post(
        server + "/api/backends",
        json={
            "cluster_id": cid,
            "name": "ipv6-backend",
            "servers": [
                {"name": "v6-server", "host": "[2001:db8::20]", "port": 8080}
            ],
        },
        headers=headers,
    )
    assert backend.status_code == 200, backend.text
    frontend = requests.post(
        server + "/api/frontends",
        json={
            "cluster_id": cid,
            "name": "dual-http",
            "port": 8081,
            "bind_family": "dual",
        },
        headers=headers,
    )
    assert frontend.status_code == 200, frontend.text
    cfg = requests.get(
        server + f"/api/clusters/{cid}/config", headers=headers
    ).text
    assert "bind *:8081" in cfg
    assert "bind :::8081 v6only" in cfg
    assert "server v6-server 2001:db8::20:8080 check" in cfg


def test_backend_update_rejects_invalid_server_host_without_mutation(server):
    token = _login(server)
    headers = _h(token)
    cid = requests.get(server + "/api/clusters", headers=headers).json()[0]["id"]
    created = requests.post(
        server + "/api/backends",
        json={
            "cluster_id": cid,
            "name": "validated-update",
            "servers": [{"name": "good", "host": "127.0.0.1", "port": 8000}],
        },
        headers=headers,
    )
    assert created.status_code == 200, created.text
    bid = created.json()["id"]
    updated = requests.put(
        server + f"/api/backends/{bid}",
        json={
            "cluster_id": cid,
            "name": "validated-update",
            "servers": [{"name": "bad", "host": "bad host", "port": 8001}],
        },
        headers=headers,
    )
    assert updated.status_code == 400
    stored = requests.get(
        server + f"/api/backends?cluster_id={cid}", headers=headers
    ).json()
    backend = next(item for item in stored if item["id"] == bid)
    assert backend["servers"][0]["host"] == "127.0.0.1"


def test_backend_ssl_verification_roundtrip_and_validation(server):
    headers = _h(_login(server))
    cid = requests.get(server + "/api/clusters", headers=headers).json()[0]["id"]

    def backend_body(servers):
        return {"cluster_id": cid, "name": "tls-backend", "servers": servers}

    rejected = requests.post(
        server + "/api/backends",
        json=backend_body([{"name": "tls-ip", "host": "10.0.0.7", "port": 443,
                            "ssl": True, "ssl_verify": True}]),
        headers=headers,
    )
    assert rejected.status_code == 400
    assert "Hostnamen" in rejected.json()["detail"]
    stored = requests.get(server + f"/api/backends?cluster_id={cid}", headers=headers).json()
    assert all(item["name"] != "tls-backend" for item in stored)

    created = requests.post(
        server + "/api/backends",
        json=backend_body([
            {"name": "tls-host", "host": "app.example.com", "port": 443,
             "ssl": True, "ssl_verify": True},
            {"name": "tls-plain", "host": "10.0.0.8", "port": 443, "ssl": True},
            {"name": "no-tls", "host": "10.0.0.9", "port": 80, "ssl_verify": True},
        ]),
        headers=headers,
    )
    assert created.status_code == 200, created.text
    bid = created.json()["id"]
    stored = requests.get(server + f"/api/backends?cluster_id={cid}", headers=headers).json()
    servers = {s["name"]: s for s in next(b for b in stored if b["id"] == bid)["servers"]}
    assert {name: (s["ssl"], s["ssl_verify"]) for name, s in servers.items()} == {
        "tls-host": (1, 1), "tls-plain": (1, 0), "no-tls": (0, 0),
    }
    cfg = requests.get(server + f"/api/clusters/{cid}/config", headers=headers).text
    assert (
        "server tls-host app.example.com:443 check ssl verify required"
        " ca-file @system-ca sni str(app.example.com) verifyhost app.example.com"
        " check-ssl check-sni app.example.com"
    ) in cfg
    assert "server tls-plain 10.0.0.8:443 check ssl verify none check-ssl" in cfg
    assert "server no-tls 10.0.0.9:80 check\n" in cfg

    updated = requests.put(
        server + f"/api/backends/{bid}",
        json=backend_body([{"name": "tls-ip", "host": "10.0.0.7", "port": 443,
                            "ssl": True, "ssl_verify": True}]),
        headers=headers,
    )
    assert updated.status_code == 400
    stored = requests.get(server + f"/api/backends?cluster_id={cid}", headers=headers).json()
    assert {s["name"] for s in next(b for b in stored if b["id"] == bid)["servers"]} == {
        "tls-host", "tls-plain", "no-tls",
    }
    assert requests.delete(server + f"/api/backends/{bid}", headers=headers).status_code == 200


def test_versions_and_audit(server):
    token = _login(server)
    audit = requests.get(server + "/api/audit", headers=_h(token)).json()
    assert any(a["action"] == "login" for a in audit)
    clusters = requests.get(server + "/api/clusters", headers=_h(token)).json()
    versions = requests.get(
        server + f"/api/clusters/{clusters[0]['id']}/versions", headers=_h(token)
    )
    assert versions.status_code == 200


def test_dns_providers_and_cert_validation(server):
    token = _login(server)
    providers = requests.get(server + "/api/dns-providers", headers=_h(token)).json()
    assert "cloudflare" in providers
    bad = requests.post(
        server + "/api/certificates",
        json={"name": "x", "domains": [], "dns_provider": "unbekannt"},
        headers=_h(token),
    )
    assert bad.status_code == 400


def test_acme_settings_require_authentication(server):
    assert requests.get(server + "/api/acme/settings").status_code == 401
    assert requests.put(
        server + "/api/acme/settings", json={"dns_resolvers": ["9.9.9.9"]}
    ).status_code == 401


def test_acme_settings_round_trip_and_audit(server):
    headers = _h(_login(server))
    url = server + "/api/acme/settings"
    original = requests.get(url, headers=headers)
    assert original.status_code == 200
    assert original.json() == {"dns_resolvers": ["9.9.9.9:53", "1.1.1.1:53"]}
    try:
        response = requests.put(
            url,
            json={"dns_resolvers": ["1.1.1.1", "1.1.1.1:53", "[2620:fe::fe]:5353"]},
            headers=headers,
        )
        assert response.status_code == 200, response.text
        assert requests.get(url, headers=headers).json() == {
            "dns_resolvers": ["1.1.1.1:53", "[2620:fe::fe]:5353"]
        }
        audit = requests.get(server + "/api/audit", headers=headers).json()
        assert any(entry["action"] == "acme.settings" for entry in audit)
        assert requests.put(url, json={"dns_resolvers": []}, headers=headers).status_code == 200
        assert requests.get(url, headers=headers).json() == {"dns_resolvers": []}
    finally:
        assert requests.put(url, json=original.json(), headers=headers).status_code == 200


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_acme_settings_writable_only_by_admin(server, role):
    admin_headers = _h(_login(server))
    response = requests.post(
        server + "/api/tokens", json={"name": f"acme-{role}", "role": role},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    headers = _h(response.json()["token"])
    url = server + "/api/acme/settings"
    original = requests.get(url, headers=headers)
    assert original.status_code == 200
    assert requests.put(url, json={"dns_resolvers": []}, headers=headers).status_code == 403
    assert requests.get(url, headers=headers).json() == original.json()


@pytest.mark.parametrize(("payload", "status"), [
    ({"dns_resolvers": ["invalid"]}, 400),
    ({"dns_resolvers": ["9.9.9.9:65536"]}, 400),
    ({"dns_resolvers": ["9.9.9.9", "1.1.1.1:0"]}, 400),
    ({"dns_resolvers": ["[2620:fe::fe]:"]}, 400),
    ({"dns_resolvers": ["[2620:fe::fe]extra"]}, 400),
    pytest.param(
        {"dns_resolvers": ["9.9.9.9", "[" + "[\\" * 50_000]},
        400,
        id="long-bracketed-resolver",
    ),
    ({"dns_resolvers": "9.9.9.9"}, 422),
    ({"dns_resolvers": [53]}, 422),
    ({}, 422),
])
def test_acme_settings_reject_invalid_input_without_saving(server, payload, status):
    headers = _h(_login(server))
    url = server + "/api/acme/settings"
    original = requests.get(url, headers=headers).json()
    response = requests.put(url, json=payload, headers=headers, timeout=5)
    assert response.status_code == status, response.text
    assert response.json()["detail"]
    assert requests.get(url, headers=headers).json() == original


def test_ldap_settings_admin_only(server):
    token = _login(server)
    res = requests.get(server + "/api/ldap/settings", headers=_h(token))
    assert res.status_code == 200
    res = requests.put(
        server + "/api/ldap/settings",
        json={"enabled": False, "server_uri": "ldap://10.255.255.1:389"},
        headers=_h(token),
    )
    assert res.status_code == 200


def test_keepalived_endpoint(server):
    token = _login(server)
    clusters = requests.get(server + "/api/clusters", headers=_h(token)).json()
    res = requests.get(
        server + f"/api/clusters/{clusters[0]['id']}/keepalived", headers=_h(token)
    )
    assert res.status_code == 200
    assert "config" in res.json() and "nodes" in res.json()


def test_keepalived_rejects_auth_for_ipv6_only(server):
    token = _login(server)
    headers = _h(token)
    clusters = requests.get(server + "/api/clusters", headers=headers).json()
    cid = clusters[0]["id"]
    res = requests.put(
        server + f"/api/clusters/{cid}/keepalived",
        json={"vip": "2001:db8::10/64", "auth_pass": "secret"},
        headers=headers,
    )
    assert res.status_code == 400
    assert "VRRPv3" in res.text


def test_portscan(server):
    token = _login(server)
    res = requests.post(
        server + "/api/tools/portscan",
        json={"host": "127.0.0.1", "ports": [18180]},
        headers=_h(token),
    ).json()
    assert any(r["port"] == 18180 and r["open"] for r in res["results"])
    ipv6 = requests.post(
        server + "/api/tools/portscan",
        json={"host": "[::1]", "ports": [18180]},
        headers=_h(token),
    )
    assert ipv6.status_code == 200
    assert ipv6.json()["host"] == "::1"


def test_logs_endpoint(server):
    token = _login(server)
    res = requests.get(server + "/api/logs/nodes/1", headers=_h(token))
    assert res.status_code == 200


def test_compare_configs(server):
    token = _login(server)
    clusters = requests.get(server + "/api/clusters", headers=_h(token)).json()
    cid, nid = clusters[0]["id"], clusters[0]["nodes"][0]["id"]
    res = requests.get(
        server + f"/api/tools/compare?cluster_id={cid}&node_a={nid}&node_b={nid}",
        headers=_h(token),
    )
    assert res.status_code == 200
    assert "keine Unterschiede" in res.json()["diff"]
