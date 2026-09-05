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
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", "18180"],
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


def test_login_and_me(server):
    token = _login(server)
    me = requests.get(server + "/api/auth/me", headers=_h(token))
    assert me.json()["role"] == "admin"
    bad = requests.post(
        server + "/api/auth/login", json={"username": "admin", "password": "falsch"}
    )
    assert bad.status_code == 401


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


def test_portscan(server):
    token = _login(server)
    res = requests.post(
        server + "/api/tools/portscan",
        json={"host": "127.0.0.1", "ports": [18180]},
        headers=_h(token),
    ).json()
    assert any(r["port"] == 18180 and r["open"] for r in res["results"])


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
