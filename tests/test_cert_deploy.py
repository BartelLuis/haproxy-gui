import importlib
from pathlib import Path

import pytest

CERT_BYTES = b"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
ISSUER_BYTES = b"-----BEGIN CERTIFICATE-----\nISSUER\n-----END CERTIFICATE-----\n"
KEY_BYTES = b"-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
CERT_DIR = "/etc/haproxy/certs"
CERT_NAME = "demo.example.com"


@pytest.fixture()
def remote_certificate(env, cluster, monkeypatch):
    from app.services import certs, deploy

    importlib.reload(certs)
    db = env["db"]
    db.execute(
        "UPDATE nodes SET is_local = 0, cert_dir = ?,"
        " config_path = '/etc/haproxy/haproxy.cfg' WHERE id = ?",
        (CERT_DIR, cluster["node"]["id"]),
    )
    node = db.one("SELECT * FROM nodes WHERE id = ?", (cluster["node"]["id"],))
    cert_id = db.execute(
        "INSERT INTO certificates (name, domains, dns_provider, status)"
        " VALUES (?, ?, 'manual', 'active')",
        (CERT_NAME, '["example.com"]'),
    )
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, cert_id)"
        " VALUES (?, 'https', 443, 1, ?)",
        (cluster["cluster"]["id"], cert_id),
    )
    source_dir = Path(certs.ACME_DIR) / "certificates"
    source_dir.mkdir(parents=True)
    (source_dir / "example.com.crt").write_bytes(CERT_BYTES)
    (source_dir / "example.com.issuer.crt").write_bytes(ISSUER_BYTES)
    (source_dir / "example.com.key").write_bytes(KEY_BYTES)

    events = []

    def run_ssh(node, command, **kwargs):
        events.append(("run", command))
        return 0, "", ""

    def sftp_write(node, target, data, mode=None):
        events.append(("write", target, data, mode))

    def reload_node(node):
        events.append(("reload", node["id"]))
        return True, "Reload successful"

    monkeypatch.setattr(deploy.sshclient, "run_ssh", run_ssh)
    monkeypatch.setattr(deploy.sshclient, "sftp_write", sftp_write)
    monkeypatch.setattr(deploy, "reload_node", reload_node)
    monkeypatch.setattr(deploy.runtime, "show_info", lambda node: {})
    monkeypatch.setattr(deploy.alerting, "notify_deploy_failure", lambda *args: None)
    return {
        "certs": certs,
        "deploy": deploy,
        "cert_id": cert_id,
        "cluster": cluster["cluster"],
        "node": node,
        "events": events,
    }


def _deploy(case, entrypoint):
    if entrypoint == "certificate":
        results = case["certs"].deploy_cert(case["cert_id"])
        assert len(results) == 1
        return results[0]
    return case["deploy"].deploy_node(case["cluster"], case["node"])


@pytest.mark.parametrize("entrypoint", ["certificate", "configuration"])
def test_remote_deploy_uploads_nonempty_certificate_and_key(remote_certificate, entrypoint):
    case = remote_certificate
    result = _deploy(case, entrypoint)

    assert result["ok"], result
    events = case["events"]
    cert_writes = [
        event for event in events
        if event[0] == "write" and event[1].startswith(CERT_DIR + "/")
    ]
    assert cert_writes == [
        ("write", f"{CERT_DIR}/{CERT_NAME}.crt", CERT_BYTES + ISSUER_BYTES, 0o600),
        ("write", f"{CERT_DIR}/{CERT_NAME}.key", KEY_BYTES, 0o600),
    ]
    removal = ("run", f"rm -f {CERT_DIR}/{CERT_NAME}.pem")
    assert events.index(removal) > events.index(cert_writes[-1])
    assert events.index(("reload", case["node"]["id"])) > events.index(removal)
    assert [event for event in events if event[0] == "run" and "rm " in event[1]] == [removal]


@pytest.mark.parametrize("entrypoint", ["certificate", "configuration"])
@pytest.mark.parametrize("failed_suffix", [".crt", ".key"])
def test_remote_upload_failure_prevents_reload(
    remote_certificate, monkeypatch, entrypoint, failed_suffix
):
    case = remote_certificate

    def fail_upload(node, target, data, mode=None):
        case["events"].append(("write", target, data, mode))
        if target.endswith(failed_suffix):
            raise OSError("Upload interrupted")

    monkeypatch.setattr(case["deploy"].sshclient, "sftp_write", fail_upload)
    result = _deploy(case, entrypoint)

    assert result["ok"] is False
    assert "Upload interrupted" in result["error"]
    assert not any(event[0] == "reload" for event in case["events"])
    commands = [event[1] for event in case["events"] if event[0] == "run"]
    assert commands == [f"mkdir -p {CERT_DIR}"]
    assert all(event[1].startswith(CERT_DIR + "/") for event in case["events"] if event[0] == "write")


@pytest.mark.parametrize("entrypoint", ["certificate", "configuration"])
def test_remote_mkdir_failure_prevents_upload_and_reload(
    remote_certificate, monkeypatch, entrypoint
):
    case = remote_certificate

    def fail_mkdir(node, command, **kwargs):
        case["events"].append(("run", command))
        return 1, "", "Permission denied"

    monkeypatch.setattr(case["deploy"].sshclient, "run_ssh", fail_mkdir)
    result = _deploy(case, entrypoint)

    assert result["ok"] is False
    assert "Permission denied" in result["error"]
    assert case["events"] == [("run", f"mkdir -p {CERT_DIR}")]


@pytest.mark.parametrize(
    "invalid_files",
    [
        {"demo.crt": b"", "demo.key": KEY_BYTES},
        {"demo.crt": CERT_BYTES, "demo.key": b" \n"},
        {"demo.crt": CERT_BYTES},
        {"demo.key": KEY_BYTES},
    ],
    ids=["empty-certificate", "empty-key", "missing-key", "missing-certificate"],
)
@pytest.mark.parametrize("local", [False, True], ids=["remote", "local"])
def test_invalid_pairs_have_no_side_effects(tmp_path, monkeypatch, invalid_files, local):
    from app.services import deploy

    old_files = {"demo.crt": b"old certificate", "demo.key": b"old key", "demo.pem": b"legacy"}
    for name, data in old_files.items():
        (tmp_path / name).write_bytes(data)

    def unexpected_network(*args, **kwargs):
        pytest.fail("Invalid certificate pairs must be rejected before network access")

    monkeypatch.setattr(deploy.sshclient, "run_ssh", unexpected_network)
    monkeypatch.setattr(deploy.sshclient, "sftp_write", unexpected_network)
    with pytest.raises(ValueError):
        if local:
            deploy._write_cert_files(str(tmp_path), invalid_files)
        else:
            deploy.install_cert_files({"cert_dir": CERT_DIR, "is_local": 0}, invalid_files)

    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == old_files


def test_local_replace_failure_preserves_existing_files(tmp_path, monkeypatch):
    from app.services import deploy

    old_files = {"demo.crt": b"old certificate", "demo.key": b"old key", "demo.pem": b"legacy"}
    for name, data in old_files.items():
        (tmp_path / name).write_bytes(data)

    def fail_replace(source, target):
        assert Path(source).read_bytes() == CERT_BYTES
        assert Path(target).read_bytes() == old_files[Path(target).name]
        raise PermissionError("Destination busy")

    monkeypatch.setattr(deploy.os, "replace", fail_replace)
    with pytest.raises(PermissionError, match="Destination busy"):
        deploy._write_cert_files(str(tmp_path), {"demo.crt": CERT_BYTES, "demo.key": KEY_BYTES})

    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == old_files
