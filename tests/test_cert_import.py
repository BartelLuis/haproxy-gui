import asyncio
import base64
import importlib
import ipaddress
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import HTTPException

from app.services import certimport

USER = {"username": "import-test"}


def _pem_body(bundle, **extra):
    return {
        "certificate_pem": bundle["certificate_pem"],
        "private_key_pem": bundle["private_key_pem"],
        **extra,
    }


def _pfx(bundle, chain=(), password=b""):
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    return base64.b64encode(pkcs12.serialize_key_and_certificates(
        b"test certificate", bundle["key"], bundle["cert"], list(chain), encryption
    )).decode("ascii")


@pytest.fixture()
def import_api(env):
    from app.routers import certs as router

    importlib.reload(router.certsvc)
    return router


@pytest.mark.parametrize("key_type", ["ec", "rsa"])
def test_pem_normalizes_leaf_chain_and_matching_key(certificate_factory, key_type):
    root = certificate_factory(("root.test",), is_ca=True)
    issuer = certificate_factory(("issuer.test",), issuer=root, is_ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if key_type == "rsa" else None
    leaf = certificate_factory(issuer=issuer, key=key)
    material = certimport.parse_pem(
        **_pem_body(leaf),
        chain_pem=root["certificate_pem"] + issuer["certificate_pem"] + root["certificate_pem"],
    )
    assert material.domains == ["example.test", "*.example.test"]
    assert material.not_after == leaf["cert"].not_valid_after_utc.isoformat()
    assert material.cert_pem == (
        leaf["certificate_pem"] + issuer["certificate_pem"] + root["certificate_pem"]
    ).encode("ascii")
    assert material.key_pem == leaf["private_key_pem"].encode("ascii")
    assert leaf["private_key_pem"] not in repr(material)


def test_combined_pem_and_encrypted_pem(certificate_factory):
    leaf = certificate_factory()
    combined = leaf["private_key_pem"] + leaf["certificate_pem"]
    assert certimport.parse_pem(combined).cert_pem == leaf["certificate_pem"].encode("ascii")
    encrypted_key = leaf["key"].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-only-password"),
    ).decode("ascii")
    material = certimport.parse_pem(leaf["certificate_pem"], encrypted_key, password="test-only-password")
    assert material.key_pem == leaf["private_key_pem"].encode("ascii")
    with pytest.raises(ValueError, match="Passwort"):
        certimport.parse_pem(leaf["certificate_pem"], encrypted_key, password="incorrect")


@pytest.mark.parametrize("password", [b"", b"test-only-password"])
def test_pkcs12_import_with_chain(certificate_factory, password):
    issuer = certificate_factory(("issuer.test",), is_ca=True)
    leaf = certificate_factory(issuer=issuer)
    material = certimport.parse_pkcs12(_pfx(leaf, [issuer["cert"]], password), password.decode("ascii"))
    assert material.domains == ["example.test", "*.example.test"]
    assert material.cert_pem == (leaf["certificate_pem"] + issuer["certificate_pem"]).encode("ascii")
    assert material.key_pem == leaf["private_key_pem"].encode("ascii")


def test_pkcs12_rejects_wrong_password_and_missing_key(certificate_factory):
    leaf = certificate_factory()
    with pytest.raises(ValueError, match="Passwort"):
        certimport.parse_pkcs12(_pfx(leaf, password=b"correct-test-password"), "incorrect")
    without_key = pkcs12.serialize_key_and_certificates(
        None, None, None, [leaf["cert"]], serialization.NoEncryption()
    )
    with pytest.raises(ValueError, match="privaten Schlüssel"):
        certimport.parse_pkcs12(base64.b64encode(without_key).decode("ascii"))


@pytest.mark.parametrize(("field", "value", "message"), [
    ("certificate_pem", "", "erforderlich"),
    ("certificate_pem", "not a certificate", "PEM-Zertifikat"),
    ("private_key_pem", "not a key", "PEM-Schlüssel"),
    ("chain_pem", "not a chain", "Zertifikatskette"),
])
def test_invalid_pem_is_rejected(certificate_factory, field, value, message):
    body = _pem_body(certificate_factory(), **{field: value})
    with pytest.raises(ValueError, match=message):
        certimport.parse_pem(**body)


@pytest.mark.parametrize("data", ["", "%%%invalid-base64%%%", "bm90LWEtcGZ4"])
def test_invalid_pkcs12_is_rejected(data):
    with pytest.raises(ValueError, match="PFX/P12"):
        certimport.parse_pkcs12(data)


def test_mismatched_key_and_multiple_leaf_certificates_are_rejected(certificate_factory):
    leaf = certificate_factory()
    other = certificate_factory()
    with pytest.raises(ValueError, match="passen nicht"):
        certimport.parse_pem(leaf["certificate_pem"], other["private_key_pem"])
    same_key = certificate_factory(key=leaf["key"])
    with pytest.raises(ValueError, match="genau ein"):
        certimport.parse_pem(
            leaf["certificate_pem"] + same_key["certificate_pem"], leaf["private_key_pem"]
        )


@pytest.mark.parametrize(("options", "message"), [
    ({"valid_days": -1}, "abgelaufen"),
    ({"not_before": datetime.now(timezone.utc) + timedelta(days=1)}, "noch nicht gültig"),
])
def test_invalid_validity_period_is_rejected(certificate_factory, options, message):
    with pytest.raises(ValueError, match=message):
        certimport.parse_pem(**_pem_body(certificate_factory(**options)))


def test_invalid_chain_is_rejected(certificate_factory):
    issuer = certificate_factory(("issuer.test",), is_ca=True)
    leaf = certificate_factory(issuer=issuer)
    unrelated = certificate_factory(("unrelated.test",), is_ca=True)
    with pytest.raises(ValueError, match="fremde Zertifikate"):
        certimport.parse_pem(**_pem_body(leaf), chain_pem=unrelated["certificate_pem"])
    wrong_issuer = certificate_factory(("issuer.test",), is_ca=True)
    with pytest.raises(ValueError, match="Signatur"):
        certimport.parse_pem(**_pem_body(leaf), chain_pem=wrong_issuer["certificate_pem"])
    expired = certificate_factory(("expired.test",), is_ca=True, valid_days=-1)
    with pytest.raises(ValueError, match="abgelaufen"):
        certimport.parse_pem(
            **_pem_body(certificate_factory(issuer=expired)), chain_pem=expired["certificate_pem"]
        )


def test_import_metadata_uses_san_and_legacy_cn_fallback(certificate_factory):
    leaf = certificate_factory(san_names=[
        x509.DNSName("EXAMPLE.test"), x509.DNSName("example.test"),
        x509.DNSName("*.example.test"), x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
        x509.IPAddress(ipaddress.ip_address("2001:db8::10")),
    ])
    assert certimport.parse_pem(**_pem_body(leaf)).domains == [
        "example.test", "*.example.test", "192.0.2.10", "2001:db8::10",
    ]
    legacy = certificate_factory(("legacy.test",), san_names=[])
    assert certimport.parse_pem(**_pem_body(legacy)).domains == ["legacy.test"]
    email_only = certificate_factory(san_names=[x509.RFC822Name("admin@example.test")])
    with pytest.raises(ValueError, match="DNS-Namen"):
        certimport.parse_pem(**_pem_body(email_only))


def test_import_size_limit_and_chain_limit(certificate_factory):
    leaf = certificate_factory()
    padding = certimport.MAX_IMPORT_BYTES - len(leaf["certificate_pem"]) - len(leaf["private_key_pem"])
    certificate = leaf["certificate_pem"] + " " * padding
    assert certimport.parse_pem(certificate, leaf["private_key_pem"]).domains
    with pytest.raises(ValueError, match="1 MiB"):
        certimport.parse_pem(certificate + " ", leaf["private_key_pem"])
    oversized = base64.b64encode(b"x" * (certimport.MAX_IMPORT_BYTES + 1)).decode("ascii")
    with pytest.raises(ValueError, match="1 MiB"):
        certimport.parse_pkcs12(oversized)
    chain = "".join(
        certificate_factory((f"ca-{i}.test",), is_ca=True)["certificate_pem"]
        for i in range(certimport.MAX_CHAIN_CERTIFICATES)
    )
    with pytest.raises(ValueError, match="höchstens 32"):
        certimport.parse_pem(**_pem_body(leaf), chain_pem=chain)


def test_import_and_replace_preserve_assignments_without_deployment(
    env, cluster, import_api, certificate_factory, monkeypatch
):
    from app.services import certmap

    def no_deployment(*args, **kwargs):
        pytest.fail("Import must not start ACME or deploy automatically")

    monkeypatch.setattr(import_api.certsvc, "issue_background", no_deployment)
    monkeypatch.setattr(import_api.certsvc, "deploy_cert", no_deployment)
    leaf = certificate_factory()
    cid = import_api.import_cert(import_api.CertImportIn(name="imported", **_pem_body(leaf)), USER)["id"]
    db = env["db"]
    bid = db.execute("INSERT INTO backends (cluster_id, name) VALUES (?, 'backend')", (cluster["cluster"]["id"],))
    fid = db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, default_backend_id)"
        " VALUES (?, 'https', 443, 1, ?)", (cluster["cluster"]["id"], bid),
    )
    certmap.save_frontend_certs(fid, [cid])
    certmap.save_backend_certs(bid, [cid])
    record = db.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    assert record["source"] == "imported"
    assert record["status"] == "active"
    assert record["auto_renew"] == 0
    assert json.loads(record["domains"]) == ["example.test", "*.example.test"]
    assert import_api.certsvc.certificate_bytes(record) == (
        leaf["certificate_pem"].encode("ascii"), leaf["private_key_pem"].encode("ascii")
    )
    stored = db.one("SELECT * FROM imported_certificates WHERE cert_id = ?", (cid,))
    assert stored["key_encrypted"].startswith("enc:")
    assert leaf["private_key_pem"] not in str(stored)
    assert env["auth"].decrypt_secret(stored["key_encrypted"]) == leaf["private_key_pem"]
    replacement = certificate_factory(("replacement.test",), valid_days=180)
    body = import_api.CertMaterialIn(format="pkcs12", pkcs12_base64=_pfx(replacement))
    assert import_api.replace_imported_cert(cid, body, USER) == {"ok": True}
    current = db.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    assert current["name"] == record["name"]
    assert current["not_after"] == replacement["cert"].not_valid_after_utc.isoformat()
    assert json.loads(current["domains"]) == ["replacement.test"]
    assert certmap.frontend_cert_ids()[fid] == [cid]
    assert certmap.backend_cert_ids()[bid] == [cid]
    files, warnings = import_api.certsvc.cluster_cert_files(cluster["cluster"]["id"])
    assert warnings == []
    assert files == {
        "imported.crt": replacement["certificate_pem"].encode("ascii"),
        "imported.key": replacement["private_key_pem"].encode("ascii"),
    }
    public = import_api.list_certs()
    assert not any(key in public[0] for key in ("cert_pem", "key_encrypted", "password", "pkcs12_base64"))
    audit = db.q("SELECT action, detail FROM audit_log")
    assert audit[-2:] == [
        {"action": "cert.import", "detail": "imported"},
        {"action": "cert.import_replace", "detail": "imported"},
    ]
    assert replacement["private_key_pem"] not in str(public) + str(audit)


def test_invalid_replacement_and_duplicate_name_do_not_change_existing_import(
    env, import_api, certificate_factory
):
    leaf = certificate_factory()
    body = import_api.CertImportIn(name="original", **_pem_body(leaf))
    cid = import_api.import_cert(body, USER)["id"]
    before = env["db"].one("SELECT * FROM certificates WHERE id = ?", (cid,))
    material = import_api.certsvc.certificate_bytes(before)
    with pytest.raises(HTTPException) as error:
        import_api.import_cert(body, USER)
    assert error.value.status_code == 400
    with pytest.raises(HTTPException) as error:
        import_api.replace_imported_cert(
            cid, import_api.CertMaterialIn(certificate_pem="invalid"), USER
        )
    assert error.value.status_code == 400
    assert env["db"].one("SELECT * FROM certificates WHERE id = ?", (cid,)) == before
    assert import_api.certsvc.certificate_bytes(before) == material


def test_import_storage_failure_rolls_back_metadata(env, import_api, certificate_factory):
    db = env["db"]
    db.execute(
        "CREATE TRIGGER fail_import BEFORE INSERT ON imported_certificates"
        " BEGIN SELECT RAISE(ABORT, 'simulated storage error'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="simulated"):
        import_api.import_cert(
            import_api.CertImportIn(name="failed", **_pem_body(certificate_factory())), USER
        )
    assert db.q("SELECT * FROM certificates") == []
    assert db.q("SELECT * FROM imported_certificates") == []


def test_replacement_storage_failure_rolls_back_metadata(env, import_api, certificate_factory):
    db = env["db"]
    cid = import_api.import_cert(
        import_api.CertImportIn(name="original", **_pem_body(certificate_factory())), USER
    )["id"]
    before = db.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    material = import_api.certsvc.certificate_bytes(before)
    db.execute(
        "CREATE TRIGGER fail_replace BEFORE UPDATE ON imported_certificates"
        " BEGIN SELECT RAISE(ABORT, 'simulated storage error'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="simulated"):
        import_api.replace_imported_cert(
            cid, import_api.CertMaterialIn(**_pem_body(certificate_factory(("new.test",)))), USER
        )
    assert db.one("SELECT * FROM certificates WHERE id = ?", (cid,)) == before
    assert import_api.certsvc.certificate_bytes(before) == material


def test_import_deletion_does_not_touch_other_imports_or_acme_files(
    env, import_api, certificate_factory
):
    leaf = certificate_factory()
    ids = [
        import_api.import_cert(import_api.CertImportIn(name=name, **_pem_body(leaf)), USER)["id"]
        for name in ("first", "second")
    ]
    acme_dir = Path(import_api.certsvc.ACME_DIR) / "certificates"
    acme_dir.mkdir(parents=True)
    for suffix in (".crt", ".key"):
        (acme_dir / ("example.test" + suffix)).write_bytes(b"existing ACME data")
    import_api.delete_cert(ids[0], USER)
    assert env["db"].one("SELECT * FROM imported_certificates WHERE cert_id = ?", (ids[0],)) is None
    remaining = env["db"].one("SELECT * FROM certificates WHERE id = ?", (ids[1],))
    assert import_api.certsvc.pem_bytes(remaining) == leaf["certificate_pem"].encode("ascii")
    assert import_api.certsvc.key_bytes(remaining) == leaf["private_key_pem"].encode("ascii")
    assert all(path.read_bytes() == b"existing ACME data" for path in acme_dir.iterdir())


def test_imported_certificates_cannot_use_acme_actions(env, import_api, certificate_factory):
    cid = import_api.import_cert(
        import_api.CertImportIn(name="imported", **_pem_body(certificate_factory())), USER
    )["id"]
    for action in (
        lambda: import_api.renew_cert(cid, USER),
        lambda: import_api.set_auto_renew(cid, {"auto_renew": True}, USER),
        lambda: import_api.get_challenge(cid, USER),
        lambda: import_api.confirm_challenge(cid, USER),
    ):
        with pytest.raises(HTTPException) as error:
            action()
        assert error.value.status_code == 400
    with pytest.raises(ValueError, match="Importierte Zertifikate"):
        import_api.certsvc.issue(cid, renew=True)
    assert import_api.set_auto_renew(cid, {"auto_renew": False}, USER) == {"ok": True}
    assert env["db"].one("SELECT status FROM certificates WHERE id = ?", (cid,))["status"] == "active"
    assert env["db"].one("SELECT auto_renew FROM certificates WHERE id = ?", (cid,))["auto_renew"] == 0


def test_acme_certificate_cannot_be_replaced_by_import(env, import_api, certificate_factory):
    cid = env["db"].execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES ('acme', '[\"example.test\"]', 'manual')"
    )
    body = import_api.CertMaterialIn(**_pem_body(certificate_factory()))
    with pytest.raises(HTTPException) as error:
        import_api.replace_imported_cert(cid, body, USER)
    assert error.value.status_code == 400
    with pytest.raises(HTTPException) as error:
        import_api.replace_imported_cert(99999, body, USER)
    assert error.value.status_code == 404


def test_renewal_loop_excludes_imported_certificates(env, import_api, certificate_factory, monkeypatch):
    db = env["db"]
    cid = import_api.import_cert(
        import_api.CertImportIn(name="imported", **_pem_body(certificate_factory(valid_days=5))), USER
    )["id"]
    db.execute("UPDATE certificates SET auto_renew = 1 WHERE id = ?", (cid,))
    acme_id = db.execute(
        "INSERT INTO certificates (name, domains, dns_provider, status, not_after)"
        " VALUES ('acme', '[\"example.test\"]', 'cloudflare', 'active', ?)",
        ((datetime.now(timezone.utc) + timedelta(days=5)).isoformat(),),
    )
    calls = []

    async def sleep(seconds):
        if seconds != 30:
            raise asyncio.CancelledError()

    monkeypatch.setattr(import_api.certsvc.asyncio, "sleep", sleep)
    monkeypatch.setattr(import_api.certsvc, "issue", lambda cid, renew: calls.append((cid, renew)))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(import_api.certsvc.renewal_loop())
    assert calls == [(acme_id, True)]


def test_certificate_source_migration_is_idempotent(env):
    db = env["db"]
    cid = db.execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES ('legacy', '[\"example.test\"]', 'manual')"
    )
    db.execute("ALTER TABLE certificates DROP COLUMN source")
    db.init_db()
    db.init_db()
    assert db.one("SELECT * FROM certificates WHERE id = ?", (cid,))["source"] == "acme"


@pytest.mark.parametrize("stored_key", ["enc:invalid", "unexpected plaintext"])
def test_unreadable_imported_key_reports_deployment_error(
    env, cluster, import_api, certificate_factory, stored_key
):
    db = env["db"]
    cid = import_api.import_cert(
        import_api.CertImportIn(name="imported", **_pem_body(certificate_factory())), USER
    )["id"]
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, cert_id) VALUES (?, 'https', 443, 1, ?)",
        (cluster["cluster"]["id"], cid),
    )
    db.execute("UPDATE imported_certificates SET key_encrypted = ? WHERE cert_id = ?", (stored_key, cid))
    result = import_api.certsvc.deploy_cert(cid)
    assert result[0]["ok"] is False
    assert "nicht entschlüsselbar" in result[0]["error"]
    assert stored_key not in str(result)
    files, warnings = import_api.certsvc.cluster_cert_files(cluster["cluster"]["id"])
    assert files == {}
    assert "nicht entschlüsselbar" in warnings[0]


def test_imported_certificate_expiry_is_monitored(env, import_api, certificate_factory, monkeypatch):
    from app.services import alerting

    import_api.import_cert(
        import_api.CertImportIn(name="expiring-import", **_pem_body(certificate_factory(valid_days=5))), USER
    )
    env["db"].execute("DELETE FROM nodes")
    monkeypatch.setattr(alerting, "get_settings", lambda: {"enabled": True, "alert_cert_expiry": True})
    messages = []
    monkeypatch.setattr(alerting, "send", messages.append)
    alerting._check_once()
    assert len(messages) == 1
    assert "expiring-import" in messages[0]


def test_mixed_import_formats_are_rejected(import_api, certificate_factory):
    leaf = certificate_factory()
    for format in ("pem", "pkcs12"):
        with pytest.raises(HTTPException) as error:
            import_api.import_cert(import_api.CertImportIn(
                name="mixed", format=format, pkcs12_base64=_pfx(leaf), **_pem_body(leaf)
            ), USER)
        assert error.value.status_code == 400
        assert leaf["private_key_pem"] not in str(error.value.detail)


def test_import_survives_database_and_secret_reload(
    env, import_api, certificate_factory, monkeypatch
):
    monkeypatch.delenv("APP_SECRET")
    importlib.reload(env["auth"])
    leaf = certificate_factory()
    cid = import_api.import_cert(
        import_api.CertImportIn(name="persistent", **_pem_body(leaf)), USER
    )["id"]
    env["db"].get_db().close()
    db = importlib.reload(env["db"])
    importlib.reload(env["auth"])
    cert = db.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    assert import_api.certsvc.certificate_bytes(cert) == (
        leaf["certificate_pem"].encode("ascii"), leaf["private_key_pem"].encode("ascii")
    )
