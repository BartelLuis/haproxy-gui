import importlib
import os
import sys

import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Isolierte Testumgebung: eigenes Datenverzeichnis + Admin-Passwort."""
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("HG_DATA", str(data))
    monkeypatch.setenv("ADMIN_PASSWORD", "test123")
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("APP_SECRET", "test-app-secret")

    import app.db as db
    import app.auth as auth

    importlib.reload(db)  # DATA_DIR/DB_PATH neu einlesen
    auth._secret = None   # Secret pro Testumgebung neu einlesen
    importlib.reload(auth)
    db.init_db()
    auth.seed_admin()
    return {"db": db, "auth": auth, "data": data}


@pytest.fixture()
def cluster(env):
    cluster = env["db"].one("SELECT * FROM clusters WHERE name = 'Local'")
    node = env["db"].one("SELECT * FROM nodes WHERE cluster_id = ?", (cluster["id"],))
    return {"cluster": cluster, "node": node}


@pytest.fixture()
def certificate_factory():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def create(
        domains=("example.test", "*.example.test"), *, key=None, issuer=None,
        valid_days=90, not_before=None, san_names=None, is_ca=False,
    ):
        key = key or ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer["cert"].subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        )
        names = [x509.DNSName(domain) for domain in domains] if san_names is None else san_names
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        cert = builder.sign(issuer["key"] if issuer else key, hashes.SHA256())
        return {
            "cert": cert,
            "key": key,
            "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "private_key_pem": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
        }

    return create
