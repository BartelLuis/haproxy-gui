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

    import app.db as db
    import app.auth as auth

    importlib.reload(db)  # DATA_DIR/DB_PATH neu einlesen
    auth._secret = None   # Secret pro Testumgebung neu aus der Datei lesen
    importlib.reload(auth)
    db.init_db()
    auth.seed_admin()
    return {"db": db, "auth": auth, "data": data}


@pytest.fixture()
def cluster(env):
    cluster = env["db"].one("SELECT * FROM clusters WHERE name = 'Local'")
    node = env["db"].one("SELECT * FROM nodes WHERE cluster_id = ?", (cluster["id"],))
    return {"cluster": cluster, "node": node}
