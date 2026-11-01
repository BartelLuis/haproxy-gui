import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import certmap
from ..services import validate as v

router = APIRouter(prefix="/api/backends", tags=["backends"])


class ServerIn(BaseModel):
    name: str
    host: str
    port: int
    check: bool = True
    ssl: bool = False
    ssl_verify: bool = False
    weight: int = 100
    maxconn: int = 0
    backup: bool = False


class BackendIn(BaseModel):
    cluster_id: int
    name: str
    mode: str = "http"
    balance: str = "roundrobin"
    check_path: str = ""
    check_expect: str = ""
    extra: str = ""
    servers: list[ServerIn] = []
    # Werden von SSL-Frontends geladen, die auf dieses Backend weiterleiten.
    # None lässt die Zuordnung beim Bearbeiten unverändert.
    cert_ids: list[int] | None = None


def _insert_servers(backend_id, servers):
    for s in servers:
        dbmod.execute(
            'INSERT INTO servers (backend_id, name, host, port, "check", ssl, ssl_verify,'
            " weight, maxconn, backup) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                backend_id, s.name, s.host, s.port, int(s.check), int(s.ssl),
                int(s.ssl_verify), s.weight, s.maxconn, int(s.backup),
            ),
        )


def _validate(body: BackendIn):
    if body.mode not in ("http", "tcp"):
        raise HTTPException(400, "Mode muss http oder tcp sein")
    try:
        v.clean_name(body.name, "Backend-Name")
        v.no_newline(body.check_path, "check_path")
        v.no_newline(body.check_expect, "check_expect")
        v.no_newline(body.extra, "extra")
        for server in body.servers:
            v.clean_name(server.name, "Server-Name")
            server.host = v.clean_host(server.host, "Server-Host")
            server.ssl_verify = server.ssl and server.ssl_verify
            if server.ssl_verify:
                v.require_tls_hostname(server.host, f"Server '{server.name}'")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _validate_certs(body: BackendIn, bid: int | None = None):
    if body.cert_ids is None:
        cert_ids = certmap.backend_cert_ids().get(bid, []) if bid else []
    else:
        cert_ids = certmap.unique_ids(body.cert_ids)
    known_certs = {row["id"] for row in dbmod.q("SELECT id FROM certificates")}
    if any(cert_id not in known_certs for cert_id in cert_ids):
        raise HTTPException(400, "Zertifikat nicht gefunden")
    if len(cert_ids) > certmap.MAX_FRONTEND_CERTS:
        raise HTTPException(
            400, f"Maximal {certmap.MAX_FRONTEND_CERTS} Zertifikate je Backend möglich"
        )
    # Vor der Folgenprüfung, die eindeutige Backend-Namen voraussetzt.
    if dbmod.one(
        "SELECT id FROM backends WHERE cluster_id = ? AND name = ? AND id != ?",
        (body.cluster_id, body.name, bid or 0),
    ):
        raise HTTPException(400, "Backend- oder Server-Name existiert bereits")
    problems = certmap.backend_change_problems(bid, body.cluster_id, body.name, cert_ids)
    if problems:
        raise HTTPException(400, "; ".join(problems))
    return cert_ids


@router.get("")
def list_backends(cluster_id: int | None = None):
    if cluster_id:
        backends = dbmod.q(
            "SELECT * FROM backends WHERE cluster_id = ? ORDER BY name", (cluster_id,)
        )
    else:
        backends = dbmod.q("SELECT * FROM backends ORDER BY name")
    backend_certs = certmap.backend_cert_ids(cluster_id or None)
    for b in backends:
        b["servers"] = dbmod.q(
            "SELECT * FROM servers WHERE backend_id = ? ORDER BY name", (b["id"],)
        )
        b["cert_ids"] = backend_certs.get(b["id"], [])
    return backends


@router.post("")
def create_backend(body: BackendIn, user=Depends(auth.require_auth)):
    _validate(body)
    cert_ids = _validate_certs(body)
    try:
        bid = dbmod.execute(
            "INSERT INTO backends (cluster_id, name, mode, balance, check_path,"
            " check_expect, extra) VALUES (?,?,?,?,?,?,?)",
            (
                body.cluster_id, body.name, body.mode, body.balance,
                body.check_path, body.check_expect, body.extra,
            ),
        )
        _insert_servers(bid, body.servers)
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Backend- oder Server-Name existiert bereits")
    certmap.save_backend_certs(bid, cert_ids)
    audit(user["username"], "backend.create", body.name)
    return {"id": bid}


@router.put("/{bid}")
def update_backend(bid: int, body: BackendIn, user=Depends(auth.require_auth)):
    if not dbmod.one("SELECT id FROM backends WHERE id = ?", (bid,)):
        raise HTTPException(404, "Backend nicht gefunden")
    _validate(body)
    cert_ids = _validate_certs(body, bid)
    try:
        dbmod.execute(
            "UPDATE backends SET cluster_id=?, name=?, mode=?, balance=?,"
            " check_path=?, check_expect=?, extra=? WHERE id=?",
            (
                body.cluster_id, body.name, body.mode, body.balance,
                body.check_path, body.check_expect, body.extra, bid,
            ),
        )
        dbmod.execute("DELETE FROM servers WHERE backend_id = ?", (bid,))
        _insert_servers(bid, body.servers)
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Backend- oder Server-Name existiert bereits")
    certmap.save_backend_certs(bid, cert_ids)
    audit(user["username"], "backend.update", body.name)
    return {"ok": True}


@router.delete("/{bid}")
def delete_backend(bid: int, user=Depends(auth.require_auth)):
    be = dbmod.one("SELECT name FROM backends WHERE id = ?", (bid,))
    dbmod.execute("DELETE FROM backends WHERE id = ?", (bid,))
    audit(user["username"], "backend.delete", (be or {}).get("name", str(bid)))
    return {"ok": True}
