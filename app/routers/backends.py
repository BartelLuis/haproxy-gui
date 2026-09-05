import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import validate as v

router = APIRouter(prefix="/api/backends", tags=["backends"])


class ServerIn(BaseModel):
    name: str
    host: str
    port: int
    check: bool = True
    ssl: bool = False
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


def _insert_servers(backend_id, servers):
    for s in servers:
        dbmod.execute(
            'INSERT INTO servers (backend_id, name, host, port, "check", ssl, weight,'
            " maxconn, backup) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                backend_id, s.name, s.host, s.port, int(s.check), int(s.ssl),
                s.weight, s.maxconn, int(s.backup),
            ),
        )


@router.get("")
def list_backends(cluster_id: int | None = None):
    if cluster_id:
        backends = dbmod.q(
            "SELECT * FROM backends WHERE cluster_id = ? ORDER BY name", (cluster_id,)
        )
    else:
        backends = dbmod.q("SELECT * FROM backends ORDER BY name")
    for b in backends:
        b["servers"] = dbmod.q(
            "SELECT * FROM servers WHERE backend_id = ? ORDER BY name", (b["id"],)
        )
    return backends


@router.post("")
def create_backend(body: BackendIn, user=Depends(auth.require_auth)):
    if body.mode not in ("http", "tcp"):
        raise HTTPException(400, "Mode muss http oder tcp sein")
    try:
        v.clean_name(body.name, "Backend-Name")
        v.no_newline(body.check_path, "check_path")
        v.no_newline(body.check_expect, "check_expect")
        v.no_newline(body.extra, "extra")
        for s in body.servers:
            v.clean_name(s.name, "Server-Name")
            v.clean_host(s.host, "Server-Host")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
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
    audit(user["username"], "backend.create", body.name)
    return {"id": bid}


@router.put("/{bid}")
def update_backend(bid: int, body: BackendIn, user=Depends(auth.require_auth)):
    if not dbmod.one("SELECT id FROM backends WHERE id = ?", (bid,)):
        raise HTTPException(404, "Backend nicht gefunden")
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
    audit(user["username"], "backend.update", body.name)
    return {"ok": True}


@router.delete("/{bid}")
def delete_backend(bid: int, user=Depends(auth.require_auth)):
    be = dbmod.one("SELECT name FROM backends WHERE id = ?", (bid,))
    dbmod.execute("DELETE FROM backends WHERE id = ?", (bid,))
    audit(user["username"], "backend.delete", (be or {}).get("name", str(bid)))
    return {"ok": True}
