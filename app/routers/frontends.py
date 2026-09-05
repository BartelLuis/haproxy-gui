import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import validate as v

router = APIRouter(prefix="/api/frontends", tags=["frontends"])


class FrontendIn(BaseModel):
    cluster_id: int
    name: str
    bind_ip: str = "*"
    port: int
    mode: str = "http"
    use_ssl: bool = False
    cert_id: int | None = None
    ssl_redirect: bool = False
    default_backend_id: int | None = None
    acls: list = []
    rules: list = []
    extra: str = ""


def _validate(body: FrontendIn):
    if body.mode not in ("http", "tcp"):
        raise HTTPException(400, "Mode muss http oder tcp sein")
    try:
        v.clean_name(body.name, "Frontend-Name")
        v.no_newline(body.bind_ip, "bind_ip")
        v.no_newline(body.extra, "extra")
        for acl in body.acls:
            v.clean_name(acl.get("name", ""), "ACL-Name")
            v.no_newline(acl.get("criterion", ""), "ACL-Kriterium")
            v.no_newline(acl.get("value", ""), "ACL-Wert")
        for rule in body.rules:
            v.no_newline(rule.get("backend", ""), "Regel-Backend")
            v.no_newline(rule.get("condition", ""), "Regel-Bedingung")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if body.use_ssl and not body.cert_id:
        raise HTTPException(400, "SSL aktiviert, aber kein Zertifikat gewählt")
    if body.cert_id and not dbmod.one(
        "SELECT id FROM certificates WHERE id = ?", (body.cert_id,)
    ):
        raise HTTPException(400, "Zertifikat nicht gefunden")
    if body.default_backend_id and not dbmod.one(
        "SELECT id FROM backends WHERE id = ? AND cluster_id = ?",
        (body.default_backend_id, body.cluster_id),
    ):
        raise HTTPException(400, "Default-Backend nicht im selben Cluster")


@router.get("")
def list_frontends(cluster_id: int | None = None):
    if cluster_id:
        return dbmod.q(
            "SELECT * FROM frontends WHERE cluster_id = ? ORDER BY name", (cluster_id,)
        )
    return dbmod.q("SELECT * FROM frontends ORDER BY name")


@router.post("")
def create_frontend(body: FrontendIn, user=Depends(auth.require_auth)):
    _validate(body)
    try:
        fid = dbmod.execute(
            "INSERT INTO frontends (cluster_id, name, bind_ip, port, mode, use_ssl,"
            " cert_id, ssl_redirect, default_backend_id, acls, rules, extra)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                body.cluster_id, body.name, body.bind_ip, body.port, body.mode,
                int(body.use_ssl), body.cert_id, int(body.ssl_redirect),
                body.default_backend_id, json.dumps(body.acls),
                json.dumps(body.rules), body.extra,
            ),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Frontend-Name existiert in diesem Cluster bereits")
    audit(user["username"], "frontend.create", body.name)
    return {"id": fid}


@router.put("/{fid}")
def update_frontend(fid: int, body: FrontendIn, user=Depends(auth.require_auth)):
    if not dbmod.one("SELECT id FROM frontends WHERE id = ?", (fid,)):
        raise HTTPException(404, "Frontend nicht gefunden")
    _validate(body)
    dbmod.execute(
        "UPDATE frontends SET cluster_id=?, name=?, bind_ip=?, port=?, mode=?,"
        " use_ssl=?, cert_id=?, ssl_redirect=?, default_backend_id=?, acls=?,"
        " rules=?, extra=? WHERE id=?",
        (
            body.cluster_id, body.name, body.bind_ip, body.port, body.mode,
            int(body.use_ssl), body.cert_id, int(body.ssl_redirect),
            body.default_backend_id, json.dumps(body.acls), json.dumps(body.rules),
            body.extra, fid,
        ),
    )
    audit(user["username"], "frontend.update", body.name)
    return {"ok": True}


@router.delete("/{fid}")
def delete_frontend(fid: int, user=Depends(auth.require_auth)):
    fe = dbmod.one("SELECT name FROM frontends WHERE id = ?", (fid,))
    dbmod.execute("DELETE FROM frontends WHERE id = ?", (fid,))
    audit(user["username"], "frontend.delete", (fe or {}).get("name", str(fid)))
    return {"ok": True}
