import json
import ipaddress
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
    bind_family: str = "ipv4"
    port: int
    mode: str = "http"
    use_ssl: bool = False
    cert_id: int | None = None
    ssl_redirect: bool = False
    default_backend_id: int | None = None
    acls: list = []
    rules: list = []
    extra: str = ""
    rate_limit_requests: int = 0
    rate_limit_period: int = 10


def _validate(body: FrontendIn):
    if body.mode not in ("http", "tcp"):
        raise HTTPException(400, "Mode muss http oder tcp sein")
    if body.bind_family not in ("ipv4", "ipv6", "dual"):
        raise HTTPException(400, "Bind-Familie muss ipv4, ipv6 oder dual sein")
    if body.rate_limit_requests < 0 or body.rate_limit_requests > 100000:
        raise HTTPException(400, "Rate-Limit muss zwischen 0 und 100000 liegen")
    if body.rate_limit_period < 1 or body.rate_limit_period > 3600:
        raise HTTPException(400, "Rate-Limit-Zeitraum muss zwischen 1 und 3600 Sekunden liegen")
    if body.rate_limit_requests and body.mode != "http":
        raise HTTPException(400, "Rate-Limits werden nur für HTTP-Frontends unterstützt")
    try:
        v.clean_name(body.name, "Frontend-Name")
        bind_ip = v.clean_bind_ip(body.bind_ip, "bind_ip")
        body.bind_ip = bind_ip
        if body.bind_family == "dual" and bind_ip not in ("*", "::"):
            raise ValueError("Dual-Stack-Binds benötigen die Wildcard-Adresse '*'")
        if bind_ip != "*":
            try:
                address_family = ipaddress.ip_address(bind_ip).version
            except ValueError:
                address_family = None
            if body.bind_family == "ipv4" and address_family == 6:
                raise ValueError("IPv4-Binds benötigen eine IPv4-Adresse")
            if body.bind_family == "ipv6" and address_family == 4:
                raise ValueError("IPv6-Binds benötigen eine IPv6-Adresse")
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
            "INSERT INTO frontends (cluster_id, name, bind_ip, bind_family, port, mode, use_ssl,"
            " cert_id, ssl_redirect, default_backend_id, acls, rules, extra,"
            " rate_limit_requests, rate_limit_period)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                body.cluster_id, body.name, body.bind_ip, body.bind_family, body.port, body.mode,
                int(body.use_ssl), body.cert_id, int(body.ssl_redirect),
                body.default_backend_id, json.dumps(body.acls),
                json.dumps(body.rules), body.extra, body.rate_limit_requests,
                body.rate_limit_period,
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
        "UPDATE frontends SET cluster_id=?, name=?, bind_ip=?, bind_family=?, port=?, mode=?,"
        " use_ssl=?, cert_id=?, ssl_redirect=?, default_backend_id=?, acls=?,"
        " rules=?, extra=?, rate_limit_requests=?, rate_limit_period=? WHERE id=?",
        (
            body.cluster_id, body.name, body.bind_ip, body.bind_family, body.port, body.mode,
            int(body.use_ssl), body.cert_id, int(body.ssl_redirect),
            body.default_backend_id, json.dumps(body.acls), json.dumps(body.rules),
            body.extra, body.rate_limit_requests, body.rate_limit_period, fid,
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
