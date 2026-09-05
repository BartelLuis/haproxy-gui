import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import certs as certsvc

router = APIRouter(prefix="/api", tags=["certificates"])


class CertIn(BaseModel):
    name: str
    domains: list[str]
    email: str = ""
    dns_provider: str
    provider_config: dict = {}
    auto_renew: bool = True


@router.get("/dns-providers")
def dns_providers():
    return certsvc.providers_public()


@router.get("/certificates")
def list_certs():
    certs = dbmod.q("SELECT * FROM certificates ORDER BY name")
    for c in certs:
        c["domains"] = json.loads(c["domains"])
        pc = json.loads(c["provider_config"] or "{}")
        c["provider_config"] = {k: ("***" if v else "") for k, v in pc.items()}
        c["auto_renew"] = bool(c["auto_renew"])
    return certs


@router.post("/certificates")
def create_cert(body: CertIn, user=Depends(auth.require_auth)):
    if body.dns_provider not in certsvc.PROVIDERS:
        raise HTTPException(400, "Unbekannter DNS-Provider")
    domains = [d.strip().lower() for d in body.domains if d.strip()]
    if not domains:
        raise HTTPException(400, "Mindestens eine Domain erforderlich")
    try:
        cid = dbmod.execute(
            "INSERT INTO certificates (name, domains, email, dns_provider,"
            " provider_config, auto_renew) VALUES (?,?,?,?,?,?)",
            (
                body.name, json.dumps(domains), body.email, body.dns_provider,
                json.dumps(body.provider_config), int(body.auto_renew),
            ),
        )
    except Exception:
        raise HTTPException(400, "Zertifikatsname existiert bereits")
    audit(user["username"], "cert.create", body.name)
    certsvc.issue_background(cid)
    return {"id": cid}


@router.post("/certificates/{cid}/renew")
def renew_cert(cid: int, user=Depends(auth.require_auth)):
    if not dbmod.one("SELECT id FROM certificates WHERE id = ?", (cid,)):
        raise HTTPException(404, "Zertifikat nicht gefunden")
    audit(user["username"], "cert.renew", str(cid))
    certsvc.issue_background(cid, renew=True)
    return {"ok": True}


@router.post("/certificates/{cid}/deploy")
def deploy_cert(cid: int, user=Depends(auth.require_auth)):
    if not dbmod.one("SELECT id FROM certificates WHERE id = ?", (cid,)):
        raise HTTPException(404, "Zertifikat nicht gefunden")
    audit(user["username"], "cert.deploy", str(cid))
    return {"results": certsvc.deploy_cert(cid)}


@router.put("/certificates/{cid}/auto-renew")
def set_auto_renew(cid: int, body: dict, user=Depends(auth.require_auth)):
    dbmod.execute(
        "UPDATE certificates SET auto_renew = ? WHERE id = ?",
        (int(bool(body.get("auto_renew"))), cid),
    )
    return {"ok": True}


@router.delete("/certificates/{cid}")
def delete_cert(cid: int, user=Depends(auth.require_auth)):
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    if cert:
        certsvc.remove_cert_files(cert)
        audit(user["username"], "cert.delete", cert["name"])
    dbmod.execute("DELETE FROM certificates WHERE id = ?", (cid,))
    return {"ok": True}
