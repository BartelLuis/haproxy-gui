import json
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, SecretStr

from .. import auth, db as dbmod
from ..db import audit
from ..services import certimport, certmap
from ..services import certs as certsvc
from ..services import validate as v

router = APIRouter(prefix="/api", tags=["certificates"])


class CertIn(BaseModel):
    name: str
    domains: list[str]
    email: str = ""
    dns_provider: str
    provider_config: dict = {}
    auto_renew: bool = True


class AcmeSettingsIn(BaseModel):
    dns_resolvers: list[str]


class CertMaterialIn(BaseModel):
    format: Literal["pem", "pkcs12"] = "pem"
    certificate_pem: SecretStr = SecretStr("")
    private_key_pem: SecretStr = SecretStr("")
    chain_pem: SecretStr = SecretStr("")
    pkcs12_base64: SecretStr = SecretStr("")
    password: SecretStr = SecretStr("")


class CertImportIn(CertMaterialIn):
    name: str


def _get_cert(cid: int):
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    if not cert:
        raise HTTPException(404, "Zertifikat nicht gefunden")
    return cert


def _parse_import(body: CertMaterialIn) -> certimport.ImportedCertificate:
    certificate = body.certificate_pem.get_secret_value()
    key = body.private_key_pem.get_secret_value()
    chain = body.chain_pem.get_secret_value()
    pfx = body.pkcs12_base64.get_secret_value()
    password = body.password.get_secret_value()
    try:
        if body.format == "pkcs12":
            if certificate or key or chain:
                raise ValueError("Bitte entweder PEM oder PFX/P12 importieren, nicht beides")
            return certimport.parse_pkcs12(pfx, password)
        if pfx:
            raise ValueError("Für PFX/P12-Dateien das Format pkcs12 auswählen")
        return certimport.parse_pem(certificate, key, chain, password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _store_import(
    conn: sqlite3.Connection, cid: int, material: certimport.ImportedCertificate
) -> None:
    conn.execute(
        "INSERT INTO imported_certificates (cert_id, cert_pem, key_encrypted) VALUES (?, ?, ?)"
        " ON CONFLICT(cert_id) DO UPDATE SET cert_pem = excluded.cert_pem,"
        " key_encrypted = excluded.key_encrypted",
        (cid, material.cert_pem, auth.encrypt_secret(material.key_pem.decode("ascii"))),
    )


@router.get("/acme/settings")
def get_acme_settings():
    return certsvc.get_acme_settings()


@router.put("/acme/settings")
def put_acme_settings(body: AcmeSettingsIn, user=Depends(auth.require_role("admin"))):
    try:
        certsvc.save_acme_settings(body.dns_resolvers)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit(user["username"], "acme.settings", ", ".join(body.dns_resolvers))
    return {"ok": True}


@router.get("/dns-providers")
def dns_providers():
    return certsvc.providers_public()


@router.get("/certificates")
def list_certs():
    certs = dbmod.q("SELECT * FROM certificates ORDER BY name")
    usage = certmap.cert_usage()
    for c in certs:
        c["domains"] = json.loads(c["domains"])
        pc = json.loads(c["provider_config"] or "{}")
        c["provider_config"] = {k: ("***" if v else "") for k, v in pc.items()}
        c["auto_renew"] = bool(c["auto_renew"])
        c["used_by"] = usage.get(c["id"], [])
    return certs


@router.post("/certificates")
def create_cert(body: CertIn, user=Depends(auth.require_auth)):
    if body.dns_provider not in certsvc.PROVIDERS:
        raise HTTPException(400, "Unbekannter DNS-Provider")
    try:
        name = v.clean_name(body.name, "Zertifikatsname")
        domains = [v.clean_domain(d.strip().lower(), "Domain") for d in body.domains if d.strip()]
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not domains:
        raise HTTPException(400, "Mindestens eine Domain erforderlich")
    try:
        cid = dbmod.execute(
            "INSERT INTO certificates (name, domains, email, dns_provider,"
            " provider_config, auto_renew) VALUES (?,?,?,?,?,?)",
            (
                name, json.dumps(domains), body.email, body.dns_provider,
                json.dumps(body.provider_config), int(body.auto_renew),
            ),
        )
    except Exception:
        raise HTTPException(400, "Zertifikatsname existiert bereits")
    audit(user["username"], "cert.create", name)
    certsvc.issue_background(cid)
    return {"id": cid}


@router.post("/certificates/import")
def import_cert(body: CertImportIn, user=Depends(auth.require_auth)):
    try:
        name = v.clean_name(body.name, "Zertifikatsname")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    material = _parse_import(body)
    conn = dbmod.get_db()
    try:
        with conn:
            cid = conn.execute(
                "INSERT INTO certificates"
                " (name, domains, dns_provider, source, auto_renew, status, not_after)"
                " VALUES (?, ?, '', 'imported', 0, 'active', ?)",
                (name, json.dumps(material.domains), material.not_after),
            ).lastrowid
            if cid is None:
                raise RuntimeError("Zertifikat konnte nicht angelegt werden")
            _store_import(conn, cid, material)
    except sqlite3.IntegrityError as exc:
        if exc.sqlite_errorcode != sqlite3.SQLITE_CONSTRAINT_UNIQUE:
            raise
        raise HTTPException(400, "Zertifikatsname existiert bereits") from exc
    audit(user["username"], "cert.import", name)
    return {"id": cid}


@router.put("/certificates/{cid}/import")
def replace_imported_cert(cid: int, body: CertMaterialIn, user=Depends(auth.require_auth)):
    cert = _get_cert(cid)
    if cert["source"] != "imported":
        raise HTTPException(400, "Nur importierte Zertifikate können per Import ersetzt werden")
    material = _parse_import(body)
    conn = dbmod.get_db()
    with conn:
        conn.execute(
            "UPDATE certificates SET domains = ?, not_after = ?, status = 'active',"
            " message = '', auto_renew = 0 WHERE id = ?",
            (json.dumps(material.domains), material.not_after, cid),
        )
        _store_import(conn, cid, material)
    audit(user["username"], "cert.import_replace", cert["name"])
    return {"ok": True}


@router.post("/certificates/{cid}/renew")
def renew_cert(cid: int, user=Depends(auth.require_auth)):
    cert = _get_cert(cid)
    if cert["source"] == "imported":
        raise HTTPException(400, "Importierte Zertifikate müssen durch einen neuen Import ersetzt werden")
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
    cert = _get_cert(cid)
    if cert["source"] == "imported" and body.get("auto_renew"):
        raise HTTPException(400, "Auto-Renew ist für importierte Zertifikate nicht verfügbar")
    dbmod.execute(
        "UPDATE certificates SET auto_renew = ? WHERE id = ?",
        (int(bool(body.get("auto_renew"))), cid),
    )
    return {"ok": True}


@router.get("/certificates/{cid}/challenge")
def get_challenge(cid: int, user=Depends(auth.require_auth)):
    """Liest die aktuell zu setzenden TXT-Records (manuelles DNS)."""
    cert = _get_cert(cid)
    if cert["source"] == "imported":
        raise HTTPException(400, "Importierte Zertifikate verwenden keine DNS-Challenge")
    records = certsvc.get_pending_challenge(cert)
    return {"status": cert["status"], "records": records}


@router.post("/certificates/{cid}/confirm")
def confirm_challenge(cid: int, user=Depends(auth.require_auth)):
    """Bestätigt, dass der TXT-Record gesetzt ist (manuelles DNS)."""
    ok, msg = certsvc.confirm_manual(cid)
    if not ok:
        raise HTTPException(400, msg)
    audit(user["username"], "cert.manual_confirm", str(cid))
    return {"ok": True, "message": msg}


@router.delete("/certificates/{cid}")
def delete_cert(cid: int, user=Depends(auth.require_auth)):
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cid,))
    if cert:
        certsvc.remove_cert_files(cert)
        audit(user["username"], "cert.delete", cert["name"])
    dbmod.execute("DELETE FROM certificates WHERE id = ?", (cid,))
    return {"ok": True}
