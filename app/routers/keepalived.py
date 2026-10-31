from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import ipaddress
import re
import logging

from .. import auth, db as dbmod
from ..db import audit
from ..services import keepalived as ksvc
from ..services import validate as v

router = APIRouter(prefix="/api/clusters/{cid}/keepalived", tags=["keepalived"])
logger = logging.getLogger(__name__)


class KeepalivedNodeIn(BaseModel):
    node_id: int
    state: str = "BACKUP"
    priority: int = 100
    peer_ip: str = ""


class KeepalivedIn(BaseModel):
    vip: str = ""
    iface: str = "eth0"
    vr_id: int = 51
    auth_pass: str = ""
    track_haproxy: bool = False
    nodes: list[KeepalivedNodeIn] = []


def _get_cluster(cid):
    cluster = dbmod.one("SELECT * FROM clusters WHERE id = ?", (cid,))
    if not cluster:
        raise HTTPException(404, "Cluster nicht gefunden")
    return cluster


@router.get("")
def get_keepalived(cid: int, user=Depends(auth.require_auth)):
    _get_cluster(cid)
    return ksvc.get_cluster_config(cid)


@router.put("")
def put_keepalived(cid: int, body: KeepalivedIn, user=Depends(auth.require_auth)):
    _get_cluster(cid)
    if not 1 <= body.vr_id <= 255:
        raise HTTPException(400, "Virtual Router ID muss zwischen 1 und 255 liegen")
    if len(body.auth_pass) > 8:
        raise HTTPException(400, "Auth-Passwort darf höchstens 8 Zeichen enthalten")
    node_ids = [node.node_id for node in body.nodes]
    if len(node_ids) != len(set(node_ids)):
        raise HTTPException(400, "Node darf nur einmal konfiguriert werden")
    cluster_node_ids = {
        node["id"]
        for node in dbmod.q("SELECT id FROM nodes WHERE cluster_id = ?", (cid,))
    }
    if any(node_id not in cluster_node_ids for node_id in node_ids):
        raise HTTPException(400, "Keepalived-Node gehört nicht zu diesem Cluster")
    try:
        if body.vip:
            vip_text = v.clean_vip(body.vip, "VIP")
            body.vip = vip_text
            vip_addresses = [
                ipaddress.ip_interface(item)
                for item in re.split(r"[\n,]+", vip_text)
                if item.strip()
            ]
            if body.auth_pass and not any(address.version == 4 for address in vip_addresses):
                raise ValueError("VRRPv3 unterstützt keine Authentifizierung für IPv6-VIPs")
        v.clean_iface(body.iface or "eth0", "Interface")
        v.no_newline(body.auth_pass, "auth_pass")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    for n in body.nodes:
        if n.state not in ("MASTER", "BACKUP"):
            raise HTTPException(400, "state muss MASTER oder BACKUP sein")
        if not 1 <= n.priority <= 254:
            raise HTTPException(400, "Priorität muss zwischen 1 und 254 liegen")
        if n.peer_ip:
            try:
                n.peer_ip = str(ipaddress.ip_address(v.clean_host(n.peer_ip, "VRRP-Peer-IP")))
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
    ksvc.save_cluster_config(
        cid,
        {"vip": body.vip, "iface": body.iface, "vr_id": body.vr_id,
         "auth_pass": body.auth_pass, "track_haproxy": body.track_haproxy},
        [n.model_dump() for n in body.nodes],
    )
    audit(user["username"], "keepalived.save", f"Cluster {cid}")
    return {"ok": True}


@router.get("/preview")
def preview(cid: int, nid: int, user=Depends(auth.require_auth)):
    cluster = _get_cluster(cid)
    node = dbmod.one("SELECT * FROM nodes WHERE id = ? AND cluster_id = ?", (nid, cid))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        return {"config": ksvc.generate(cluster, node)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/deploy")
def deploy(cid: int, user=Depends(auth.require_auth)):
    cluster = _get_cluster(cid)
    nodes = dbmod.q(
        "SELECT * FROM nodes WHERE cluster_id = ? AND is_local = 0", (cid,)
    )
    if not nodes:
        raise HTTPException(400, "Keine Remote-Nodes im Cluster")
    results = [ksvc.deploy_node(cluster, n) for n in nodes]
    audit(user["username"], "keepalived.deploy", cluster["name"])
    return {"results": results}


@router.get("/status")
def status(cid: int, user=Depends(auth.require_auth)):
    _get_cluster(cid)
    nodes = dbmod.q("SELECT * FROM nodes WHERE cluster_id = ?", (cid,))
    out = []
    for n in nodes:
        try:
            out.append(ksvc.node_status(n))
        except Exception:
            logger.exception("Failed to fetch keepalived status for node '%s' in cluster %s", n["name"], cid)
            out.append({"node": n["name"], "status": "Fehler bei der Statusabfrage"})
    return out
