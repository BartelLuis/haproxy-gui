from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import keepalived as ksvc

router = APIRouter(prefix="/api/clusters/{cid}/keepalived", tags=["keepalived"])


class KeepalivedNodeIn(BaseModel):
    node_id: int
    state: str = "BACKUP"
    priority: int = 100


class KeepalivedIn(BaseModel):
    vip: str = ""
    iface: str = "eth0"
    vr_id: int = 51
    auth_pass: str = ""
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
    for n in body.nodes:
        if n.state not in ("MASTER", "BACKUP"):
            raise HTTPException(400, "state muss MASTER oder BACKUP sein")
    ksvc.save_cluster_config(
        cid,
        {"vip": body.vip, "iface": body.iface, "vr_id": body.vr_id,
         "auth_pass": body.auth_pass},
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
        except Exception as exc:
            out.append({"node": n["name"], "status": f"Fehler: {exc}"})
    return out
