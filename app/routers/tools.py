import difflib
import socket
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..services import metrics as metricsvc
from ..services.configgen import generate_config

router = APIRouter(prefix="/api", tags=["tools"])

DEFAULT_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 3306, 5432, 6379, 8080, 8443, 9000, 27017,
]


class PortScanIn(BaseModel):
    host: str
    ports: list[int] = []


def _scan_one(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {"port": port, "open": True}
    except OSError:
        return {"port": port, "open": False}


@router.post("/tools/portscan")
def portscan(body: PortScanIn, user=Depends(auth.require_auth)):
    host = body.host.strip()
    if not host:
        raise HTTPException(400, "Host erforderlich")
    ports = [p for p in body.ports if 0 < p < 65536] or DEFAULT_PORTS
    ports = sorted(set(ports))[:200]
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(lambda p: _scan_one(host, p), ports))
    return {"host": host, "results": results}


@router.get("/tools/compare")
def compare_configs(cluster_id: int, node_a: int, node_b: int,
                    user=Depends(auth.require_auth)):
    cluster = dbmod.one("SELECT * FROM clusters WHERE id = ?", (cluster_id,))
    if not cluster:
        raise HTTPException(404, "Cluster nicht gefunden")
    texts, names = [], []
    for nid in (node_a, node_b):
        node = dbmod.one(
            "SELECT * FROM nodes WHERE id = ? AND cluster_id = ?", (nid, cluster_id)
        )
        if not node:
            raise HTTPException(404, "Node nicht gefunden")
        try:
            texts.append(generate_config(cluster, node))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        names.append(node["name"])
    diff = difflib.unified_diff(
        texts[0].splitlines(), texts[1].splitlines(),
        fromfile=names[0], tofile=names[1], lineterm="",
    )
    return {"diff": "\n".join(diff) or "(keine Unterschiede)", "a": names[0], "b": names[1]}


@router.get("/nodes/{nid}/metrics")
def node_metrics(nid: int, user=Depends(auth.require_auth)):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        return {"ok": True, "metrics": metricsvc.get_metrics(node)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
