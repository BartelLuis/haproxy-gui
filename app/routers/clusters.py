import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .. import auth, db as dbmod
from ..db import audit
from ..services import deploy as deploysvc
from ..services import runtime as runtimesvc
from ..services.configgen import generate_config

router = APIRouter(prefix="/api", tags=["clusters"])


class ClusterIn(BaseModel):
    name: str
    description: str = ""
    global_extra: str = ""
    defaults_extra: str = ""


class NodeIn(BaseModel):
    cluster_id: int
    name: str
    host: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_key: str = ""
    ssh_password: str = ""
    is_local: bool = False
    config_path: str = "/etc/haproxy/haproxy.cfg"
    cert_dir: str = "/etc/haproxy/certs"
    socket_type: str = "ssh"
    socket_path: str = "/var/run/haproxy/admin.sock"
    socket_host: str = ""
    socket_port: int = 0
    reload_cmd: str = ""


class DeployIn(BaseModel):
    validate_only: bool = False
    node_ids: list[int] = []


def node_public(node):
    n = dict(node)
    n["has_key"] = bool(n.pop("ssh_key", ""))
    n["has_password"] = bool(n.pop("ssh_password", ""))
    return n


def _get_cluster(cid):
    cluster = dbmod.one("SELECT * FROM clusters WHERE id = ?", (cid,))
    if not cluster:
        raise HTTPException(404, "Cluster nicht gefunden")
    return cluster


def _get_node(nid):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    return node


@router.get("/clusters")
def list_clusters():
    clusters = dbmod.q("SELECT * FROM clusters ORDER BY name")
    for c in clusters:
        c["nodes"] = [
            node_public(n)
            for n in dbmod.q(
                "SELECT * FROM nodes WHERE cluster_id = ? ORDER BY name", (c["id"],)
            )
        ]
    return clusters


@router.post("/clusters")
def create_cluster(body: ClusterIn, user=Depends(auth.require_auth)):
    try:
        cid = dbmod.execute(
            "INSERT INTO clusters (name, description, global_extra, defaults_extra)"
            " VALUES (?, ?, ?, ?)",
            (body.name, body.description, body.global_extra, body.defaults_extra),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Cluster-Name existiert bereits")
    audit(user["username"], "cluster.create", body.name)
    return {"id": cid}


@router.put("/clusters/{cid}")
def update_cluster(cid: int, body: ClusterIn, user=Depends(auth.require_auth)):
    _get_cluster(cid)
    dbmod.execute(
        "UPDATE clusters SET name=?, description=?, global_extra=?, defaults_extra=?"
        " WHERE id=?",
        (body.name, body.description, body.global_extra, body.defaults_extra, cid),
    )
    audit(user["username"], "cluster.update", body.name)
    return {"ok": True}


@router.delete("/clusters/{cid}")
def delete_cluster(cid: int, user=Depends(auth.require_auth)):
    cluster = _get_cluster(cid)
    dbmod.execute("DELETE FROM clusters WHERE id = ?", (cid,))
    audit(user["username"], "cluster.delete", cluster["name"])
    return {"ok": True}


@router.post("/nodes")
def create_node(body: NodeIn, user=Depends(auth.require_auth)):
    _get_cluster(body.cluster_id)
    try:
        nid = dbmod.execute(
            "INSERT INTO nodes (cluster_id, name, host, ssh_port, ssh_user, ssh_key,"
            " ssh_password, is_local, config_path, cert_dir, socket_type, socket_path,"
            " socket_host, socket_port, reload_cmd)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                body.cluster_id, body.name, body.host, body.ssh_port, body.ssh_user,
                body.ssh_key, body.ssh_password, int(body.is_local), body.config_path,
                body.cert_dir, body.socket_type, body.socket_path, body.socket_host,
                body.socket_port, body.reload_cmd,
            ),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Node-Name existiert in diesem Cluster bereits")
    audit(user["username"], "node.create", body.name)
    return {"id": nid}


@router.put("/nodes/{nid}")
def update_node(nid: int, body: NodeIn, user=Depends(auth.require_auth)):
    node = _get_node(nid)
    key = body.ssh_key if body.ssh_key else node["ssh_key"]
    password = body.ssh_password if body.ssh_password else node["ssh_password"]
    dbmod.execute(
        "UPDATE nodes SET cluster_id=?, name=?, host=?, ssh_port=?, ssh_user=?,"
        " ssh_key=?, ssh_password=?, is_local=?, config_path=?, cert_dir=?,"
        " socket_type=?, socket_path=?, socket_host=?, socket_port=?, reload_cmd=?"
        " WHERE id=?",
        (
            body.cluster_id, body.name, body.host, body.ssh_port, body.ssh_user,
            key, password, int(body.is_local), body.config_path, body.cert_dir,
            body.socket_type, body.socket_path, body.socket_host, body.socket_port,
            body.reload_cmd, nid,
        ),
    )
    audit(user["username"], "node.update", body.name)
    return {"ok": True}


@router.delete("/nodes/{nid}")
def delete_node(nid: int, user=Depends(auth.require_auth)):
    node = _get_node(nid)
    dbmod.execute("DELETE FROM nodes WHERE id = ?", (nid,))
    audit(user["username"], "node.delete", node["name"])
    return {"ok": True}


@router.post("/nodes/{nid}/test")
def test_node(nid: int):
    node = _get_node(nid)
    try:
        info = runtimesvc.show_info(node)
        return {
            "ok": True,
            "version": info.get("Version", "?"),
            "uptime": info.get("Uptime", "?"),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.get("/clusters/{cid}/config", response_class=PlainTextResponse)
def preview_config(cid: int, node_id: int | None = None):
    cluster = _get_cluster(cid)
    if node_id:
        node = dbmod.one(
            "SELECT * FROM nodes WHERE id = ? AND cluster_id = ?", (node_id, cid)
        )
        if not node:
            raise HTTPException(404, "Node nicht gefunden")
    else:
        node = dbmod.one(
            "SELECT * FROM nodes WHERE cluster_id = ?"
            " ORDER BY is_local DESC, name LIMIT 1",
            (cid,),
        )
    try:
        return generate_config(cluster, node)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


class DeployResult(BaseModel):
    results: list


@router.post("/clusters/{cid}/deploy")
def deploy_cluster(cid: int, body: DeployIn, user=Depends(auth.require_auth)):
    cluster = _get_cluster(cid)
    if body.node_ids:
        placeholders = ",".join("?" for _ in body.node_ids)
        nodes = dbmod.q(
            f"SELECT * FROM nodes WHERE cluster_id = ? AND id IN ({placeholders})",
            (cid, *body.node_ids),
        )
    else:
        nodes = dbmod.q("SELECT * FROM nodes WHERE cluster_id = ?", (cid,))
    if not nodes:
        raise HTTPException(400, "Cluster hat keine Nodes")
    results = [
        deploysvc.deploy_node(
            cluster, n, body.validate_only, user=user["username"]
        )
        for n in nodes
    ]
    ok_count = sum(1 for r in results if r["ok"])
    audit(
        user["username"],
        "cluster.deploy" if not body.validate_only else "cluster.validate",
        f"{cluster['name']}: {ok_count}/{len(results)} Nodes OK",
    )
    return {"results": results}
