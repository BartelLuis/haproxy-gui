from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import db as dbmod
from ..services import runtime as runtimesvc
from .clusters import node_public

router = APIRouter(prefix="/api", tags=["stats"])


def _probe(node):
    try:
        info = runtimesvc.show_info(node)
        return {"online": True, "info": info}
    except Exception as exc:
        return {"online": False, "error": str(exc)}


@router.get("/overview")
def overview():
    clusters = dbmod.q("SELECT * FROM clusters ORDER BY name")
    all_nodes = []
    for c in clusters:
        nodes = dbmod.q(
            "SELECT * FROM nodes WHERE cluster_id = ? ORDER BY name", (c["id"],)
        )
        c["nodes"] = nodes
        all_nodes.extend(nodes)
    if all_nodes:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_probe, all_nodes))
        probed = {n["id"]: r for n, r in zip(all_nodes, results)}
        for c in clusters:
            c["nodes"] = [
                dict(node_public(n), **probed[n["id"]]) for n in c["nodes"]
            ]
    return clusters


@router.get("/stats/nodes/{nid}/stat")
def node_stat(nid: int):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        rows = runtimesvc.show_stat(node)
        return {"ok": True, "rows": rows}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "rows": []}


class ServerStateIn(BaseModel):
    backend: str
    server: str
    state: str


@router.post("/stats/nodes/{nid}/server-state")
def server_state(nid: int, body: ServerStateIn):
    if body.state not in ("ready", "drain", "maint"):
        raise HTTPException(400, "state muss ready, drain oder maint sein")
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        out = runtimesvc.set_server_state(node, body.backend, body.server, body.state)
        return {"ok": True, "message": out.strip()}
    except Exception as exc:
        raise HTTPException(502, str(exc))


def _parse_tables(text):
    tables = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# table:"):
            name = line.split(":", 1)[1].split(",")[0].strip()
            info = {"name": name}
            for part in line.split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    info[k.strip().lstrip("#").strip()] = v.strip()
            tables.append(info)
    return tables


@router.get("/stats/nodes/{nid}/tables")
def list_tables(nid: int):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        return {"ok": True, "tables": _parse_tables(runtimesvc.runtime_cmd(node, "show table"))}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "tables": []}


class TableIn(BaseModel):
    table: str


@router.post("/stats/nodes/{nid}/tables/clear")
def clear_table(nid: int, body: TableIn):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        out = runtimesvc.runtime_cmd(node, f"clear table {body.table}")
        return {"ok": True, "message": out.strip()}
    except Exception as exc:
        raise HTTPException(502, str(exc))


def _parse_maps(text):
    maps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("# id") and "(" not in line:
            continue
        if line.startswith("#"):
            # Format: "# 1 (desc) size" bzw. "# id (file) curr_size"
            content = line.lstrip("#").strip()
            parts = content.split(None, 1)
            if parts and parts[0].isdigit():
                maps.append({"id": parts[0], "info": parts[1] if len(parts) > 1 else ""})
    return maps


@router.get("/stats/nodes/{nid}/maps")
def list_maps(nid: int):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        return {"ok": True, "maps": _parse_maps(runtimesvc.runtime_cmd(node, "show map"))}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "maps": []}


@router.get("/stats/nodes/{nid}/maps/{map_id}/entries")
def map_entries(nid: int, map_id: str):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        out = runtimesvc.runtime_cmd(node, f"show map #{map_id}")
        entries = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            entries.append({"key": parts[0], "value": parts[1] if len(parts) > 1 else ""})
        return {"ok": True, "entries": entries}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "entries": []}


class MapEntryIn(BaseModel):
    map_id: str
    key: str
    value: str = ""
    action: str = "add"


@router.post("/stats/nodes/{nid}/maps/entry")
def map_entry(nid: int, body: MapEntryIn):
    if body.action not in ("add", "del"):
        raise HTTPException(400, "action muss add oder del sein")
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    if body.action == "add":
        cmd = f"add map #{body.map_id} {body.key} {body.value}"
    else:
        cmd = f"del map #{body.map_id} {body.key}"
    try:
        out = runtimesvc.runtime_cmd(node, cmd)
        return {"ok": True, "message": out.strip()}
    except Exception as exc:
        raise HTTPException(502, str(exc))
