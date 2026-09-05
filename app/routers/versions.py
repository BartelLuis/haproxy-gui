import difflib

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from .. import auth, db as dbmod
from ..db import audit
from ..services import deploy as deploysvc
from ..services.configgen import generate_config

router = APIRouter(prefix="/api", tags=["versions"])


def _get_version(vid):
    v = dbmod.one("SELECT * FROM config_versions WHERE id = ?", (vid,))
    if not v:
        raise HTTPException(404, "Version nicht gefunden")
    return v


@router.get("/clusters/{cid}/versions")
def list_versions(cid: int, user=Depends(auth.require_auth)):
    return dbmod.q(
        "SELECT id, cluster_id, node_id, node_name, user, note, created_at,"
        " length(content) AS size FROM config_versions"
        " WHERE cluster_id = ? ORDER BY id DESC LIMIT 100",
        (cid,),
    )


@router.get("/versions/{vid}", response_class=PlainTextResponse)
def get_version(vid: int, user=Depends(auth.require_auth)):
    return _get_version(vid)["content"]


@router.get("/versions/{vid}/diff")
def diff_version(vid: int, other: int = 0, user=Depends(auth.require_auth)):
    """Vergleicht eine Version mit einer anderen (other=0: aktuell generierte Config)."""
    v = _get_version(vid)
    if other:
        other_text = _get_version(other)["content"]
        other_name = f"Version {other}"
    else:
        node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (v["node_id"],))
        cluster = dbmod.one("SELECT * FROM clusters WHERE id = ?", (v["cluster_id"],))
        if not node or not cluster:
            raise HTTPException(404, "Node/Cluster der Version existiert nicht mehr")
        try:
            other_text = generate_config(cluster, node)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        other_name = "Aktuell (generiert)"
    diff = difflib.unified_diff(
        v["content"].splitlines(),
        other_text.splitlines(),
        fromfile=f"Version {vid} ({v['created_at']})",
        tofile=other_name,
        lineterm="",
    )
    return {"diff": "\n".join(diff) or "(keine Unterschiede)"}


@router.post("/versions/{vid}/rollback")
def rollback(vid: int, user=Depends(auth.require_auth)):
    v = _get_version(vid)
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (v["node_id"],))
    cluster = dbmod.one("SELECT * FROM clusters WHERE id = ?", (v["cluster_id"],))
    if not node or not cluster:
        raise HTTPException(404, "Node/Cluster der Version existiert nicht mehr")
    result = deploysvc.deploy_node(
        cluster, node, content=v["content"], user=user["username"],
        note=f"Rollback auf Version {vid}",
    )
    audit(user["username"], "config.rollback", f"Version {vid} auf {node['name']}")
    return result
