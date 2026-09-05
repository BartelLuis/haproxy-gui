from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from .. import auth, db as dbmod
from ..services import logs as logsvc

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/nodes/{nid}", response_class=PlainTextResponse)
def node_log(nid: int, lines: int = 300, user=Depends(auth.require_auth)):
    node = dbmod.one("SELECT * FROM nodes WHERE id = ?", (nid,))
    if not node:
        raise HTTPException(404, "Node nicht gefunden")
    try:
        return logsvc.get_node_log(node, lines)
    except Exception as exc:
        raise HTTPException(502, str(exc))
