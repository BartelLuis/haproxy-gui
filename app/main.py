import asyncio
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth, db
from .routers import (
    alerts,
    auth_routes,
    backends,
    certs,
    clusters,
    frontends,
    keepalived,
    ldaprouter,
    logs,
    stats,
    tools,
    users,
    versions,
)
from .services import alerting
from .services import certs as certsvc

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="HAProxy GUI", docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(auth_routes.router)
for r in (users.router, alerts.router, ldaprouter.router):
    app.include_router(r, dependencies=[Depends(auth.require_role("admin"))])
for r in (
    clusters.router,
    frontends.router,
    backends.router,
    certs.router,
    stats.router,
    versions.router,
    logs.router,
    tools.router,
    keepalived.router,
):
    app.include_router(r, dependencies=[Depends(auth.require_auth)])


@app.on_event("startup")
async def startup():
    db.init_db()
    auth.seed_admin()
    asyncio.create_task(certsvc.renewal_loop())
    asyncio.create_task(alerting.alert_loop())


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
