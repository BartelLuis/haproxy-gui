import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth
from .. import db as dbmod
from ..db import audit

router = APIRouter(prefix="/api", tags=["users"])

ROLES = ("viewer", "operator", "admin")


class UserIn(BaseModel):
    username: str
    password: str = ""
    role: str = "viewer"


class TokenIn(BaseModel):
    name: str
    role: str = "operator"


@router.get("/users")
def list_users(user=Depends(auth.require_role("admin"))):
    return dbmod.q(
        "SELECT id, username, role, created_at FROM users ORDER BY username"
    )


@router.post("/users")
def create_user(body: UserIn, user=Depends(auth.require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(400, "Ungültige Rolle")
    if not body.password:
        raise HTTPException(400, "Passwort erforderlich")
    try:
        uid = dbmod.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (body.username, auth.hash_password(body.password), body.role),
        )
    except Exception:
        raise HTTPException(400, "Benutzername existiert bereits")
    audit(user["username"], "user.create", body.username)
    return {"id": uid}


@router.put("/users/{uid}")
def update_user(uid: int, body: UserIn, user=Depends(auth.require_role("admin"))):
    row = dbmod.one("SELECT * FROM users WHERE id = ?", (uid,))
    if not row:
        raise HTTPException(404, "Benutzer nicht gefunden")
    if body.role not in ROLES:
        raise HTTPException(400, "Ungültige Rolle")
    if row["username"] == user["username"] and body.role != "admin":
        raise HTTPException(400, "Die eigene Admin-Rolle kann nicht entzogen werden")
    dbmod.execute(
        "UPDATE users SET username = ?, role = ? WHERE id = ?",
        (body.username, body.role, uid),
    )
    if body.password:
        dbmod.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (auth.hash_password(body.password), uid),
        )
    audit(user["username"], "user.update", body.username)
    return {"ok": True}


@router.delete("/users/{uid}")
def delete_user(uid: int, user=Depends(auth.require_role("admin"))):
    row = dbmod.one("SELECT * FROM users WHERE id = ?", (uid,))
    if not row:
        raise HTTPException(404, "Benutzer nicht gefunden")
    if row["username"] == user["username"]:
        raise HTTPException(400, "Der eigene Benutzer kann nicht gelöscht werden")
    dbmod.execute("DELETE FROM users WHERE id = ?", (uid,))
    audit(user["username"], "user.delete", row["username"])
    return {"ok": True}


@router.get("/tokens")
def list_tokens(user=Depends(auth.require_role("admin"))):
    return dbmod.q(
        "SELECT id, name, role, created_at, last_used FROM api_tokens ORDER BY name"
    )


@router.post("/tokens")
def create_token(body: TokenIn, user=Depends(auth.require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(400, "Ungültige Rolle")
    token = "hg_" + secrets.token_urlsafe(32)
    try:
        tid = dbmod.execute(
            "INSERT INTO api_tokens (name, token_hash, role) VALUES (?, ?, ?)",
            (body.name, hashlib.sha256(token.encode()).hexdigest(), body.role),
        )
    except Exception:
        raise HTTPException(400, "Token-Name existiert bereits")
    audit(user["username"], "token.create", body.name)
    return {"id": tid, "token": token}


@router.delete("/tokens/{tid}")
def delete_token(tid: int, user=Depends(auth.require_role("admin"))):
    dbmod.execute("DELETE FROM api_tokens WHERE id = ?", (tid,))
    audit(user["username"], "token.delete", str(tid))
    return {"ok": True}


@router.get("/audit")
def list_audit(user=Depends(auth.require_role("admin")), limit: int = 200):
    limit = max(1, min(limit, 1000))
    return dbmod.q(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    )
