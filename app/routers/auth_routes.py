from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from .. import auth
from ..db import audit
from ..services import ldapsvc

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginIn, response: Response):
    user = auth.check_credentials(body.username, body.password)
    if not user:
        # Fallback: LDAP (falls aktiviert)
        ldap_user = ldapsvc.authenticate(body.username, body.password)
        if ldap_user:
            user = {"id": -1, **ldap_user}
    if not user:
        raise HTTPException(status_code=401, detail="Ungültige Zugangsdaten")
    token = auth.create_token(user)
    response.set_cookie(
        "hg_token", token, httponly=True, samesite="lax", max_age=auth.TOKEN_TTL
    )
    audit(user["username"], "login", "")
    return {"token": token, "username": user["username"], "role": user["role"]}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("hg_token")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(auth.require_auth)):
    return {"username": user["username"], "role": user["role"]}
