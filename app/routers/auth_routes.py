from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .. import auth
from ..db import audit
from ..services import ldapsvc

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str
    totp: str = ""


def _client_ip(request):
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    ip = _client_ip(request)
    rate_key = f"{ip}|{body.username}"
    if not auth.login_rate_check(rate_key):
        audit(body.username, "login.locked", f"IP {ip}")
        raise HTTPException(429, "Zu viele Fehlversuche – bitte kurz warten")

    user = auth.check_credentials(body.username, body.password)
    if not user:
        ldap_user = ldapsvc.authenticate(body.username, body.password)
        if ldap_user:
            user = {"id": -1, **ldap_user}

    if not user:
        auth.login_failed(rate_key)
        audit(body.username, "login.failed", f"IP {ip}")
        raise HTTPException(status_code=401, detail="Ungültige Zugangsdaten")

    # MFA: TOTP erforderlich, wenn für den Benutzer aktiviert
    if user.get("id", 0) > 0:
        from ..services import totp as totpsvc
        if totpsvc.is_enabled(user["id"]):
            if not body.totp:
                return {"mfa_required": True}
            if not totpsvc.verify(user["id"], body.totp):
                auth.login_failed(rate_key)
                audit(body.username, "login.mfa_failed", f"IP {ip}")
                raise HTTPException(401, "Ungültiger MFA-Code")

    auth.login_succeeded(rate_key)
    token = auth.create_token(user)
    # Secure-Flag nur über HTTPS sinnvoll; bei lokalem HTTP würde der Browser es ablehnen.
    secure = request.url.scheme == "https"
    response.set_cookie(
        "hg_token", token, httponly=True, samesite="lax",
        secure=secure, max_age=auth.TOKEN_TTL,
    )
    audit(user["username"], "login", f"IP {ip}")
    return {"token": token, "username": user["username"], "role": user["role"],
            "mfa_required": False}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("hg_token")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(auth.require_auth)):
    return {"username": user["username"], "role": user["role"]}
