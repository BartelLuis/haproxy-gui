import ipaddress
import os

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


def _trusted_proxy_networks():
    return [
        ipaddress.ip_network(item.strip(), strict=False)
        for item in os.environ.get("TRUSTED_PROXIES", "").split(",")
        if item.strip()
    ]


def _normalized_ip(value):
    ip = ipaddress.ip_address(value)
    return getattr(ip, "ipv4_mapped", None) or ip


def _is_trusted_proxy(ip):
    return any(ip in network for network in _trusted_proxy_networks())


def _client_ip(request):
    peer = request.client.host if request.client else "unknown"
    try:
        peer_ip = _normalized_ip(peer)
    except ValueError:
        return peer

    if not _is_trusted_proxy(peer_ip):
        return str(peer_ip)

    forwarded = request.headers.get("x-forwarded-for", "")
    try:
        chain = [ipaddress.ip_address(item.strip()) for item in forwarded.split(",")]
        if not chain:
            return str(peer_ip)
    except ValueError:
        return str(peer_ip)
    chain.append(peer_ip)
    for candidate in reversed(chain):
        candidate = getattr(candidate, "ipv4_mapped", None) or candidate
        if not _is_trusted_proxy(candidate):
            return str(candidate)
    return str(peer_ip)


def _request_is_secure(request):
    if request.url.scheme == "https":
        return True
    peer = request.client.host if request.client else ""
    try:
        peer_ip = _normalized_ip(peer)
    except ValueError:
        return False
    return (
        _is_trusted_proxy(peer_ip)
        and request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        == "https"
    )


def _rate_limit_key(client_ip, username):
    try:
        parsed_ip = _normalized_ip(client_ip)
        network = ipaddress.ip_network(
            f"{parsed_ip}/64" if parsed_ip.version == 6 else parsed_ip,
            strict=False,
        )
        client_ip = str(network)
    except ValueError:
        pass
    return f"{client_ip}|{username}"


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    client_ip = _client_ip(request)
    rate_key = _rate_limit_key(client_ip, body.username)
    ip = rate_key.rsplit("|", 1)[0]
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
    secure = _request_is_secure(request)
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
