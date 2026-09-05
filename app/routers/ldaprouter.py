from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth
from ..db import audit
from ..services import ldapsvc

router = APIRouter(prefix="/api/ldap", tags=["ldap"])


class LdapSettingsIn(BaseModel):
    enabled: bool = False
    server_uri: str = "ldap://localhost:389"
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(&(objectClass=person)(uid={username}))"
    use_tls: bool = False
    group_admin: str = ""
    group_operator: str = ""
    default_role: str = "viewer"


@router.get("/settings")
def get_settings(user=Depends(auth.require_role("admin"))):
    st = ldapsvc.get_settings()
    st["bind_password"] = "***" if st.get("bind_password") else ""
    return st


@router.put("/settings")
def put_settings(body: LdapSettingsIn, user=Depends(auth.require_role("admin"))):
    data = body.model_dump()
    if data.get("bind_password") == "***":
        data["bind_password"] = ""
    ldapsvc.save_settings(data)
    audit(user["username"], "ldap.settings", "")
    return {"ok": True}


@router.post("/test")
def test_ldap(user=Depends(auth.require_role("admin"))):
    ok, message = ldapsvc.test_connection()
    return {"ok": ok, "message": message}
