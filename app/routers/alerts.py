from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth
from ..db import audit
from ..services import alerting

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertSettingsIn(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    alert_node_down: bool = True
    alert_cert_expiry: bool = True
    alert_deploy_fail: bool = True


@router.get("/settings")
def get_settings(user=Depends(auth.require_role("admin"))):
    st = alerting.get_settings()
    st["smtp_pass"] = "***" if st.get("smtp_pass") else ""
    return st


@router.put("/settings")
def put_settings(body: AlertSettingsIn, user=Depends(auth.require_role("admin"))):
    data = body.model_dump()
    if data.get("smtp_pass") == "***":
        data["smtp_pass"] = ""
    alerting.save_settings(data)
    audit(user["username"], "alerts.settings", "")
    return {"ok": True}


@router.post("/test")
def test_alert(user=Depends(auth.require_role("admin"))):
    errors = alerting.send("Test-Alarm von HAProxy-GUI ✅")
    return {"ok": not errors, "errors": errors}
