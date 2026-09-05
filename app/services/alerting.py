import asyncio
import smtplib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage

from .. import db as dbmod
from . import runtime as runtimesvc

DEFAULTS = {
    "enabled": 0,
    "webhook_url": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_pass": "",
    "smtp_from": "",
    "smtp_to": "",
    "alert_node_down": 1,
    "alert_cert_expiry": 1,
    "alert_deploy_fail": 1,
}


def get_settings():
    row = dbmod.one("SELECT * FROM alert_settings WHERE id = 1")
    if row:
        data = dict(DEFAULTS)
        data.update(row)
        return data
    return dict(DEFAULTS)


def save_settings(data):
    current = get_settings()
    if not data.get("smtp_pass"):
        data["smtp_pass"] = current.get("smtp_pass", "")
    dbmod.execute(
        "INSERT INTO alert_settings (id, enabled, webhook_url, smtp_host, smtp_port,"
        " smtp_user, smtp_pass, smtp_from, smtp_to, alert_node_down,"
        " alert_cert_expiry, alert_deploy_fail)"
        " VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,"
        " webhook_url=excluded.webhook_url, smtp_host=excluded.smtp_host,"
        " smtp_port=excluded.smtp_port, smtp_user=excluded.smtp_user,"
        " smtp_pass=excluded.smtp_pass, smtp_from=excluded.smtp_from,"
        " smtp_to=excluded.smtp_to, alert_node_down=excluded.alert_node_down,"
        " alert_cert_expiry=excluded.alert_cert_expiry,"
        " alert_deploy_fail=excluded.alert_deploy_fail",
        (
            int(bool(data.get("enabled"))),
            data.get("webhook_url", ""),
            data.get("smtp_host", ""),
            int(data.get("smtp_port") or 587),
            data.get("smtp_user", ""),
            data.get("smtp_pass", ""),
            data.get("smtp_from", ""),
            data.get("smtp_to", ""),
            int(bool(data.get("alert_node_down"))),
            int(bool(data.get("alert_cert_expiry"))),
            int(bool(data.get("alert_deploy_fail"))),
        ),
    )


def _state_get(key):
    row = dbmod.one("SELECT value FROM alert_state WHERE key = ?", (key,))
    return row["value"] if row else None


def _state_set(key, value):
    dbmod.execute(
        "INSERT INTO alert_state (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def send(message):
    """Sendet eine Benachrichtigung über alle konfigurierten Kanäle."""
    st = get_settings()
    if not st.get("enabled"):
        return ["Alerts sind deaktiviert"]
    errors = []
    if st.get("webhook_url"):
        try:
            payload = ('{"text": ' + _json_str(message) + "}").encode()
            req = urllib.request.Request(
                st["webhook_url"], data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            errors.append(f"Webhook: {exc}")
    if st.get("smtp_host") and st.get("smtp_to"):
        try:
            msg = EmailMessage()
            msg["Subject"] = "HAProxy-GUI Alert"
            msg["From"] = st.get("smtp_from") or st.get("smtp_user") or "haproxy-gui@local"
            msg["To"] = st["smtp_to"]
            msg.set_content(message)
            with smtplib.SMTP(st["smtp_host"], int(st.get("smtp_port") or 587), timeout=15) as smtp:
                smtp.ehlo()
                try:
                    smtp.starttls()
                except smtplib.SMTPException:
                    pass
                if st.get("smtp_user"):
                    smtp.login(st["smtp_user"], st.get("smtp_pass") or "")
                smtp.send_message(msg)
        except Exception as exc:
            errors.append(f"SMTP: {exc}")
    return errors


def _json_str(text):
    escaped = (
        text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    )
    return f'"{escaped}"'


def notify_deploy_failure(cluster, node, message):
    st = get_settings()
    if st.get("enabled") and st.get("alert_deploy_fail"):
        try:
            send(
                f"❌ Deploy fehlgeschlagen: {cluster['name']}/{node['name']}\n"
                f"{message[:400]}"
            )
        except Exception:
            pass


def _probe(node):
    try:
        runtimesvc.show_info(node)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _check_once():
    st = get_settings()
    if not st.get("enabled"):
        return
    nodes = dbmod.q(
        "SELECT n.*, c.name AS cluster_name FROM nodes n"
        " JOIN clusters c ON c.id = n.cluster_id"
    )
    if nodes:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_probe, nodes))
        for node, (ok, err) in zip(nodes, results):
            key = f"node_down:{node['id']}"
            was_down = _state_get(key) == "1"
            if not ok and not was_down:
                _state_set(key, "1")
                if st.get("alert_node_down"):
                    send(
                        f"🔴 Node OFFLINE: {node['cluster_name']}/{node['name']}"
                        f" ({node['host']})\n{err[:300]}"
                    )
            elif ok and was_down:
                _state_set(key, "0")
                if st.get("alert_node_down"):
                    send(
                        f"✅ Node wieder ONLINE: {node['cluster_name']}/{node['name']}"
                    )
    if st.get("alert_cert_expiry"):
        today = datetime.now(timezone.utc).date().isoformat()
        for cert in dbmod.q(
            "SELECT * FROM certificates WHERE status = 'active' AND not_after != ''"
        ):
            try:
                expiry = datetime.fromisoformat(cert["not_after"])
                days = (expiry - datetime.now(timezone.utc)).days
            except Exception:
                continue
            key = f"cert_warn:{cert['id']}:{today}"
            if days < 14 and _state_get(key) is None:
                _state_set(key, "1")
                send(
                    f"⚠️ Zertifikat '{cert['name']}' läuft in {days} Tagen ab "
                    f"({cert['not_after'][:10]})"
                )


async def alert_loop():
    """Prüft periodisch Node-Verfügbarkeit und Zertifikatslaufzeiten."""
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.to_thread(_check_once)
        except Exception:
            pass
        await asyncio.sleep(60)
