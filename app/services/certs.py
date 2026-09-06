import asyncio
import glob
import json
import os
import subprocess
import threading
from datetime import datetime, timezone

from cryptography import x509

from .. import db as dbmod

ACME_DIR = os.path.join(os.environ.get("HG_DATA", "/data"), "acme")

# Kuratierte Liste von lego-DNS-Providern: env = [(ENV_VAR, Beschreibung), ...]
PROVIDERS = {
    "cloudflare": {
        "label": "Cloudflare",
        "env": [("CLOUDFLARE_DNS_API_TOKEN", "API-Token (Zone DNS Edit)")],
    },
    "route53": {
        "label": "AWS Route53",
        "env": [
            ("AWS_ACCESS_KEY_ID", "Access Key ID"),
            ("AWS_SECRET_ACCESS_KEY", "Secret Access Key"),
            ("AWS_REGION", "Region (optional)"),
        ],
    },
    "digitalocean": {
        "label": "DigitalOcean",
        "env": [("DO_AUTH_TOKEN", "API-Token")],
    },
    "hetzner": {
        "label": "Hetzner Cloud",
        "env": [("HETZNER_API_TOKEN", "API-Token (Cloud-Konsole → Security → API)")],
    },
    "azure": {
        "label": "Azure DNS",
        "env": [
            ("AZURE_CLIENT_ID", "Client ID"),
            ("AZURE_CLIENT_SECRET", "Client Secret"),
            ("AZURE_TENANT_ID", "Tenant ID"),
            ("AZURE_SUBSCRIPTION_ID", "Subscription ID"),
            ("AZURE_RESOURCE_GROUP", "Resource Group"),
        ],
    },
    "duckdns": {
        "label": "DuckDNS",
        "env": [("DUCKDNS_TOKEN", "Token")],
    },
    "desec": {
        "label": "deSEC",
        "env": [("DESEC_TOKEN", "Token")],
    },
    "ionos": {
        "label": "IONOS DNS",
        "env": [("IONOS_API_KEY", "API-Key (prefix.public)")],
    },
    "netcup": {
        "label": "netcup",
        "env": [
            ("NETCUP_CUSTOMER_NUMBER", "Kundennummer"),
            ("NETCUP_API_KEY", "API-Key"),
            ("NETCUP_API_PASSWORD", "API-Passwort"),
        ],
    },
    "ovh": {
        "label": "OVH",
        "env": [
            ("OVH_ENDPOINT", "Endpoint (z. B. ovh-eu)"),
            ("OVH_APPLICATION_KEY", "Application Key"),
            ("OVH_APPLICATION_SECRET", "Application Secret"),
            ("OVH_CONSUMER_KEY", "Consumer Key"),
        ],
    },
    "technitium": {
        "label": "Technitium DNS",
        "env": [
            ("TECHNITIUM_SERVER", "Server-URL (z. B. http://192.168.1.10:5380)"),
            ("TECHNITIUM_TOKEN", "API-Token (aus der Technitium-Web-GUI)"),
        ],
    },
    "manual": {
        "label": "Manuelles DNS (TXT selbst anlegen)",
        "env": [],
    },
}


def providers_public():
    return {k: {"label": v["label"], "env": v["env"]} for k, v in PROVIDERS.items()}


def _base(cert):
    domains = json.loads(cert["domains"])
    return domains[0].replace("*.", "_.")


def _safe_path(base_dir, filename):
    """Verhindert Path-Traversal: Ergebnis muss innerhalb von base_dir liegen."""
    full = os.path.realpath(os.path.join(base_dir, filename))
    if not full.startswith(os.path.realpath(base_dir) + os.sep):
        raise ValueError(f"Ungültiger Dateiname: {filename!r}")
    return full


def cert_paths(cert):
    base = _base(cert)
    cert_dir = os.path.join(ACME_DIR, "certificates")
    return (
        _safe_path(cert_dir, base + ".crt"),
        _safe_path(cert_dir, base + ".key"),
    )


def pem_bytes(cert):
    """Zertifikatsbundle ohne Key: Leaf + Intermediate/Chain, wie HAProxy für crt erwartet."""
    cert_dir = os.path.join(ACME_DIR, "certificates")
    base = _base(cert)
    name = (cert.get("name") or "").strip()
    candidates = []
    for prefix in [base, name, name.rsplit(".pem", 1)[0] if name.endswith(".pem") else name]:
        if not prefix:
            continue
        candidates.extend(
            [
                os.path.join(cert_dir, prefix + ".crt"),
                os.path.join(cert_dir, prefix + ".issuer.crt"),
                os.path.join(cert_dir, prefix + ".chain.crt"),
            ]
        )
    candidates.extend(glob.glob(os.path.join(cert_dir, base + "*.crt")))
    seen = set()
    cert_files = []
    for path in candidates:
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        with open(path, "rb") as f:
            data = f.read()
        if b"BEGIN CERTIFICATE" in data:
            cert_files.append(path)
    if not cert_files:
        return None

    bundle = []
    for path in sorted(cert_files):
        with open(path, "rb") as f:
            data = f.read().strip()
        if data:
            bundle.append(data + b"\n")
    return b"".join(bundle)


def key_bytes(cert):
    """Privater Schlüssel für das Zertifikat; separat auf dem Zielhost installieren."""
    cert_dir = os.path.join(ACME_DIR, "certificates")
    base = _base(cert)
    name = (cert.get("name") or "").strip()
    for prefix in [base, name, name.rsplit(".pem", 1)[0] if name.endswith(".pem") else name]:
        if not prefix:
            continue
        for suffix in (".key", ".private.key"):
            path = os.path.join(cert_dir, prefix + suffix)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read().strip()
                if data:
                    return data + b"\n"
    return None


def cluster_cert_files(cluster_id):
    """Alle Zertifikate und Keys, die von SSL-Frontends des Clusters referenziert werden."""
    rows = dbmod.q(
        "SELECT DISTINCT c.* FROM certificates c"
        " JOIN frontends f ON f.cert_id = c.id"
        " WHERE f.cluster_id = ? AND f.use_ssl = 1",
        (cluster_id,),
    )
    files, warnings = {}, []
    for cert in rows:
        crt = pem_bytes(cert)
        k = key_bytes(cert)
        if crt and k:
            files[cert["name"] + ".crt"] = crt
            files[cert["name"] + ".key"] = k
        else:
            warnings.append(
                f"Zertifikat '{cert['name']}' ist noch nicht ausgestellt"
            )
    return files, warnings


def remove_cert_files(cert):
    cert_dir = os.path.join(ACME_DIR, "certificates")
    for suffix in (".crt", ".key", ".issuer.crt", ".json"):
        path = _safe_path(cert_dir, _base(cert) + suffix)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _set(cert_id, **fields):
    cols = ", ".join(f"{k} = ?" for k in fields)
    dbmod.execute(
        f"UPDATE certificates SET {cols} WHERE id = ?", (*fields.values(), cert_id)
    )


# ---------------------------------------------------------------------------
# Technitium DNS (via lego webhook-Provider)
# ---------------------------------------------------------------------------

TECHNITIUM_HOOK = r"""#!/bin/sh
# lego webhook-Hook für Technitium DNS Server
# Erwartet LEGO_VALIDATION_DOMAIN (FQDN) und LEGO_VALIDATION_VALUE (TXT-Wert)
API="$TECHNITIUM_SERVER/api/dns"
TOKEN="$TECHNITIUM_TOKEN"

# Zonennamen aus FQDN ableiten: längste bekannte Zone finden,
# Fallback: letzte beiden Labels (example.com)
FQDN="${LEGO_VALIDATION_DOMAIN#.}"
ZONE=$(printf '%s' "$FQDN" | awk -F. '{print $(NF-1)"."$NF}')
RECORD=$(printf '%s' "$FQDN" | sed "s/\.$ZONE$//")

if [ "$LEGO_MODE" = "present" ]; then
  curl -sf "$API/zones/records/add?token=$TOKEN&zone=$ZONE&domain=$FQDN&type=TXT&ttl=60&text=$LEGO_VALIDATION_VALUE" || true
else
  curl -sf "$API/zones/records/delete?token=$TOKEN&zone=$ZONE&domain=$FQDN&type=TXT&text=$LEGO_VALIDATION_VALUE" || true
fi
sleep 10
"""


def _write_technitium_hook():
    os.makedirs(ACME_DIR, exist_ok=True)
    path = os.path.join(ACME_DIR, "technitium_hook.sh")
    with open(path, "w", newline="\n") as f:
        f.write(TECHNITIUM_HOOK)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _technitium_env(cfg):
    server = (cfg.get("TECHNITIUM_SERVER") or "").rstrip("/")
    token = cfg.get("TECHNITIUM_TOKEN") or ""
    if not server or not token:
        raise ValueError("Technitium: TECHNITIUM_SERVER und TECHNITIUM_TOKEN erforderlich")
    hook = _write_technitium_hook()
    return {
        "TECHNITIUM_SERVER": server,
        "TECHNITIUM_TOKEN": token,
        "EXEC_PATH": hook,
        "EXEC_MODE": "",
        "EXEC_PROPAGATION_TIMEOUT": "300",
        "EXEC_POLLING_INTERVAL": "5",
    }


# ---------------------------------------------------------------------------
# Manuelles DNS (TXT-Record wird angezeigt, Benutzer legt ihn selbst an)
# ---------------------------------------------------------------------------

MANUAL_HOOK_PRESENT = r"""#!/bin/sh
# Schreibt die benötigten TXT-Records in eine Datei und wartet auf Bestätigung.
CONF_FILE="$LEGO_MANUAL_CONFIRM_FILE"
RECORDS_FILE="$LEGO_MANUAL_RECORDS_FILE"
printf '%s %s\n' "$LEGO_VALIDATION_DOMAIN" "$LEGO_VALIDATION_VALUE" >> "$RECORDS_FILE"
# Warten, bis der Benutzer die Bestätigungsdatei angelegt hat (max 20 min)
i=0
while [ ! -f "$CONF_FILE" ] && [ $i -lt 1200 ]; do
  sleep 1
  i=$((i+1))
done
exit 0
"""

MANUAL_HOOK_CLEANUP = "#!/bin/sh\nexit 0\n"


def _write_manual_hooks():
    os.makedirs(ACME_DIR, exist_ok=True)
    present = os.path.join(ACME_DIR, "manual_present.sh")
    cleanup = os.path.join(ACME_DIR, "manual_cleanup.sh")
    for path, content in ((present, MANUAL_HOOK_PRESENT), (cleanup, MANUAL_HOOK_CLEANUP)):
        with open(path, "w", newline="\n") as f:
            f.write(content)
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
    return present, cleanup


def _manual_paths(cert):
    os.makedirs(ACME_DIR, exist_ok=True)
    return (
        os.path.join(ACME_DIR, f"manual_{cert['id']}.records"),
        os.path.join(ACME_DIR, f"manual_{cert['id']}.confirm"),
    )


def get_pending_challenge(cert):
    """Liest die aktuell zu setzenden TXT-Records einer laufenden manuellen Challenge."""
    records_file, confirm_file = _manual_paths(cert)
    if os.path.exists(confirm_file) or not os.path.exists(records_file):
        return None
    records = []
    with open(records_file) as f:
        for line in f:
            parts = line.split(None, 1)
            if len(parts) == 2:
                records.append({"domain": parts[0].strip(), "value": parts[1].strip()})
    return records or None


def confirm_manual(cert_id):
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not cert or cert["dns_provider"] != "manual":
        return False, "Kein manuelles Zertifikat"
    _, confirm_file = _manual_paths(cert)
    with open(confirm_file, "w") as f:
        f.write("ok\n")
    return True, "Bestätigt – Ausstellung läuft weiter"


def _cleanup_manual(cert):
    for p in _manual_paths(cert):
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def _issue_manual(cert, renew):
    cert_id = cert["id"]
    _cleanup_manual(cert)
    _set(cert_id, status="waiting_dns", message="")
    present, cleanup = _write_manual_hooks()
    records_file, confirm_file = _manual_paths(cert)
    open(records_file, "w").close()
    domains = json.loads(cert["domains"])
    crt, _ = cert_paths(cert)
    cmd = [
        "lego", "--accept-tos",
        "--path", ACME_DIR,
        "--email", cert["email"] or "admin@example.com",
        "--dns", "manual",
    ]
    for d in domains:
        cmd += ["--domains", d]
    cmd.append("renew" if renew and os.path.exists(crt) else "run")
    env = dict(os.environ)
    env["LEGO_MANUAL_CONFIRM_FILE"] = confirm_file
    env["LEGO_MANUAL_RECORDS_FILE"] = records_file
    # lego manual ruft kein Skript auf – wir lesen die Challenge aus dem Log.
    # Daher: --dns.exec-Modus mit unseren Hooks.
    cmd = [c if c != "manual" else "exec" for c in cmd]
    env["EXEC_PATH"] = present
    env["EXEC_CLEANUP_PATH"] = cleanup
    env["EXEC_MODE"] = ""
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env,
        )
    except FileNotFoundError:
        _set(cert_id, status="error", message="lego-Binary nicht gefunden")
        _cleanup_manual(cert)
        return
    try:
        proc.wait(timeout=1300)
    except subprocess.TimeoutExpired:
        proc.kill()
        _set(cert_id, status="error",
             message="Zeitüberschreitung – TXT-Record wurde nicht bestätigt")
        _cleanup_manual(cert)
        return
    if proc.returncode != 0:
        _set(cert_id, status="error", message="lego fehlgeschlagen (manuell)")
        _cleanup_manual(cert)
        return
    not_after = ""
    try:
        with open(crt, "rb") as f:
            x509cert = x509.load_pem_x509_certificate(f.read())
        not_after = x509cert.not_valid_after_utc.isoformat()
    except Exception:
        pass
    _cleanup_manual(cert)
    _set(cert_id, status="active", message="", not_after=not_after)
    deploy_cert(cert_id)


def issue(cert_id, renew=False):
    """Ausstellung/Erneuerung via lego (blockierend – in Thread ausführen)."""
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not cert:
        return
    provider = cert["dns_provider"]
    domains = json.loads(cert["domains"])

    if provider == "manual":
        _issue_manual(cert, renew)
        return

    _set(cert_id, status="issuing", message="")
    cfg = json.loads(cert["provider_config"] or "{}")
    cmd = [
        "lego",
        "--accept-tos",
        "--path", ACME_DIR,
        "--email", cert["email"] or "admin@example.com",
    ]
    env = dict(os.environ)
    try:
        if provider == "technitium":
            cmd += ["--dns", "exec"]
            env.update(_technitium_env(cfg))
        else:
            cmd += ["--dns", provider]
            # Nur die für diesen Provider deklarierten Env-Keys durchreichen
            allowed = {k for k, _ in PROVIDERS.get(provider, {}).get("env", [])}
            env.update({k: v for k, v in cfg.items() if v and k in allowed})
    except ValueError as exc:
        _set(cert_id, status="error", message=str(exc))
        return
    for d in domains:
        cmd += ["--domains", d]
    crt, _ = cert_paths(cert)
    cmd.append("renew" if renew and os.path.exists(crt) else "run")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=900, env=env
        )
    except FileNotFoundError:
        _set(cert_id, status="error", message="lego-Binary nicht gefunden")
        return
    except subprocess.TimeoutExpired:
        _set(cert_id, status="error", message="Zeitüberschreitung bei der Ausstellung")
        return
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-1500:].strip()
        _set(cert_id, status="error", message=tail or "lego fehlgeschlagen")
        return
    not_after = ""
    try:
        with open(crt, "rb") as f:
            x509cert = x509.load_pem_x509_certificate(f.read())
        not_after = x509cert.not_valid_after_utc.isoformat()
    except Exception:
        pass
    _set(cert_id, status="active", message="", not_after=not_after)
    deploy_cert(cert_id)


def deploy_cert(cert_id):
    """Verteilt Zertifikat und Schlüssel auf alle Nodes der zugehörigen Cluster."""
    from . import deploy as deploysvc

    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not cert:
        return []
    pem = pem_bytes(cert)
    key = key_bytes(cert)
    if not pem or not key:
        return [
            {
                "node": "-",
                "ok": False,
                "error": "Zertifikat ist noch nicht ausgestellt",
                "log": [],
            }
        ]
    cert_name = cert["name"]
    cert_file = cert_name + ".crt"
    key_file = cert_name + ".key"
    clusters = dbmod.q(
        "SELECT DISTINCT cl.* FROM clusters cl"
        " JOIN frontends f ON f.cluster_id = cl.id"
        " WHERE f.cert_id = ? AND f.use_ssl = 1",
        (cert_id,),
    )
    if not clusters:
        return [
            {
                "node": "-",
                "ok": True,
                "error": "",
                "log": ["Zertifikat wird von keinem SSL-Frontend genutzt – nichts zu tun."],
            }
        ]
    results = []
    for cluster in clusters:
        for node in dbmod.q(
            "SELECT * FROM nodes WHERE cluster_id = ?", (cluster["id"],)
        ):
            log = []
            try:
                cert_target = node["cert_dir"].rstrip("/") + "/" + cert_file
                key_target = node["cert_dir"].rstrip("/") + "/" + key_file
                deploysvc.install_cert_files(node, {cert_file: pem, key_file: key})
                log.append(
                    f"Zertifikat nach {cert_target} ({len(pem)} Bytes) und Schlüssel nach "
                    f"{key_target} ({len(key)} Bytes) übertragen und geprüft"
                )
                ok, msg = deploysvc.reload_node(node)
                log.append(msg)
                results.append(
                    {
                        "node": node["name"],
                        "ok": ok,
                        "error": "" if ok else msg,
                        "log": log,
                    }
                )
            except Exception as exc:
                results.append(
                    {"node": node["name"], "ok": False, "error": str(exc), "log": log}
                )
    return results


def issue_background(cert_id, renew=False):
    threading.Thread(target=issue, args=(cert_id, renew), daemon=True).start()


async def renewal_loop():
    """Prüft periodisch auf auslaufende Zertifikate und erneuert sie."""
    await asyncio.sleep(30)
    while True:
        try:
            certs = dbmod.q(
                "SELECT * FROM certificates WHERE auto_renew = 1 AND status = 'active'"
                " AND dns_provider != 'manual'"
            )
            for cert in certs:
                try:
                    if not cert.get("not_after"):
                        continue
                    expiry = datetime.fromisoformat(cert["not_after"])
                    if (expiry - datetime.now(timezone.utc)).days < 30:
                        await asyncio.to_thread(issue, cert["id"], True)
                except Exception:
                    continue
        except Exception:
            pass
        await asyncio.sleep(6 * 3600)
