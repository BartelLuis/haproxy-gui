import asyncio
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
        "label": "Hetzner DNS",
        "env": [("HETZNER_API_KEY", "API-Key")],
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
}


def providers_public():
    return {k: {"label": v["label"], "env": v["env"]} for k, v in PROVIDERS.items()}


def _base(cert):
    domains = json.loads(cert["domains"])
    return domains[0].replace("*.", "_.")


def cert_paths(cert):
    base = _base(cert)
    return (
        os.path.join(ACME_DIR, "certificates", base + ".crt"),
        os.path.join(ACME_DIR, "certificates", base + ".key"),
    )


def pem_bytes(cert):
    """Kombiniertes PEM (Zertifikat + Chain + Key), wie HAProxy es erwartet."""
    crt, key = cert_paths(cert)
    if not (os.path.exists(crt) and os.path.exists(key)):
        return None
    with open(crt, "rb") as f:
        c = f.read()
    with open(key, "rb") as f:
        k = f.read()
    if not c.endswith(b"\n"):
        c += b"\n"
    return c + k


def cluster_cert_files(cluster_id):
    """Alle Zertifikate, die von SSL-Frontends des Clusters referenziert werden."""
    rows = dbmod.q(
        "SELECT DISTINCT c.* FROM certificates c"
        " JOIN frontends f ON f.cert_id = c.id"
        " WHERE f.cluster_id = ? AND f.use_ssl = 1",
        (cluster_id,),
    )
    files, warnings = {}, []
    for cert in rows:
        pem = pem_bytes(cert)
        if pem:
            files[cert["name"] + ".pem"] = pem
        else:
            warnings.append(
                f"Zertifikat '{cert['name']}' ist noch nicht ausgestellt"
            )
    return files, warnings


def remove_cert_files(cert):
    crt, key = cert_paths(cert)
    for suffix in (".crt", ".key", ".issuer.crt", ".json"):
        path = os.path.join(ACME_DIR, "certificates", _base(cert) + suffix)
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


def issue(cert_id, renew=False):
    """Ausstellung/Erneuerung via lego (blockierend – in Thread ausführen)."""
    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not cert:
        return
    _set(cert_id, status="issuing", message="")
    domains = json.loads(cert["domains"])
    cmd = [
        "lego",
        "--accept-tos",
        "--path", ACME_DIR,
        "--email", cert["email"] or "admin@example.com",
        "--dns", cert["dns_provider"],
    ]
    for d in domains:
        cmd += ["--domains", d]
    crt, _ = cert_paths(cert)
    cmd.append("renew" if renew and os.path.exists(crt) else "run")
    env = dict(os.environ)
    env.update(
        {
            k: v
            for k, v in json.loads(cert["provider_config"] or "{}").items()
            if v
        }
    )
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
    """Schreibt das PEM auf alle Nodes der Cluster, die das Zertifikat nutzen."""
    from . import deploy as deploysvc
    from . import sshclient

    cert = dbmod.one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not cert:
        return []
    pem = pem_bytes(cert)
    if not pem:
        return [
            {
                "node": "-",
                "ok": False,
                "error": "Zertifikat ist noch nicht ausgestellt",
                "log": [],
            }
        ]
    fname = cert["name"] + ".pem"
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
                target = node["cert_dir"].rstrip("/") + "/" + fname
                if node.get("is_local"):
                    os.makedirs(node["cert_dir"], exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(pem)
                    os.chmod(target, 0o600)
                else:
                    sshclient.run_ssh(node, f"mkdir -p {node['cert_dir']}")
                    sshclient.sftp_write(node, target, pem, mode=0o600)
                log.append(f"Zertifikat nach {target} geschrieben")
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
