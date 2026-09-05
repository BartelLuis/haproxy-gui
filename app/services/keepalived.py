from .. import db as dbmod
from . import sshclient

CONFIG_PATH = "/etc/keepalived/keepalived.conf"


def get_cluster_config(cluster_id):
    cfg = dbmod.one("SELECT * FROM keepalived WHERE cluster_id = ?", (cluster_id,))
    if not cfg:
        cfg = {"cluster_id": cluster_id, "vip": "", "iface": "eth0", "vr_id": 51,
               "auth_pass": ""}
    nodes = dbmod.q(
        "SELECT n.id, n.name, n.host, n.is_local, k.state, k.priority"
        " FROM nodes n LEFT JOIN keepalived_nodes k ON k.node_id = n.id"
        " WHERE n.cluster_id = ? ORDER BY n.name",
        (cluster_id,),
    )
    for n in nodes:
        n["state"] = n["state"] or "BACKUP"
        n["priority"] = n["priority"] if n["priority"] is not None else 100
    return {"config": cfg, "nodes": nodes}


def save_cluster_config(cluster_id, cfg, nodes):
    dbmod.execute(
        "INSERT INTO keepalived (cluster_id, vip, iface, vr_id, auth_pass)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(cluster_id) DO UPDATE SET vip=excluded.vip,"
        " iface=excluded.iface, vr_id=excluded.vr_id, auth_pass=excluded.auth_pass",
        (
            cluster_id,
            cfg.get("vip", ""),
            cfg.get("iface") or "eth0",
            int(cfg.get("vr_id") or 51),
            cfg.get("auth_pass", "")[:8],
        ),
    )
    for n in nodes:
        dbmod.execute(
            "INSERT INTO keepalived_nodes (node_id, state, priority) VALUES (?, ?, ?)"
            " ON CONFLICT(node_id) DO UPDATE SET state=excluded.state,"
            " priority=excluded.priority",
            (n["node_id"], n.get("state") or "BACKUP", int(n.get("priority") or 100)),
        )


def generate(cluster, node):
    """Erzeugt die keepalived.conf für einen Node."""
    data = get_cluster_config(cluster["id"])
    cfg = data["config"]
    if not cfg.get("vip"):
        raise ValueError("Keine virtuelle IP (VIP) konfiguriert")
    entry = next((n for n in data["nodes"] if n["id"] == node["id"]), None)
    state = entry["state"] if entry else "BACKUP"
    priority = entry["priority"] if entry else 100
    name = "VI_" + "".join(c if c.isalnum() else "_" for c in cluster["name"])
    lines = [
        f"vrrp_instance {name} {{",
        f"    state {state}",
        f"    interface {cfg.get('iface') or 'eth0'}",
        f"    virtual_router_id {int(cfg.get('vr_id') or 51)}",
        f"    priority {int(priority)}",
        "    advert_int 1",
    ]
    if cfg.get("auth_pass"):
        lines += [
            "    authentication {",
            "        auth_type PASS",
            f"        auth_pass {cfg['auth_pass']}",
            "    }",
        ]
    lines += [
        "    virtual_ipaddress {",
        f"        {cfg['vip']}",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def deploy_node(cluster, node):
    """Schreibt die keepalived.conf auf einen Remote-Node und lädt den Dienst neu."""
    if node.get("is_local"):
        return {
            "node": node["name"],
            "ok": False,
            "error": "Keepalived auf dem lokalen Container-Node wird nicht unterstützt",
        }
    cfg_text = generate(cluster, node)
    log = []
    try:
        sshclient.run_ssh(node, "mkdir -p /etc/keepalived")
        sshclient.sftp_write(node, CONFIG_PATH, cfg_text.encode())
        log.append(f"Konfiguration nach {CONFIG_PATH} geschrieben")
        rc, out, err = sshclient.run_ssh(
            node,
            "systemctl reload keepalived 2>/dev/null || systemctl restart keepalived",
        )
        text = (out + err).strip()
        log.append(text or "keepalived neu geladen")
        ok = rc == 0
        return {"node": node["name"], "ok": ok,
                "error": "" if ok else text or "Reload fehlgeschlagen", "log": log}
    except Exception as exc:
        return {"node": node["name"], "ok": False, "error": str(exc), "log": log}


def node_status(node):
    if node.get("is_local"):
        return {"node": node["name"], "status": "n/a (lokaler Container)"}
    rc, out, err = sshclient.run_ssh(
        node, "systemctl is-active keepalived 2>&1; true", timeout=15
    )
    return {"node": node["name"], "status": (out or err).strip() or "unbekannt"}
