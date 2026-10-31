import ipaddress

from .. import db as dbmod
from . import sshclient

CONFIG_PATH = "/etc/keepalived/keepalived.conf"


def get_cluster_config(cluster_id):
    cfg = dbmod.one("SELECT * FROM keepalived WHERE cluster_id = ?", (cluster_id,))
    if not cfg:
        cfg = {"cluster_id": cluster_id, "vip": "", "iface": "eth0", "vr_id": 51,
               "auth_pass": "", "track_haproxy": 0}
    nodes = dbmod.q(
        "SELECT n.id, n.name, n.host, n.is_local, k.state, k.priority, k.peer_ip"
        " FROM nodes n LEFT JOIN keepalived_nodes k ON k.node_id = n.id"
        " WHERE n.cluster_id = ? ORDER BY n.name",
        (cluster_id,),
    )
    for n in nodes:
        n["state"] = n["state"] or "BACKUP"
        n["priority"] = n["priority"] if n["priority"] is not None else 100
        n["peer_ip"] = n["peer_ip"] or ""
    return {"config": cfg, "nodes": nodes}


def save_cluster_config(cluster_id, cfg, nodes):
    dbmod.execute(
        "INSERT INTO keepalived (cluster_id, vip, iface, vr_id, auth_pass, track_haproxy)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(cluster_id) DO UPDATE SET vip=excluded.vip,"
        " iface=excluded.iface, vr_id=excluded.vr_id, auth_pass=excluded.auth_pass,"
        " track_haproxy=excluded.track_haproxy",
        (
            cluster_id,
            cfg.get("vip", ""),
            cfg.get("iface") or "eth0",
            int(cfg.get("vr_id") or 51),
            cfg.get("auth_pass", "")[:8],
            int(bool(cfg.get("track_haproxy"))),
        ),
    )
    for n in nodes:
        dbmod.execute(
            "INSERT INTO keepalived_nodes (node_id, state, priority, peer_ip)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(node_id) DO UPDATE SET state=excluded.state,"
            " priority=excluded.priority, peer_ip=excluded.peer_ip",
            (
                n["node_id"],
                n.get("state") or "BACKUP",
                int(n.get("priority") or 100),
                n.get("peer_ip", ""),
            ),
        )


def generate(cluster, node):
    """Erzeugt die keepalived.conf für einen Node."""
    data = get_cluster_config(cluster["id"])
    cfg = data["config"]
    if not cfg.get("vip"):
        raise ValueError("Keine virtuelle IP (VIP) konfiguriert")
    vips = [item.strip() for item in cfg["vip"].replace(",", "\n").splitlines() if item.strip()]
    vips_by_family = {4: [], 6: []}
    for vip in vips:
        interface = ipaddress.ip_interface(vip)
        vips_by_family[interface.version].append(vip)
    primary_family = 4 if vips_by_family[4] else 6
    primary_vips = vips_by_family[primary_family]
    excluded_vips = vips_by_family[6 if primary_family == 4 else 4]
    entry = next((n for n in data["nodes"] if n["id"] == node["id"]), None)
    state = entry["state"] if entry else "BACKUP"
    priority = entry["priority"] if entry else 100
    peers = [
        item["peer_ip"]
        for item in data["nodes"]
        if item["id"] != node["id"] and item["peer_ip"]
    ]
    name = "VI_" + "".join(c if c.isalnum() else "_" for c in cluster["name"])
    lines = []
    if cfg.get("track_haproxy"):
        lines += [
            "vrrp_script chk_haproxy {",
            '    script "pidof haproxy"',
            "    interval 2",
            "    fall 2",
            "    rise 1",
            "}",
            "",
        ]
    lines = [
        *lines,
        f"vrrp_instance {name} {{",
        f"    state {state}",
        f"    interface {cfg.get('iface') or 'eth0'}",
        f"    virtual_router_id {int(cfg.get('vr_id') or 51)}",
        f"    priority {int(priority)}",
        "    advert_int 1",
    ]
    if peers:
        lines += ["    unicast_peer {"]
        lines += [f"        {peer}" for peer in peers]
        lines += ["    }"]
    if cfg.get("track_haproxy"):
        lines += ["    track_script {", "        chk_haproxy", "    }"]
    if cfg.get("auth_pass") and primary_family == 4:
        lines += [
            "    authentication {",
            "        auth_type PASS",
            f"        auth_pass {cfg['auth_pass']}",
            "    }",
        ]
    lines += [
        "    virtual_ipaddress {",
        *(f"        {vip}" for vip in primary_vips),
        "    }",
    ]
    if excluded_vips:
        lines += [
            "    virtual_ipaddress_excluded {",
            *(f"        {vip}" for vip in excluded_vips),
            "    }",
        ]
    lines += ["}", ""]
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
