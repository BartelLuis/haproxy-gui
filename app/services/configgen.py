import json

from .. import db as dbmod
from . import validate as v


def _indent_block(text, pad="    "):
    return "\n".join(
        pad + line if line.strip() else line for line in text.strip().splitlines()
    )


def _normalize_condition(cond):
    cond = cond.strip()
    if not cond:
        return ""
    if cond.startswith(("if ", "unless ", "{")):
        return cond
    return "if " + cond


def generate_config(cluster, node=None):
    fe_list = dbmod.q(
        "SELECT * FROM frontends WHERE cluster_id = ? ORDER BY port, name",
        (cluster["id"],),
    )
    be_list = dbmod.q(
        "SELECT * FROM backends WHERE cluster_id = ? ORDER BY name", (cluster["id"],)
    )
    certs = {c["id"]: c for c in dbmod.q("SELECT id, name FROM certificates")}
    backends_by_id = {b["id"]: b for b in be_list}
    cert_dir = (node or {}).get("cert_dir") or "/etc/haproxy/certs"

    lines = ["global"]
    lines.append("    log stdout format raw local0 info")
    lines.append("    maxconn 4096")
    if node and node.get("socket_type") == "tcp":
        # Niemals auf * binden – der Socket hat keine Authentifizierung.
        bind_addr = node.get("socket_host") or "127.0.0.1"
        lines.append(
            f"    stats socket ipv4@{bind_addr}:{node.get('socket_port') or 9999} level operator"
        )
    else:
        sock = (node or {}).get("socket_path") or "/var/run/haproxy/admin.sock"
        lines.append(f"    stats socket {sock} mode 660 level admin")
    lines.append("    stats timeout 30s")
    lines.append("    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets")
    if cluster.get("global_extra"):
        lines.append(_indent_block(cluster["global_extra"]))
    lines.append("")

    lines.append("defaults")
    lines.append("    log global")
    lines.append("    mode http")
    lines.append("    option httplog")
    lines.append("    option dontlognull")
    lines.append("    option redispatch")
    lines.append("    retries 3")
    lines.append("    timeout connect 5s")
    lines.append("    timeout client 30s")
    lines.append("    timeout server 30s")
    lines.append("    timeout http-request 10s")
    if cluster.get("defaults_extra"):
        lines.append(_indent_block(cluster["defaults_extra"]))
    lines.append("")

    for fe in fe_list:
        v.clean_name(fe["name"], "Frontend-Name")
        v.no_newline(fe["bind_ip"], "bind_ip")
        lines.append(f"frontend {fe['name']}")
        bind = f"    bind {fe['bind_ip']}:{fe['port']}"
        if fe["use_ssl"]:
            cert = certs.get(fe["cert_id"])
            if not cert:
                raise ValueError(
                    f"Frontend '{fe['name']}': kein Zertifikat zugeordnet"
                )
            bind += (
                f" ssl crt {cert_dir}/{cert['name']}.crt"
                f" ssl-key-file {cert_dir}/{cert['name']}.key"
                " alpn h2,http1.1"
            )
        lines.append(bind)
        lines.append(f"    mode {fe['mode']}")
        if fe["ssl_redirect"] and fe["use_ssl"] and fe["mode"] == "http":
            lines.append(
                "    http-request redirect scheme https code 301 unless { ssl_fc }"
            )
        for acl in json.loads(fe["acls"] or "[]"):
            if acl.get("name") and acl.get("criterion"):
                lines.append(f"    acl {acl['name']} {acl['criterion']} {acl.get('value', '')}".rstrip())
        for rule in json.loads(fe["rules"] or "[]"):
            cond = _normalize_condition(rule.get("condition") or "")
            if cond and rule.get("backend"):
                lines.append(f"    use_backend {rule['backend']} {cond}")
        if fe.get("default_backend_id") in backends_by_id:
            lines.append(
                f"    default_backend {backends_by_id[fe['default_backend_id']]['name']}"
            )
        if fe.get("extra"):
            lines.append(_indent_block(fe["extra"]))
        lines.append("")

    for be in be_list:
        v.clean_name(be["name"], "Backend-Name")
        lines.append(f"backend {be['name']}")
        lines.append(f"    mode {be['mode']}")
        lines.append(f"    balance {be['balance']}")
        if be.get("check_path") and be["mode"] == "http":
            v.no_newline(be["check_path"], "check_path")
            lines.append(f"    option httpchk GET {be['check_path']}")
            if be.get("check_expect"):
                v.no_newline(be["check_expect"], "check_expect")
                lines.append(f"    http-check expect {be['check_expect']}")
        for s in dbmod.q(
            "SELECT * FROM servers WHERE backend_id = ? ORDER BY name", (be["id"],)
        ):
            v.clean_name(s["name"], "Server-Name")
            v.clean_host(s["host"], "Server-Host")
            parts = ["    server", s["name"], f"{s['host']}:{s['port']}"]
            if s["check"]:
                parts.append("check")
            if s["ssl"]:
                parts.append("ssl")
                if s["check"]:
                    parts.append("check-ssl")
            if s["weight"] and s["weight"] != 100:
                parts.append(f"weight {s['weight']}")
            if s["maxconn"]:
                parts.append(f"maxconn {s['maxconn']}")
            if s["backup"]:
                parts.append("backup")
            lines.append(" ".join(parts))
        if be.get("extra"):
            lines.append(_indent_block(be["extra"]))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
