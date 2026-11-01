import json
import ipaddress

from .. import db as dbmod
from . import certmap
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
    fe_list = certmap.annotate_frontends(
        dbmod.q(
            "SELECT * FROM frontends WHERE cluster_id = ? ORDER BY port, name",
            (cluster["id"],),
        ),
        cluster["id"],
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
        bind_addr = node.get("socket_host") or (
            "127.0.0.1" if node.get("is_local") else node["host"]
        )
        try:
            family = ipaddress.ip_address(bind_addr).version
            prefix = f"ipv{family}@"
        except ValueError:
            prefix = ""
        lines.append(
            f"    stats socket {prefix}{bind_addr}:{node.get('socket_port') or 9999} level operator"
        )
    else:
        sock = (node or {}).get("socket_path") or "/var/run/haproxy/admin.sock"
        lines.append(f"    stats socket {sock} mode 660 level admin")
    lines.append("    stats timeout 30s")
    lines.append("    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets")
    # Zu NAME.crt den separat installierten Schlüssel NAME.key laden.
    lines.append("    ssl-load-extra-del-ext")
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
        bind_ip = v.clean_bind_ip(fe["bind_ip"], "bind_ip")
        bind_family = fe.get("bind_family") or "ipv4"
        if bind_family not in ("ipv4", "ipv6", "dual"):
            raise ValueError(f"Frontend '{fe['name']}': ungültige Bind-Familie")
        if bind_family == "dual" and bind_ip not in ("*", "::"):
            raise ValueError(
                f"Frontend '{fe['name']}': Dual-Stack-Binds benötigen '*'."
            )
        if bind_ip != "*":
            try:
                address_family = ipaddress.ip_address(bind_ip).version
            except ValueError:
                address_family = None
            if bind_family == "ipv4" and address_family == 6:
                raise ValueError(f"Frontend '{fe['name']}': IPv4-Bind mit IPv6-Adresse")
            if bind_family == "ipv6" and address_family == 4:
                raise ValueError(f"Frontend '{fe['name']}': IPv6-Bind mit IPv4-Adresse")
        lines.append(f"frontend {fe['name']}")
        bind_ips = (
            [("*", False), ("::", True)]
            if bind_family == "dual"
            else [("::" if bind_family == "ipv6" and bind_ip == "*" else bind_ip,
                   bind_family == "ipv6")]
        )
        cert_names = []
        if fe["use_ssl"]:
            # Eigene Zertifikate zuerst (das erste ist der Standard), dann die der Backends.
            cert_names = [
                v.clean_name(certs[cid]["name"], "Zertifikatsname")
                for cid in fe["effective_cert_ids"]
                if cid in certs
            ]
            if not cert_names:
                raise ValueError(
                    f"Frontend '{fe['name']}': kein Zertifikat zugeordnet"
                )
            if len(cert_names) > certmap.MAX_FRONTEND_CERTS:
                raise ValueError(
                    f"Frontend '{fe['name']}': {len(cert_names)} Zertifikate,"
                    f" maximal {certmap.MAX_FRONTEND_CERTS} möglich"
                )
        for address, ipv6 in bind_ips:
            bind = f"    bind {address}:{fe['port']}"
            if ipv6:
                bind += " v6only"
            if cert_names:
                bind += (
                    " ssl"
                    + "".join(f" crt {cert_dir}/{name}.crt" for name in cert_names)
                    + " alpn h2,http1.1"
                )
            lines.append(bind)
        lines.append(f"    mode {fe['mode']}")
        if fe.get("rate_limit_requests"):
            requests_per_window = int(fe["rate_limit_requests"])
            period = int(fe.get("rate_limit_period") or 10)
            if (
                fe["mode"] != "http"
                or not 1 <= requests_per_window <= 100000
                or not 1 <= period <= 3600
            ):
                raise ValueError(f"Frontend '{fe['name']}': ungültiges Rate-Limit")
            lines += [
                f"    stick-table type ip size 100k expire {max(30, period * 3)}s"
                f" store http_req_rate({period}s)",
                "    http-request track-sc0 src,ipmask(32,64)",
                "    http-request deny deny_status 429 if"
                f" {{ sc_http_req_rate(0) gt {requests_per_window} }}",
            ]
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
                verify_host = None
                if s.get("ssl_verify"):
                    verify_host = v.require_tls_hostname(
                        s["host"], f"Server '{s['name']}'"
                    )
                    parts += [
                        "verify required",
                        "ca-file @system-ca",
                        f"sni str({verify_host})",
                        f"verifyhost {verify_host}",
                    ]
                else:
                    parts.append("verify none")
                if s["check"]:
                    parts.append("check-ssl")
                    if verify_host:
                        parts.append(f"check-sni {verify_host}")
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
