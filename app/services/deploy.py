import os
import signal
import subprocess

from .. import db as dbmod
from . import alerting, certs as certsvc
from . import runtime, sshclient
from .configgen import generate_config

MASTER_PID = "/run/haproxy/master.pid"


def _local(cmd, timeout=60):
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def reload_node(node):
    if node.get("is_local"):
        with open(MASTER_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGUSR2)
        return True, "Reload via SIGUSR2 (master-worker)"
    cmd = (node.get("reload_cmd") or "").strip()
    if cmd == "sigusr2":
        cmd = "kill -USR2 $(cat /run/haproxy/master.pid)"
    if not cmd:
        cmd = (
            "systemctl reload haproxy 2>/dev/null || "
            f"haproxy -D -f {node['config_path']} -sf $(pidof haproxy)"
        )
    rc, out, err = sshclient.run_ssh(node, cmd)
    text = (out + err).strip()
    return rc == 0, text or "Reload ausgeführt"


def deploy_node(cluster, node, validate_only=False, content=None,
                user="system", note=""):
    log = []

    def fail(msg):
        if not validate_only:
            try:
                alerting.notify_deploy_failure(cluster, node, msg)
            except Exception:
                pass
        return {"node": node["name"], "ok": False, "error": msg, "log": log}

    def ok():
        if not validate_only:
            try:
                dbmod.execute(
                    "INSERT INTO config_versions"
                    " (cluster_id, node_id, node_name, content, user, note)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (cluster["id"], node["id"], node["name"], cfg, user, note),
                )
                dbmod.execute(
                    "DELETE FROM config_versions WHERE node_id = ? AND id NOT IN"
                    " (SELECT id FROM config_versions WHERE node_id = ?"
                    " ORDER BY id DESC LIMIT 30)",
                    (node["id"], node["id"]),
                )
            except Exception:
                pass
        return {"node": node["name"], "ok": True, "error": "", "log": log}

    try:
        if content is not None:
            cfg = content
            log.append(f"Version übernommen ({len(cfg.splitlines())} Zeilen)")
        else:
            cfg = generate_config(cluster, node)
            log.append(f"Konfiguration erzeugt ({len(cfg.splitlines())} Zeilen)")
        cert_files, warnings = certsvc.cluster_cert_files(cluster["id"])
        for w in warnings:
            log.append("WARNUNG: " + w)
        path = node["config_path"]
        new_path = path + ".new"

        if node.get("is_local"):
            os.makedirs(node["cert_dir"], exist_ok=True)
            for name, data in cert_files.items():
                target = os.path.join(node["cert_dir"], name)
                with open(target, "wb") as f:
                    f.write(data)
                os.chmod(target, 0o600)
            log.append(f"{len(cert_files)} Zertifikat(e) aktualisiert")
            with open(new_path, "w") as f:
                f.write(cfg)
            rc, out, err = _local(f"haproxy -c -f {new_path}")
            if (out + err).strip():
                log.append((out + err).strip())
            if rc != 0:
                os.remove(new_path)
                return fail("Validierung fehlgeschlagen – alte Config bleibt aktiv")
            log.append("haproxy -c: Konfiguration valide")
            if validate_only:
                os.remove(new_path)
                return ok()
            _local(f"cp {path} {path}.bak")
            os.replace(new_path, path)
            log.append(f"Konfiguration aktiviert (Backup: {path}.bak)")
            success, msg = reload_node(node)
            log.append(msg)
            if not success:
                return fail("Reload fehlgeschlagen: " + msg)
        else:
            rc, out, err = sshclient.run_ssh(node, f"mkdir -p {node['cert_dir']}")
            if rc != 0:
                return fail("SSH-Verbindung fehlgeschlagen: " + (err.strip() or out.strip()))
            for name, data in cert_files.items():
                sshclient.sftp_write(
                    node, f"{node['cert_dir'].rstrip('/')}/{name}", data, mode=0o600
                )
            log.append(f"{len(cert_files)} Zertifikat(e) hochgeladen")
            sshclient.sftp_write(node, new_path, cfg.encode())
            log.append(f"Konfiguration nach {new_path} hochgeladen")
            rc, out, err = sshclient.run_ssh(node, f"haproxy -c -f {new_path}")
            if (out + err).strip():
                log.append((out + err).strip())
            if rc != 0:
                sshclient.run_ssh(node, f"rm -f {new_path}")
                return fail(
                    "Validierung auf dem Node fehlgeschlagen – alte Config bleibt aktiv"
                )
            log.append("haproxy -c: Konfiguration valide")
            if validate_only:
                sshclient.run_ssh(node, f"rm -f {new_path}")
                return ok()
            sshclient.run_ssh(
                node, f"cp {path} {path}.bak 2>/dev/null; mv {new_path} {path}"
            )
            log.append(f"Konfiguration aktiviert (Backup: {path}.bak)")
            success, msg = reload_node(node)
            log.append(msg)
            if not success:
                return fail("Reload fehlgeschlagen: " + msg)

        try:
            info = runtime.show_info(node)
            log.append(
                f"Node online – HAProxy {info.get('Version', '?')}, "
                f"Uptime {info.get('Uptime', '?')}"
            )
        except Exception as exc:
            log.append(f"Runtime-Check fehlgeschlagen: {exc}")
        return ok()
    except Exception as exc:
        return fail(str(exc))
