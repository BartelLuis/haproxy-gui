import os

from .. import db as dbmod
from . import sshclient


def get_node_log(node, lines=300):
    """Liest die letzten Logzeilen eines HAProxy-Nodes."""
    lines = max(1, min(int(lines or 300), 2000))
    if node.get("is_local"):
        path = os.path.join(dbmod.DATA_DIR, "haproxy", "haproxy.log")
        if not os.path.exists(path):
            return "(noch keine Logs – läuft der eingebettete HAProxy?)"
        with open(path, "r", errors="replace") as f:
            content = f.readlines()
        return "".join(content[-lines:]) or "(Logdatei ist leer)"
    cmd = (
        f"journalctl -u haproxy -n {lines} --no-pager -o cat 2>/dev/null "
        f"|| tail -n {lines} /var/log/haproxy.log 2>/dev/null "
        f"|| tail -n {lines} /var/log/haproxy/haproxy.log 2>/dev/null "
        "|| echo 'KEIN LOG GEFUNDEN (journalctl/syslog)'"
    )
    rc, out, err = sshclient.run_ssh(node, cmd, timeout=30)
    text = (out or "").strip()
    if not text:
        text = (err or "").strip() or "(leere Antwort)"
    return text
