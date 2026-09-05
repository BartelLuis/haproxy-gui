import csv
import io
import shlex
import socket

from . import sshclient


def _quote_cmd(cmd):
    """Ein Runtime-Kommando sicher in ein Shell-echo einbetten (einfache Quotes)."""
    return shlex.quote(cmd)


def _read_all(sock):
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _unix_cmd(path, cmd, timeout=5):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(cmd.encode() + b"\n")
        return _read_all(s)


def _tcp_cmd(host, port, cmd, timeout=5):
    with socket.create_connection((host, int(port)), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(cmd.encode() + b"\n")
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return _read_all(s)


def _ssh_cmd(node, cmd, timeout=15):
    # cmd und socket_path quoten -> keine Shell-/Runtime-Injection möglich
    quoted = _quote_cmd(cmd)
    socket_path = shlex.quote(node["socket_path"])
    rc, out, err = sshclient.run_ssh(
        node, f"printf '%s\\n' {quoted} | socat stdio {socket_path}", timeout=timeout
    )
    if rc != 0 and not out:
        raise RuntimeError(
            err.strip() or "socat fehlgeschlagen – ist socat auf dem Node installiert?"
        )
    return out


def _sanitize_token(value):
    """Einzelnes Runtime-Token (backend/server/table/key) auf sichere Zeichen prüfen."""
    value = (value or "").strip()
    if not value or any(c in value for c in "\n\r \t\"'\\`$;|&<>"):
        raise ValueError(f"Ungültiger Runtime-Wert: {value!r}")
    return value


def runtime_cmd(node, cmd):
    stype = node.get("socket_type") or "ssh"
    if stype == "tcp":
        return _tcp_cmd(
            node.get("socket_host") or node["host"], node.get("socket_port") or 9999, cmd
        )
    if stype == "unix":
        return _unix_cmd(node["socket_path"], cmd)
    return _ssh_cmd(node, cmd)


def show_info(node):
    info = {}
    for line in runtime_cmd(node, "show info").splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()
    return info


def show_stat(node):
    text = runtime_cmd(node, "show stat")
    rows = []
    headers = None
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if row[0].startswith("#"):
            headers = [h.strip() for h in row]
            headers[0] = headers[0].lstrip("#").strip()
            continue
        if headers and len(row) >= len(headers):
            rows.append(dict(zip(headers, row)))
    return rows


def set_server_state(node, backend, server, state):
    backend = _sanitize_token(backend)
    server = _sanitize_token(server)
    state = _sanitize_token(state)
    return runtime_cmd(node, f"set server {backend}/{server} state {state}")


def sanitize_token(value):
    return _sanitize_token(value)
