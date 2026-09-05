import csv
import io
import socket

from . import sshclient


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
    rc, out, err = sshclient.run_ssh(
        node, f'echo "{cmd}" | socat stdio {node["socket_path"]}', timeout=timeout
    )
    if rc != 0 and not out:
        raise RuntimeError(
            err.strip() or "socat fehlgeschlagen – ist socat auf dem Node installiert?"
        )
    return out


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
    return runtime_cmd(node, f"set server {backend}/{server} state {state}")
