import io

import paramiko


def _load_key(text):
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception as exc:
            errors.append(str(exc))
    raise ValueError("SSH-Schlüssel ungültig: " + "; ".join(errors))


def ssh_connect(node, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": node["host"],
        "port": int(node.get("ssh_port") or 22),
        "username": node.get("ssh_user") or "root",
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if node.get("ssh_key"):
        kwargs["pkey"] = _load_key(node["ssh_key"])
        if node.get("ssh_password"):
            kwargs["passphrase"] = node["ssh_password"]
    elif node.get("ssh_password"):
        kwargs["password"] = node["ssh_password"]
    client.connect(**kwargs)
    return client


def run_ssh(node, command, timeout=60):
    client = ssh_connect(node)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        return (
            rc,
            stdout.read().decode("utf-8", "replace"),
            stderr.read().decode("utf-8", "replace"),
        )
    finally:
        client.close()


def sftp_write(node, remote_path, data, mode=None):
    client = ssh_connect(node)
    try:
        sftp = client.open_sftp()
        try:
            with sftp.file(remote_path, "wb") as f:
                f.write(data)
            if mode is not None:
                sftp.chmod(remote_path, mode)
        finally:
            sftp.close()
    finally:
        client.close()
