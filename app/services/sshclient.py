import base64
import io
import os

import paramiko

from .. import db as dbmod

KNOWN_HOSTS = os.path.join(dbmod.DATA_DIR, "known_hosts")


class _VerifyHostKey(paramiko.MissingHostKeyPolicy):
    """TOFU: bekannte Keys akzeptieren, neue speichern, geänderte ablehnen."""

    def missing_host_key(self, client, hostname, key):
        known = paramiko.HostKeys()
        if os.path.exists(KNOWN_HOSTS):
            known.load(KNOWN_HOSTS)
        ktype = key.get_name()
        if hostname in known and ktype in known[hostname]:
            if known[hostname][ktype] == key:
                return
            raise paramiko.SSHException(
                f"Host-Key für {hostname} hat sich geändert – möglicher MITM-Angriff!"
            )
        known.add(hostname, ktype, key)
        os.makedirs(dbmod.DATA_DIR, exist_ok=True)
        known.save(KNOWN_HOSTS)
        try:
            os.chmod(KNOWN_HOSTS, 0o600)
        except OSError:
            pass


def _load_key(text):
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception as exc:
            errors.append(str(exc))
    raise ValueError("SSH-Schlüssel ungültig: " + "; ".join(errors))


def _decode_secret(value):
    """Entschlüsselt enc:-Werte; erkennt und dekodiert zusätzlich Base64-Altbestand."""
    from .. import auth
    plain = auth.decrypt_secret(value or "")
    if not plain:
        return plain
    # Base64-kodierte Altbestände / YAML-Artefakte tolerieren
    if not plain.startswith("-----BEGIN") and "\n" not in plain:
        try:
            decoded = base64.b64decode(plain, validate=True).decode()
            if decoded.startswith("-----BEGIN"):
                return decoded
        except Exception:
            pass
    return plain


def ssh_connect(node, timeout=10):
    from .. import auth
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_VerifyHostKey())
    ssh_key = _decode_secret(node.get("ssh_key") or "")
    ssh_password = auth.decrypt_secret(node.get("ssh_password") or "")
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
    if ssh_key:
        kwargs["pkey"] = _load_key(ssh_key)
        if ssh_password:
            kwargs["passphrase"] = ssh_password
    elif ssh_password:
        kwargs["password"] = ssh_password
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
