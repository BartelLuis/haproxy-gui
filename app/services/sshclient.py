import base64
import io
import logging
import os
import posixpath
import stat
import threading
import uuid

import paramiko

from .. import db as dbmod

KNOWN_HOSTS = os.path.join(dbmod.DATA_DIR, "known_hosts")
SFTP_TIMEOUT = 60
logger = logging.getLogger(__name__)


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
    expired = threading.Event()

    def expire():
        expired.set()
        client.close()

    # Paramiko's command acknowledgement and exit-status waits have no deadline.
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        result = (
            rc,
            stdout.read().decode("utf-8", "replace"),
            stderr.read().decode("utf-8", "replace"),
        )
        if expired.is_set():
            raise TimeoutError("SSH-Befehl hat zu lange gedauert")
        return result
    except Exception as exc:
        if expired.is_set() or isinstance(exc, TimeoutError):
            name = node.get("name") or node.get("host") or "Node"
            raise TimeoutError(
                f"Zeitüberschreitung beim SSH-Befehl auf {name} "
                f"(Zeitlimit: {timeout} Sekunden)"
            ) from exc
        raise
    finally:
        timer.cancel()
        client.close()


def _open_sftp(client):
    channel = client.get_transport().open_session(timeout=SFTP_TIMEOUT)
    channel.settimeout(SFTP_TIMEOUT)
    expired = threading.Event()

    def expire():
        expired.set()
        channel.close()

    # invoke_subsystem waits without respecting the channel's socket timeout.
    timer = threading.Timer(SFTP_TIMEOUT, expire)
    timer.daemon = True
    timer.start()
    try:
        channel.invoke_subsystem("sftp")
        sftp = paramiko.SFTPClient(channel)
        if expired.is_set():
            raise TimeoutError("SFTP-Verbindungsaufbau hat zu lange gedauert")
        return sftp
    except Exception as exc:
        channel.close()
        if expired.is_set():
            raise TimeoutError("SFTP-Verbindungsaufbau hat zu lange gedauert") from exc
        raise
    finally:
        timer.cancel()


def sftp_write(node, remote_path, data, mode=None):
    """Erst vollständig hochladen und prüfen, dann die Zieldatei atomar ersetzen."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory, basename = posixpath.split(remote_path)
    temporary = posixpath.join(directory, f".{basename}.{uuid.uuid4().hex}.tmp")
    client = ssh_connect(node)
    try:
        sftp = _open_sftp(client)
        created = False
        try:
            if mode is None:
                try:
                    attrs = sftp.stat(remote_path)
                except FileNotFoundError:
                    pass
                else:
                    if attrs.st_mode is not None:
                        mode = stat.S_IMODE(attrs.st_mode)
            staged = sftp.file(temporary, "wxb")
            created = True
            with staged as f:
                if mode is not None:
                    sftp.chmod(temporary, mode)
                f.write(data)
            with sftp.file(temporary, "rb") as f:
                if f.read(len(data) + 1) != data:
                    raise OSError(
                        f"SFTP-Prüfung fehlgeschlagen: Inhalt von {remote_path} "
                        "stimmt nicht überein"
                    )
            try:
                sftp.posix_rename(temporary, remote_path)
            except TimeoutError:
                raise
            except OSError as exc:
                raise OSError(
                    f"Atomarer SFTP-Austausch von {remote_path} fehlgeschlagen "
                    f"(posix-rename erforderlich): {exc}"
                ) from exc
            created = False
        finally:
            try:
                if created:
                    try:
                        sftp.get_channel().settimeout(5)
                        sftp.remove(temporary)
                    except (OSError, EOFError, paramiko.SSHException):
                        logger.warning(
                            "Temporäre SFTP-Datei konnte nicht entfernt werden: %s",
                            temporary, exc_info=True,
                        )
            finally:
                sftp.close()
    except TimeoutError as exc:
        raise TimeoutError(
            f"Zeitüberschreitung bei SFTP-Übertragung nach {remote_path} "
            f"(Zeitlimit: {SFTP_TIMEOUT} Sekunden)"
        ) from exc
    finally:
        client.close()
