import base64
import hashlib
import io
import logging
import os
import posixpath
import shlex
import socket
import stat
import sys
import threading
import uuid

import paramiko

from .. import db as dbmod

KNOWN_HOSTS = os.path.join(dbmod.DATA_DIR, "known_hosts")
SFTP_TIMEOUT = 60
DEFAULT_SSH_TCP_MAXSEG = 1024 if sys.platform.startswith("linux") else 0
logger = logging.getLogger(__name__)
UPLOAD_STAGES = {
    "prepare": "temporäre Datei anlegen",
    "receive": "Dateidaten empfangen",
    "verify": "Datei prüfen",
    "activate": "Zieldatei ersetzen",
    "done": "Datei installiert",
}


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


def _ssh_tcp_maxseg():
    value = os.environ.get("SSH_TCP_MAXSEG", str(DEFAULT_SSH_TCP_MAXSEG))
    try:
        maxseg = int(value)
    except ValueError as exc:
        raise ValueError("SSH_TCP_MAXSEG muss eine Ganzzahl von 0 bis 65535 sein") from exc
    if not 0 <= maxseg <= 65535:
        raise ValueError("SSH_TCP_MAXSEG muss eine Ganzzahl von 0 bis 65535 sein")
    if maxseg and not hasattr(socket, "TCP_MAXSEG"):
        raise ValueError("SSH_TCP_MAXSEG wird auf diesem System nicht unterstützt; 0 deaktiviert es")
    return maxseg


def _open_ssh_socket(host, port, timeout, maxseg):
    """Begrenze TCP-Segmente vor dem Verbindungsaufbau, auch für die Gegenstelle."""
    addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    last_error = None
    for family, socktype, proto, _, address in addresses:
        connection = None
        try:
            connection = socket.socket(family, socktype, proto)
            connection.settimeout(timeout)
            # Linux advertises this MSS in the SYN only when set before connect.
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, maxseg)
            connection.connect(address)
            return connection
        except OSError as exc:
            if connection is not None:
                connection.close()
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError(f"Keine TCP-Adresse für SSH-Host {host} gefunden")


def ssh_connect(node, timeout=10):
    from .. import auth
    maxseg = _ssh_tcp_maxseg()
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
    connection = None
    try:
        if maxseg:
            connection = _open_ssh_socket(kwargs["hostname"], kwargs["port"], timeout, maxseg)
            kwargs["sock"] = connection
        client.connect(**kwargs)
    except Exception:
        client.close()
        if connection is not None:
            connection.close()
        raise
    return client


def run_ssh(node, command, timeout=60):
    return _exec_ssh(node, command, timeout=timeout)


class SSHCommandTimeout(TimeoutError):
    def __init__(self, message, *, phase, bytes_accepted, input_size,
                 stdin_eof_sent, exit_status, stdout, stderr):
        super().__init__(message)
        self.phase = phase
        self.bytes_accepted = bytes_accepted
        self.input_size = input_size
        self.stdin_eof_sent = stdin_eof_sent
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


def _exec_ssh(node, command, timeout=60, input_data=b""):
    client = ssh_connect(node)
    expired = threading.Event()
    channel = None
    output, errors = [], []
    phase = "exec_start"
    sent = 0
    eof_sent = False
    timeout_progress = None

    def progress():
        status = channel.exit_status if channel is not None else -1
        return phase, sent, eof_sent, status if status != -1 else None

    def expire():
        nonlocal timeout_progress
        # Closing a Paramiko channel sets readiness flags without a remote reply.
        timeout_progress = progress()
        expired.set()
        client.close()

    # Paramiko's command acknowledgement and exit-status waits have no deadline.
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        # Keep stdin alive: Paramiko's stdin destructor sends EOF to the command.
        _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
        channel = stdout.channel
        phase = "send" if input_data else "await_result"
        while not expired.is_set():
            active = False
            if channel.recv_ready():
                output.append(channel.recv(65536))
                active = True
            if channel.recv_stderr_ready():
                errors.append(channel.recv_stderr(65536))
                active = True
            if (
                channel.exit_status_ready()
                and (channel.eof_received or channel.closed)
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                break
            if (
                not eof_sent
                and not channel.closed
                and not channel.exit_status_ready()
            ):
                if sent == len(input_data):
                    # SSH EOF is a control message and needs no data-window credit.
                    channel.shutdown_write()
                    eof_sent = True
                    phase = "await_result"
                    active = True
                elif channel.send_ready():
                    count = channel.send(input_data[sent:sent + 65536])
                    if count == 0:
                        raise EOFError("SSH-Verbindung beim Schreiben geschlossen")
                    sent += count
                    active = True
            if not active:
                expired.wait(0.01)
        if expired.is_set():
            raise TimeoutError("SSH-Befehl hat zu lange gedauert")
        rc = channel.recv_exit_status()
        result = (
            rc,
            b"".join(output).decode("utf-8", "replace"),
            b"".join(errors).decode("utf-8", "replace"),
        )
        if expired.is_set():
            raise TimeoutError("SSH-Befehl hat zu lange gedauert")
        return result
    except Exception as exc:
        if expired.is_set() or isinstance(exc, TimeoutError):
            name = node.get("name") or node.get("host") or "Node"
            stage, accepted, input_eof, status = timeout_progress or progress()
            stages = {
                "exec_start": "SSH-Befehl starten",
                "send": "Daten an SSH übergeben",
                "await_result": "Remote-Ergebnis abwarten",
            }
            eof_text = "ja" if input_eof else "nein"
            status_text = str(status) if status is not None else "nicht empfangen"
            raise SSHCommandTimeout(
                f"Zeitüberschreitung beim SSH-Befehl auf {name} "
                f"(Zeitlimit: {timeout} Sekunden; Phase: {stages[stage]}; "
                f"von SSH angenommen: {accepted}/{len(input_data)} Bytes; "
                f"stdin-EOF gesendet: {eof_text}; Exit-Status: {status_text})",
                phase=stage, bytes_accepted=accepted, input_size=len(input_data),
                stdin_eof_sent=input_eof, exit_status=status,
                stdout=b"".join(output).decode("utf-8", "replace"),
                stderr=b"".join(errors).decode("utf-8", "replace"),
            ) from exc
        raise
    finally:
        timer.cancel()
        client.close()


def ssh_write(node, remote_path, data, mode=None, timeout=60):
    """Datei über SSH-stdin prüfen und atomar installieren, ohne SFTP."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory, basename = posixpath.split(remote_path)
    if not basename:
        raise ValueError("SSH-Ziel muss ein Dateipfad sein")
    template = posixpath.join(directory or ".", f".{basename}.tmp.XXXXXX")
    digest = hashlib.sha256(data).hexdigest()
    if mode is None:
        permissions = (
            'if [ -e "$target" ]; then\n'
            '    chmod "$(stat -L -c %a -- "$target")" "$temporary"\n'
            'else\n'
            '    chmod 644 "$temporary"\n'
            'fi'
        )
    else:
        permissions = f'chmod {mode:o} "$temporary"'
    script = f"""set -eu
umask 077
target={shlex.quote(remote_path)}
if [ -d "$target" ]; then
    printf '%s\\n' 'SSH-Ziel ist ein Verzeichnis' >&2
    exit 1
fi
printf '%s\\n' 'HG_UPLOAD_STAGE=prepare' >&2
temporary=$(mktemp {shlex.quote(template)})
trap 'rm -f -- "$temporary"' 0
trap 'exit 1' 1 2 15
printf '%s\\n' 'HG_UPLOAD_STAGE=receive' >&2
cat > "$temporary"
printf '%s\\n' 'HG_UPLOAD_STAGE=verify' >&2
actual_size=$(wc -c < "$temporary")
if [ "$actual_size" -ne {len(data)} ]; then
    printf '%s\\n' 'SSH-Dateiprüfung fehlgeschlagen: falsche Dateigröße' >&2
    exit 1
fi
actual_hash=$(sha256sum < "$temporary")
if [ "${{actual_hash%% *}}" != {digest} ]; then
    printf '%s\\n' 'SSH-Dateiprüfung fehlgeschlagen: SHA-256 stimmt nicht überein' >&2
    exit 1
fi
{permissions}
printf '%s\\n' 'HG_UPLOAD_STAGE=activate' >&2
mv -f -- "$temporary" "$target"
printf '%s\\n' 'HG_UPLOAD_STAGE=done' >&2
"""
    command = "sh -c " + shlex.quote(script)
    try:
        rc, out, err = _exec_ssh(node, command, timeout=timeout, input_data=data)
    except TimeoutError as exc:
        remote_stage = ""
        if isinstance(exc, SSHCommandTimeout):
            for line in exc.stderr.splitlines():
                if line.startswith("HG_UPLOAD_STAGE="):
                    stage = line.removeprefix("HG_UPLOAD_STAGE=")
                    if stage in UPLOAD_STAGES:
                        remote_stage = f"; letzte Remote-Phase: {UPLOAD_STAGES[stage]}"
        raise TimeoutError(
            f"SSH-Dateiübertragung nach {remote_path}: {exc}{remote_stage}"
        ) from exc
    if rc != 0:
        markers = {f"HG_UPLOAD_STAGE={stage}" for stage in UPLOAD_STAGES}
        error_lines = [
            line for line in err.splitlines()
            if line not in markers
        ]
        detail = ("\n".join(error_lines) or out).strip() or f"Exit-Code {rc}"
        raise OSError(
            f"SSH-Dateiübertragung nach {remote_path} fehlgeschlagen: {detail}"
        )


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
