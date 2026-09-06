import io
import shutil
import subprocess
import threading
from types import SimpleNamespace

import paramiko
import pytest

from app.services import sshclient


class FakeExecChannel:
    def __init__(self, stdout=b"", stderr=b"", status=0, require_input=False):
        self.output = bytearray(stdout)
        self.errors = bytearray(stderr)
        self.status = status
        self.received = bytearray()
        self.closed = False
        self.eof_received = not require_input
        self.input_closed = False
        self.require_input = require_input

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv(self, size):
        result = bytes(self.output[:size])
        del self.output[:size]
        return result

    def recv_stderr(self, size):
        result = bytes(self.errors[:size])
        del self.errors[:size]
        return result

    def send_ready(self):
        return True

    def send(self, data):
        assert not self.input_closed
        count = min(7, len(data))
        self.received.extend(data[:count])
        return count

    def shutdown_write(self):
        self.input_closed = True
        self.eof_received = True

    def exit_status_ready(self):
        return not self.require_input or self.input_closed

    def recv_exit_status(self):
        assert not self.output and not self.errors
        return self.status


def test_run_ssh_preserves_exit_status_and_output(monkeypatch):
    closed = []
    channel = FakeExecChannel(b"command output\n", b"error \xff\n", status=7)

    def exec_command(command, timeout):
        assert command == "test command"
        assert timeout == 3
        return None, SimpleNamespace(channel=channel), None

    client = SimpleNamespace(
        exec_command=exec_command, close=lambda: closed.append(True),
    )
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    assert sshclient.run_ssh({}, "test command", timeout=3) == (
        7, "command output\n", "error �\n",
    )
    assert closed == [True]


def test_exec_ssh_sends_all_stdin_without_closing_it_early(monkeypatch):
    channel = FakeExecChannel(b"output", b"errors", require_input=True)
    client = SimpleNamespace(
        exec_command=lambda command, timeout: (
            paramiko.channel.ChannelStdinFile(channel, "wb"),
            SimpleNamespace(channel=channel), None,
        ),
        close=lambda: None,
    )
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    payload = b"private payload\x00\xff\n" * 20
    assert sshclient._exec_ssh({}, "test", input_data=payload) == (
        0, "output", "errors",
    )
    assert bytes(channel.received) == payload
    assert channel.input_closed


@pytest.mark.parametrize("stage", ["exec", "status", "read"])
def test_run_ssh_stalled_operations_are_bounded(monkeypatch, stage):
    closed = threading.Event()

    def wait_for_close():
        assert closed.wait(2), "SSH command was not stopped by its deadline"
        raise paramiko.SSHException("Connection closed")

    channel = FakeExecChannel()
    if stage == "status":
        channel.exit_status_ready = lambda: False
    elif stage == "read":
        channel.recv_ready = lambda: True
        channel.recv = lambda size: wait_for_close()

    def exec_command(command, timeout):
        if stage == "exec":
            wait_for_close()
        return None, SimpleNamespace(channel=channel), None

    client = SimpleNamespace(exec_command=exec_command, close=closed.set)
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    with pytest.raises(TimeoutError, match="Zeitüberschreitung.*remote-node"):
        sshclient.run_ssh({"name": "remote-node"}, "test command", timeout=0.05)
    assert closed.is_set()


def test_ssh_connect_closes_failed_connection(monkeypatch):
    closed = []

    def connect(**kwargs):
        raise paramiko.AuthenticationException("Denied")

    client = SimpleNamespace(
        set_missing_host_key_policy=lambda policy: None,
        connect=connect, close=lambda: closed.append(True),
    )
    monkeypatch.setattr(sshclient.paramiko, "SSHClient", lambda: client)
    with pytest.raises(paramiko.AuthenticationException, match="Denied"):
        sshclient.ssh_connect({"host": "example.com", "ssh_password": "test"})
    assert closed == [True]


def test_ssh_write_passes_private_bytes_only_over_stdin(monkeypatch):
    payload = b"-----BEGIN PRIVATE KEY-----\nsecret bytes\x00\xff\n"
    calls = []

    def execute(node, command, timeout, input_data):
        calls.append((command, timeout, input_data))
        return 0, "", ""

    monkeypatch.setattr(sshclient, "_exec_ssh", execute)
    sshclient.ssh_write({}, "/etc/haproxy/certs/example.key", payload, mode=0o600)
    command, timeout, sent = calls[0]
    assert sent == payload
    assert command.startswith("sh -c ")
    assert "PRIVATE KEY" not in command and "secret bytes" not in command
    assert "sha256sum" in command and "chmod 600" in command
    assert timeout == 60


@pytest.mark.parametrize("failure", ["command", "timeout"])
def test_ssh_write_errors_include_destination(monkeypatch, failure):
    def execute(*args, **kwargs):
        if failure == "timeout":
            raise TimeoutError("SSH timeout")
        return 1, "", "Disk full"

    monkeypatch.setattr(sshclient, "_exec_ssh", execute)
    with pytest.raises(OSError, match="example.key"):
        sshclient.ssh_write({}, "/etc/haproxy/certs/example.key", b"key", mode=0o600)


@pytest.mark.parametrize("corrupt", [False, True])
def test_ssh_write_script_verifies_and_atomically_installs(
    tmp_path, monkeypatch, corrupt,
):
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX shell required for remote script execution")
    target = tmp_path / "example.key"
    target.write_bytes(b"old key")
    payload = b"new key\x00with binary data\xff\n"

    def execute(node, command, timeout, input_data):
        if corrupt:
            input_data = b"!" * len(input_data)
        proc = subprocess.run(
            [shell, "-c", command], input=input_data, capture_output=True,
            timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    monkeypatch.setattr(sshclient, "_exec_ssh", execute)
    if corrupt:
        with pytest.raises(OSError, match="SHA-256"):
            sshclient.ssh_write({}, target.as_posix(), payload, mode=0o600)
        assert target.read_bytes() == b"old key"
    else:
        sshclient.ssh_write({}, target.as_posix(), payload, mode=0o600)
        assert target.read_bytes() == payload
    assert list(tmp_path.iterdir()) == [target]


class FakeSFTP:
    def __init__(self):
        self.target = "/etc/haproxy/certs/example.crt"
        self.files = {self.target: b"previous certificate"}
        self.modes = {self.target: 0o640}
        self.failure = None
        self.closed = False
        self.removed = []
        self.renamed = []
        self.timeouts = []
        self.write_modes = []

    def file(self, path, mode):
        if mode == "rb":
            return io.BytesIO(self.files[path])
        assert mode == "wxb"
        assert path != self.target
        assert path not in self.files
        self.files[path] = b""
        self.modes[path] = 0o644
        sftp = self

        class Writer:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def write(self, data):
                sftp.write_modes.append(sftp.modes[path])
                if isinstance(sftp.failure, Exception):
                    raise sftp.failure
                if sftp.failure == "empty":
                    return
                if sftp.failure == "corrupt":
                    sftp.files[path] = b"!" * len(data)
                else:
                    sftp.files[path] = data

        return Writer()

    def chmod(self, path, mode):
        self.modes[path] = mode

    def stat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=self.modes[path])

    def posix_rename(self, source, destination):
        if self.failure == "rename":
            raise OSError("Operation unsupported")
        self.renamed.append((source, destination))
        self.files[destination] = self.files.pop(source)
        self.modes[destination] = self.modes.pop(source)

    def remove(self, path):
        assert path != self.target
        self.removed.append(path)
        del self.files[path]

    def get_channel(self):
        return SimpleNamespace(settimeout=self.timeouts.append)

    def close(self):
        self.closed = True


@pytest.fixture()
def upload(monkeypatch):
    sftp = FakeSFTP()
    closed = []
    client = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    monkeypatch.setattr(sshclient, "_open_sftp", lambda client: sftp)
    return sftp, closed


def test_sftp_upload_verifies_content_and_activates_with_permissions(upload):
    sftp, closed = upload
    sshclient.sftp_write({}, sftp.target, b"new certificate", mode=0o600)
    assert sftp.files == {sftp.target: b"new certificate"}
    assert sftp.modes[sftp.target] == 0o600
    assert sftp.write_modes == [0o600]
    assert len(sftp.renamed) == 1
    assert sftp.renamed[0][0].startswith("/etc/haproxy/certs/.example.crt.")
    assert sftp.removed == []
    assert sftp.closed and closed == [True]


def test_sftp_upload_preserves_existing_mode_when_unspecified(upload):
    sftp, _ = upload
    sshclient.sftp_write({}, sftp.target, "new configuration")
    assert sftp.files[sftp.target] == b"new configuration"
    assert sftp.modes[sftp.target] == 0o640


@pytest.mark.parametrize(
    "failure", [OSError("Disk full"), "empty", "corrupt", "rename"],
)
def test_failed_upload_preserves_live_file_and_cleans_temporary(upload, failure):
    sftp, closed = upload
    sftp.failure = failure
    with pytest.raises(OSError):
        sshclient.sftp_write({}, sftp.target, b"new certificate", mode=0o600)
    assert sftp.files == {sftp.target: b"previous certificate"}
    assert sftp.modes[sftp.target] == 0o640
    assert len(sftp.removed) == 1
    assert sftp.renamed == []
    assert sftp.closed and closed == [True]


def test_upload_timeout_reports_destination_and_preserves_live_file(upload):
    sftp, closed = upload
    sftp.failure = TimeoutError()
    with pytest.raises(TimeoutError, match="Zeitüberschreitung.*example.crt"):
        sshclient.sftp_write({}, sftp.target, b"new certificate", mode=0o600)
    assert sftp.files == {sftp.target: b"previous certificate"}
    assert sftp.timeouts == [5]
    assert sftp.closed and closed == [True]


def test_sftp_upload_creates_new_config_file(upload):
    sftp, _ = upload
    sftp.files.clear()
    sftp.modes.clear()
    sshclient.sftp_write({}, sftp.target, b"new configuration")
    assert sftp.files == {sftp.target: b"new configuration"}
    assert sftp.modes[sftp.target] == 0o644


def test_sftp_setup_failure_still_closes_ssh_client(upload, monkeypatch):
    sftp, closed = upload

    def fail_setup(client):
        raise TimeoutError()

    monkeypatch.setattr(sshclient, "_open_sftp", fail_setup)
    with pytest.raises(TimeoutError, match="example.crt"):
        sshclient.sftp_write({}, sftp.target, b"new certificate")
    assert closed == [True]
    assert sftp.files == {sftp.target: b"previous certificate"}


def test_sftp_subsystem_negotiation_is_bounded(monkeypatch):
    closed = threading.Event()
    timeouts = []
    monkeypatch.setattr(sshclient, "SFTP_TIMEOUT", 0.05)

    def invoke_subsystem(name):
        assert name == "sftp"
        assert closed.wait(2), "SFTP negotiation was not stopped by its deadline"
        raise paramiko.SSHException("Channel closed")

    channel = SimpleNamespace(
        settimeout=timeouts.append, close=closed.set, invoke_subsystem=invoke_subsystem,
    )

    def open_session(timeout):
        assert timeout == 0.05
        return channel

    client = SimpleNamespace(
        get_transport=lambda: SimpleNamespace(open_session=open_session),
    )
    with pytest.raises(TimeoutError, match="SFTP-Verbindungsaufbau"):
        sshclient._open_sftp(client)
    assert timeouts == [0.05]
    assert closed.is_set()
