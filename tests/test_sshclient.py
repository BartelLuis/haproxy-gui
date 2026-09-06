import io
import threading
from types import SimpleNamespace

import paramiko
import pytest

from app.services import sshclient


def test_run_ssh_preserves_exit_status_and_output(monkeypatch):
    closed = []
    stdout = io.BytesIO(b"command output\n")
    stdout.channel = SimpleNamespace(recv_exit_status=lambda: 7)
    stderr = io.BytesIO(b"error \xff\n")

    def exec_command(command, timeout):
        assert command == "test command"
        assert timeout == 3
        return None, stdout, stderr

    client = SimpleNamespace(
        exec_command=exec_command, close=lambda: closed.append(True),
    )
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    assert sshclient.run_ssh({}, "test command", timeout=3) == (
        7, "command output\n", "error �\n",
    )
    assert closed == [True]


@pytest.mark.parametrize("stage", ["exec", "status", "read"])
def test_run_ssh_stalled_operations_are_bounded(monkeypatch, stage):
    closed = threading.Event()

    def wait_for_close():
        assert closed.wait(2), "SSH command was not stopped by its deadline"
        raise paramiko.SSHException("Connection closed")

    stdout = SimpleNamespace(
        channel=SimpleNamespace(
            recv_exit_status=wait_for_close if stage == "status" else lambda: 0,
        ),
        read=wait_for_close if stage == "read" else lambda: b"",
    )

    def exec_command(command, timeout):
        if stage == "exec":
            wait_for_close()
        return None, stdout, io.BytesIO()

    client = SimpleNamespace(exec_command=exec_command, close=closed.set)
    monkeypatch.setattr(sshclient, "ssh_connect", lambda node: client)
    with pytest.raises(TimeoutError, match="Zeitüberschreitung.*remote-node"):
        sshclient.run_ssh({"name": "remote-node"}, "test command", timeout=0.05)
    assert closed.is_set()


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
