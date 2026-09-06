import socket
from types import SimpleNamespace

import paramiko
import pytest

from app.services import sshclient


class SocketProbe:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure
        self.closed = False

    def settimeout(self, timeout):
        self.calls.append(("timeout", timeout))

    def setsockopt(self, level, option, value):
        self.calls.append(("option", level, option, value))

    def connect(self, address):
        self.calls.append(("connect", address))
        if self.failure:
            raise self.failure

    def close(self):
        self.closed = True


def test_mss_is_set_before_connect_and_failed_addresses_are_closed(monkeypatch):
    ipv6 = ("::1", 2222, 0, 0)
    ipv4 = ("127.0.0.1", 2222)
    addresses = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ipv6),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ipv4),
    ]
    failed = SocketProbe(ConnectionRefusedError("IPv6 unavailable"))
    connected = SocketProbe()
    pending = iter([failed, connected])
    monkeypatch.setattr(socket, "TCP_MAXSEG", 2, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: addresses)
    monkeypatch.setattr(socket, "socket", lambda *args: next(pending))

    result = sshclient._open_ssh_socket("node.example", 2222, 7, 1024)

    assert result is connected and not connected.closed
    assert failed.closed
    for connection, address in [(failed, ipv6), (connected, ipv4)]:
        assert connection.calls == [
            ("timeout", 7),
            ("option", socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1024),
            ("connect", address),
        ]


def test_socket_creation_failure_tries_next_address(monkeypatch):
    connected = SocketProbe()
    addresses = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 22, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 22)),
    ]

    def create(family, *args):
        if family == socket.AF_INET6:
            raise OSError("IPv6 disabled")
        return connected

    monkeypatch.setattr(socket, "TCP_MAXSEG", 2, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: addresses)
    monkeypatch.setattr(socket, "socket", create)
    assert sshclient._open_ssh_socket("node.example", 22, 10, 1024) is connected


def test_failed_connection_is_closed_and_error_preserved(monkeypatch):
    failure = TimeoutError("TCP connection timed out")
    connection = SocketProbe(failure)
    monkeypatch.setattr(socket, "TCP_MAXSEG", 2, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 22)),
    ])
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    with pytest.raises(TimeoutError) as error:
        sshclient._open_ssh_socket("node.example", 22, 10, 1024)
    assert error.value is failure
    assert connection.closed


@pytest.mark.parametrize("setting", ["-1", "65536", "abc", "", "1024.5"])
def test_invalid_mss_configuration_is_rejected(monkeypatch, setting):
    monkeypatch.setenv("SSH_TCP_MAXSEG", setting)
    with pytest.raises(ValueError, match="SSH_TCP_MAXSEG"):
        sshclient._ssh_tcp_maxseg()


def test_default_mss_and_explicit_disable(monkeypatch):
    monkeypatch.delenv("SSH_TCP_MAXSEG", raising=False)
    monkeypatch.setattr(sshclient, "DEFAULT_SSH_TCP_MAXSEG", 1024)
    monkeypatch.setattr(socket, "TCP_MAXSEG", 2, raising=False)
    assert sshclient._ssh_tcp_maxseg() == 1024
    monkeypatch.setenv("SSH_TCP_MAXSEG", "0")
    assert sshclient._ssh_tcp_maxseg() == 0


def test_explicit_mss_on_unsupported_platform_has_clear_error(monkeypatch):
    monkeypatch.setenv("SSH_TCP_MAXSEG", "1024")
    monkeypatch.delattr(socket, "TCP_MAXSEG", raising=False)
    with pytest.raises(ValueError, match="nicht unterstützt"):
        sshclient._ssh_tcp_maxseg()


@pytest.mark.parametrize("mss", [0, 1024])
@pytest.mark.parametrize("auth_fails", [False, True])
def test_ssh_connection_preserves_host_authentication_and_socket_ownership(
    monkeypatch, mss, auth_fails,
):
    monkeypatch.setenv("SSH_TCP_MAXSEG", str(mss))
    monkeypatch.setattr(socket, "TCP_MAXSEG", 2, raising=False)
    connection = SocketProbe()
    calls = []
    closed = []
    policies = []

    def connect(**kwargs):
        calls.append(kwargs)
        if auth_fails:
            raise paramiko.AuthenticationException("Denied")

    def open_socket(*args):
        assert mss == 1024
        assert args == ("node.example", 2222, 7, 1024)
        return connection

    client = SimpleNamespace(
        set_missing_host_key_policy=policies.append,
        connect=connect, close=lambda: closed.append(True),
    )
    monkeypatch.setattr(sshclient.paramiko, "SSHClient", lambda: client)
    monkeypatch.setattr(sshclient, "_open_ssh_socket", open_socket)
    node = {
        "host": "node.example", "ssh_port": 2222,
        "ssh_user": "operator", "ssh_password": "test-password",
    }
    if auth_fails:
        with pytest.raises(paramiko.AuthenticationException, match="Denied"):
            sshclient.ssh_connect(node, timeout=7)
        assert closed == [True]
        assert connection.closed is bool(mss)
    else:
        assert sshclient.ssh_connect(node, timeout=7) is client
        assert not closed and not connection.closed
    assert isinstance(policies[0], sshclient._VerifyHostKey)
    kwargs = calls[0]
    assert kwargs["hostname"] == "node.example" and kwargs["port"] == 2222
    assert kwargs["username"] == "operator" and kwargs["password"] == "test-password"
    assert kwargs["timeout"] == kwargs["auth_timeout"] == kwargs["banner_timeout"] == 7
    assert kwargs["allow_agent"] is False and kwargs["look_for_keys"] is False
    if mss:
        assert kwargs["sock"] is connection
    else:
        assert "sock" not in kwargs
