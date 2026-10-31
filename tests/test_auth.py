import hashlib


def test_admin_login_and_token(env):
    auth = env["auth"]
    user = auth.check_credentials("admin", "test123")
    assert user and user["role"] == "admin"
    token = auth.create_token(user)
    assert auth.verify_token(token)["username"] == "admin"
    assert auth.verify_token(token.rstrip("="))["username"] == "admin"
    assert auth.verify_token(token + "x") is None
    assert auth.check_credentials("admin", "falsch") is None


def test_password_hash_roundtrip(env):
    auth = env["auth"]
    stored = auth.hash_password("geheim42")
    assert stored.startswith("pbkdf2$")
    assert auth.verify_password("geheim42", stored)
    assert not auth.verify_password("falsch", stored)


def test_viewer_user(env):
    db, auth = env["db"], env["auth"]
    db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("view1", auth.hash_password("pw12345"), "viewer"),
    )
    user = auth.check_credentials("view1", "pw12345")
    assert user["role"] == "viewer"
    assert auth.check_credentials("view1", "falsch") is None


def test_api_token_lookup(env):
    db, auth = env["db"], env["auth"]
    raw = "hg_testtoken123"
    db.execute(
        "INSERT INTO api_tokens (name, token_hash, role) VALUES (?, ?, ?)",
        ("ci", hashlib.sha256(raw.encode()).hexdigest(), "operator"),
    )
    user = auth._api_token_user(raw)
    assert user and user["role"] == "operator" and user["username"] == "api:ci"
    assert auth._api_token_user("hg_falsch") is None


def test_role_levels(env):
    auth = env["auth"]
    assert auth.ROLE_LEVEL["viewer"] < auth.ROLE_LEVEL["operator"] < auth.ROLE_LEVEL["admin"]


def test_forwarded_ip_is_ignored_without_trusted_proxy(env, monkeypatch):
    from starlette.requests import Request
    from app.routers.auth_routes import _client_ip

    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    request = Request({
        "type": "http",
        "method": "POST",
        "headers": [(b"x-forwarded-for", b"198.51.100.10")],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "path": "/",
        "query_string": b"",
    })
    assert _client_ip(request) == "127.0.0.1"


def test_forwarded_ip_is_used_only_through_trusted_proxy(env, monkeypatch):
    from starlette.requests import Request
    from app.routers.auth_routes import _client_ip

    monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1/32")
    request = Request({
        "type": "http",
        "method": "POST",
        "headers": [
            (b"x-forwarded-for", b"2001:db8:1::10, 127.0.0.1"),
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "path": "/",
        "query_string": b"",
    })
    assert _client_ip(request) == "2001:db8:1::10"


def test_login_rate_limit_groups_ipv6_by_64(env):
    from app.routers.auth_routes import _rate_limit_key

    assert _rate_limit_key("2001:db8:1:2::1", "admin") == (
        "2001:db8:1:2::/64|admin"
    )
    assert _rate_limit_key("2001:db8:1:2::abcd", "admin") == (
        "2001:db8:1:2::/64|admin"
    )
    assert _rate_limit_key("::ffff:192.0.2.1", "admin") == (
        "192.0.2.1/32|admin"
    )
