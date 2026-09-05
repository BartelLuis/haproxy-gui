import hashlib


def test_admin_login_and_token(env):
    auth = env["auth"]
    user = auth.check_credentials("admin", "test123")
    assert user and user["role"] == "admin"
    token = auth.create_token(user)
    assert auth.verify_token(token)["username"] == "admin"
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
