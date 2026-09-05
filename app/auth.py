import base64
import binascii
import hashlib
import hmac
import os
import time

from fastapi import Depends, HTTPException, Request

from . import db

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
TOKEN_TTL = 7 * 24 * 3600
ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}

_secret = None


def _get_secret():
    global _secret
    if _secret is None:
        path = os.path.join(db.DATA_DIR, "secret.key")
        if os.path.exists(path):
            with open(path, "rb") as f:
                _secret = f.read().strip()
        else:
            os.makedirs(db.DATA_DIR, exist_ok=True)
            _secret = os.urandom(32).hex().encode()
            with open(path, "wb") as f:
                f.write(_secret)
    return _secret


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 150000).hex()
    return f"pbkdf2${salt.hex()}${digest}"


def verify_password(password, stored):
    try:
        _, salt_hex, digest = stored.split("$", 2)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 150000
        ).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def seed_admin():
    """Legt den initialen Admin aus den Umgebungsvariablen an."""
    if db.one("SELECT id FROM users LIMIT 1"):
        return
    db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        (ADMIN_USER, hash_password(ADMIN_PASSWORD)),
    )


def check_credentials(username, password):
    row = db.one("SELECT * FROM users WHERE username = ?", (username,))
    if row and verify_password(password, row["password_hash"]):
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    return None


def create_token(user):
    exp = int(time.time()) + TOKEN_TTL
    payload = f"{user['id']}:{user['username']}:{user['role']}:{exp}"
    sig = hmac.new(_get_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def verify_token(token):
    try:
        normalized = token + ("=" * (-len(token) % 4))
        raw = base64.b64decode(
            normalized.encode(), altchars=b"-_", validate=True
        ).decode()
        uid, username, role, exp, sig = raw.rsplit(":", 4)
        if time.time() > int(exp):
            return None
        expected = hmac.new(
            _get_secret(),
            f"{uid}:{username}:{role}:{exp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return {"id": int(uid), "username": username, "role": role}
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None


def _api_token_user(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.one("SELECT * FROM api_tokens WHERE token_hash = ?", (token_hash,))
    if not row:
        return None
    db.execute(
        "UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?", (row["id"],)
    )
    return {"id": 0, "username": f"api:{row['name']}", "role": row["role"]}


def require_auth(request: Request):
    user = None
    token = request.cookies.get("hg_token", "")
    if token:
        user = verify_token(token)
    if not user:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            raw = header[7:].strip()
            if raw.startswith("hg_"):
                user = _api_token_user(raw)
            else:
                user = verify_token(raw)
    if not user:
        raise HTTPException(status_code=401, detail="Nicht authentifiziert")
    if user["role"] not in ROLE_LEVEL:
        raise HTTPException(status_code=403, detail="Unbekannte Rolle")
    if user["role"] == "viewer" and request.method not in ("GET", "HEAD", "OPTIONS"):
        raise HTTPException(status_code=403, detail="Viewer haben nur Lesezugriff")
    return user


def require_role(min_role):
    def dep(user=Depends(require_auth)):
        if ROLE_LEVEL.get(user["role"], 0) < ROLE_LEVEL[min_role]:
            raise HTTPException(403, f"Rolle '{min_role}' erforderlich")
        return user

    return dep
