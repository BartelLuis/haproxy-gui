"""TOTP-basiertes MFA (RFC 6238) – ohne externe Abhängigkeit."""
import base64
import hashlib
import hmac
import os
import struct
import time

from .. import db as dbmod


def _ensure_column():
    cols = [r["name"] for r in dbmod.q("PRAGMA table_info(users)")]
    if "totp_secret" not in cols:
        dbmod.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''")
    if "totp_enabled" not in cols:
        dbmod.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")


def generate_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp(secret, timestep=None, digits=6, period=30):
    if timestep is None:
        timestep = int(time.time() // period)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", timestep)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_code(secret, code, window=1):
    """Prüft einen TOTP-Code (±1 Zeitschritt Toleranz)."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = int(time.time() // 30)
    for dt in (-1, 0, 1):
        if hmac.compare_digest(_totp(secret, now + dt), code):
            return True
    return False


def start_setup(user_id):
    """Erzeugt ein neues Secret (noch nicht aktiviert)."""
    _ensure_column()
    secret = generate_secret()
    dbmod.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?",
                  (secret, user_id))
    return secret


def confirm_setup(user_id, code):
    """Aktiviert MFA, wenn der Code zum Secret passt."""
    _ensure_column()
    row = dbmod.one("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
    if not row or not row["totp_secret"]:
        return False, "Kein Setup gestartet"
    if not verify_code(row["totp_secret"], code):
        return False, "Code ungültig"
    dbmod.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user_id,))
    return True, "MFA aktiviert"


def disable(user_id):
    _ensure_column()
    dbmod.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?", (user_id,)
    )


def is_enabled(user_id):
    _ensure_column()
    row = dbmod.one("SELECT totp_enabled FROM users WHERE id = ?", (user_id,))
    return bool(row and row["totp_enabled"])


def get_secret(user_id):
    row = dbmod.one("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
    return row["totp_secret"] if row else ""


def verify(user_id, code):
    row = dbmod.one("SELECT totp_secret, totp_enabled FROM users WHERE id = ?", (user_id,))
    if not row or not row["totp_enabled"]:
        return True
    return verify_code(row["totp_secret"], code)


def provisioning_uri(username, secret, issuer="HAProxy-GUI"):
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def qr_png_data_uri(uri):
    """QR-Code als data-URI (nur wenn 'qrcode' installiert ist)."""
    try:
        import io
        import qrcode
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        return None
