from .. import db as dbmod

DEFAULTS = {
    "enabled": 0,
    "server_uri": "ldap://localhost:389",
    "bind_dn": "",
    "bind_password": "",
    "base_dn": "",
    "user_filter": "(&(objectClass=person)(uid={username}))",
    "use_tls": 0,
    "group_admin": "",
    "group_operator": "",
    "default_role": "viewer",
}


def get_settings():
    row = dbmod.one("SELECT value FROM alert_state WHERE key = 'ldap_settings'")
    if row:
        import json

        data = dict(DEFAULTS)
        data.update(json.loads(row["value"]))
        return data
    return dict(DEFAULTS)


def save_settings(data):
    import json

    current = get_settings()
    if not data.get("bind_password"):
        data["bind_password"] = current.get("bind_password", "")
    dbmod.execute(
        "INSERT INTO alert_state (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ("ldap_settings", json.dumps(data)),
    )


def _role_from_groups(member_of, st):
    def norm(dn):
        return dn.strip().lower()

    admin_g, op_g = norm(st.get("group_admin", "")), norm(st.get("group_operator", ""))
    groups = {norm(g) for g in member_of}
    if admin_g and admin_g in groups:
        return "admin"
    if op_g and op_g in groups:
        return "operator"
    if admin_g or op_g:
        # Gruppenfilter konfiguriert, aber keiner passt → kein Login
        return None
    return st.get("default_role") or "viewer"


def authenticate(username, password):
    """
    Authentifiziert gegen LDAP.
    Rückgabe: {"username", "role"} oder None (Fehler/ungültig/nicht konfiguriert).
    """
    st = get_settings()
    if not st.get("enabled") or not username or not password:
        return None
    try:
        import ldap3
    except ImportError:
        return None
    try:
        import ssl

        server = ldap3.Server(
            st["server_uri"],
            get_info=ldap3.NONE,
            tls=ldap3.Tls(validate=ssl.CERT_REQUIRED) if st.get("use_tls") else None,
        )
        # 1) Service-Bind zum Suchen (falls konfiguriert)
        if st.get("bind_dn"):
            search_conn = ldap3.Connection(
                server,
                user=st["bind_dn"],
                password=st.get("bind_password") or "",
                auto_bind=True,
                receive_timeout=10,
            )
        else:
            search_conn = ldap3.Connection(server, receive_timeout=10)
            search_conn.bind()
        user_filter = (st.get("user_filter") or "(uid={username})").replace(
            "{username}", ldap3.utils.conv.escape_filter_chars(username)
        )
        search_conn.search(
            st.get("base_dn") or "",
            user_filter,
            attributes=["memberOf"],
            size_limit=1,
        )
        if not search_conn.entries:
            search_conn.unbind()
            return None
        user_dn = search_conn.entries[0].entry_dn
        member_of = [
            str(g) for g in search_conn.entries[0].entry_attributes_dict.get("memberOf", [])
        ]
        search_conn.unbind()
        # 2) Benutzer-Bind (eigentliche Passwortprüfung)
        user_conn = ldap3.Connection(
            server, user=user_dn, password=password, auto_bind=True, receive_timeout=10
        )
        user_conn.unbind()
        role = _role_from_groups(member_of, st)
        if role is None:
            return None
        return {"username": username, "role": role}
    except Exception:
        return None


def test_connection():
    """Bind-Test mit den Service-Credentials. Rückgabe: (ok, nachricht)."""
    st = get_settings()
    try:
        import ldap3
    except ImportError:
        return False, "ldap3 ist nicht installiert"
    try:
        server = ldap3.Server(st["server_uri"], get_info=ldap3.NONE)
        conn = ldap3.Connection(
            server,
            user=st.get("bind_dn") or None,
            password=st.get("bind_password") or None,
            receive_timeout=8,
        )
        if conn.bind():
            conn.unbind()
            return True, "Verbindung und Bind erfolgreich"
        return False, f"Bind fehlgeschlagen: {conn.result.get('description', '?')}"
    except Exception as exc:
        return False, str(exc)
