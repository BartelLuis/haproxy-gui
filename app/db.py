import os
import sqlite3
import threading

DATA_DIR = os.environ.get("HG_DATA", "/data")
DB_PATH = os.path.join(DATA_DIR, "haproxy-gui.db")

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    global_extra TEXT DEFAULT '',
    defaults_extra TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    ssh_port INTEGER DEFAULT 22,
    ssh_user TEXT DEFAULT 'root',
    ssh_key TEXT DEFAULT '',
    ssh_password TEXT DEFAULT '',
    is_local INTEGER DEFAULT 0,
    config_path TEXT DEFAULT '/etc/haproxy/haproxy.cfg',
    cert_dir TEXT DEFAULT '/etc/haproxy/certs',
    socket_type TEXT DEFAULT 'ssh',
    socket_path TEXT DEFAULT '/var/run/haproxy/admin.sock',
    socket_host TEXT DEFAULT '',
    socket_port INTEGER DEFAULT 0,
    reload_cmd TEXT DEFAULT '',
    UNIQUE(cluster_id, name)
);
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    domains TEXT NOT NULL,
    email TEXT DEFAULT '',
    dns_provider TEXT NOT NULL,
    provider_config TEXT DEFAULT '{}',
    auto_renew INTEGER DEFAULT 1,
    status TEXT DEFAULT 'pending',
    message TEXT DEFAULT '',
    not_after TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS backends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mode TEXT DEFAULT 'http',
    balance TEXT DEFAULT 'roundrobin',
    check_path TEXT DEFAULT '',
    check_expect TEXT DEFAULT '',
    extra TEXT DEFAULT '',
    UNIQUE(cluster_id, name)
);
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backend_id INTEGER NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    "check" INTEGER DEFAULT 1,
    ssl INTEGER DEFAULT 0,
    weight INTEGER DEFAULT 100,
    maxconn INTEGER DEFAULT 0,
    backup INTEGER DEFAULT 0,
    UNIQUE(backend_id, name)
);
CREATE TABLE IF NOT EXISTS frontends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    bind_ip TEXT DEFAULT '*',
    port INTEGER NOT NULL,
    mode TEXT DEFAULT 'http',
    use_ssl INTEGER DEFAULT 0,
    cert_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    ssl_redirect INTEGER DEFAULT 0,
    default_backend_id INTEGER REFERENCES backends(id) ON DELETE SET NULL,
    acls TEXT DEFAULT '[]',
    rules TEXT DEFAULT '[]',
    extra TEXT DEFAULT '',
    UNIQUE(cluster_id, name)
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'operator',
    created_at TEXT DEFAULT (datetime('now')),
    last_used TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    user TEXT DEFAULT 'system',
    action TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS config_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    node_name TEXT DEFAULT '',
    content TEXT NOT NULL,
    user TEXT DEFAULT 'system',
    note TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS alert_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER DEFAULT 0,
    webhook_url TEXT DEFAULT '',
    smtp_host TEXT DEFAULT '',
    smtp_port INTEGER DEFAULT 587,
    smtp_user TEXT DEFAULT '',
    smtp_pass TEXT DEFAULT '',
    smtp_from TEXT DEFAULT '',
    smtp_to TEXT DEFAULT '',
    alert_node_down INTEGER DEFAULT 1,
    alert_cert_expiry INTEGER DEFAULT 1,
    alert_deploy_fail INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alert_state (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS keepalived (
    cluster_id INTEGER PRIMARY KEY REFERENCES clusters(id) ON DELETE CASCADE,
    vip TEXT DEFAULT '',
    iface TEXT DEFAULT 'eth0',
    vr_id INTEGER DEFAULT 51,
    auth_pass TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS keepalived_nodes (
    node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    state TEXT DEFAULT 'BACKUP',
    priority INTEGER DEFAULT 100
);
"""


def audit(username, action, detail=""):
    execute(
        "INSERT INTO audit_log (user, action, detail) VALUES (?, ?, ?)",
        (username, action, (detail or "")[:2000]),
    )


def get_db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _local.conn = conn
        _harden_db_file()
    return conn


def _harden_db_file():
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def q(sql, args=()):
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def one(sql, args=()):
    row = get_db().execute(sql, args).fetchone()
    return dict(row) if row else None


def execute(sql, args=()):
    cur = get_db().execute(sql, args)
    get_db().commit()
    return cur.lastrowid


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
    _seed_local()


def _seed_local():
    if os.environ.get("ENABLE_LOCAL_HAPROXY", "true").lower() != "true":
        return
    if one("SELECT id FROM clusters WHERE name = 'Local'"):
        return
    cid = execute(
        "INSERT INTO clusters (name, description) VALUES (?, ?)",
        ("Local", "Eingebettete HAProxy-Instanz in diesem Container"),
    )
    execute(
        "INSERT INTO nodes (cluster_id, name, host, is_local, config_path, cert_dir,"
        " socket_type, socket_path, reload_cmd) VALUES (?, ?, ?, 1, ?, ?, 'unix', ?, 'sigusr2')",
        (
            cid,
            "local",
            "127.0.0.1",
            os.path.join(DATA_DIR, "haproxy", "haproxy.cfg"),
            os.path.join(DATA_DIR, "haproxy", "certs"),
            "/run/haproxy/admin.sock",
        ),
    )
