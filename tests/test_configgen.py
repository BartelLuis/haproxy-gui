from app.services import configgen


def _make_backend_cluster(env, cluster):
    db = env["db"]
    be_id = db.execute(
        "INSERT INTO backends (cluster_id, name, mode, balance, check_path)"
        " VALUES (?, 'web', 'http', 'roundrobin', '/health')",
        (cluster["id"],),
    )
    db.execute(
        "INSERT INTO servers (backend_id, name, host, port)"
        " VALUES (?, 'web1', '10.0.0.1', 8080)",
        (be_id,),
    )
    return be_id


def test_generate_minimal(env, cluster):
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert cfg.startswith("global")
    assert "stats socket /run/haproxy/admin.sock" in cfg
    assert "defaults" in cfg


def test_generate_full(env, cluster):
    db = env["db"]
    be_id = _make_backend_cluster(env, cluster["cluster"])
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, default_backend_id, acls, rules)"
        " VALUES (?, 'https_in', 443, ?, ?, ?)",
        (
            cluster["cluster"]["id"],
            be_id,
            '[{"name": "host_api", "criterion": "hdr(host) -i", "value": "api.example.com"}]',
            '[{"backend": "web", "condition": "host_api"}]',
        ),
    )
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "frontend https_in" in cfg
    assert "bind *:443" in cfg
    assert "acl host_api hdr(host) -i api.example.com" in cfg
    assert "use_backend web if host_api" in cfg
    assert "default_backend web" in cfg
    assert "backend web" in cfg
    assert "balance roundrobin" in cfg
    assert "option httpchk GET /health" in cfg
    assert "server web1 10.0.0.1:8080 check" in cfg


def test_generate_tcp_backend(env, cluster):
    db = env["db"]
    be_id = db.execute(
        "INSERT INTO backends (cluster_id, name, mode) VALUES (?, 'db', 'tcp')",
        (cluster["cluster"]["id"],),
    )
    db.execute(
        "INSERT INTO servers (backend_id, name, host, port, backup)"
        " VALUES (?, 'db1', '10.0.0.2', 5432, 1)",
        (be_id,),
    )
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "backend db" in cfg
    assert "mode tcp" in cfg
    assert "server db1 10.0.0.2:5432 check backup" in cfg


def test_ssl_frontend_requires_cert(env, cluster):
    import pytest

    db = env["db"]
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, cert_id)"
        " VALUES (?, 'bad', 443, 1, NULL)",
        (cluster["cluster"]["id"],),
    )
    with pytest.raises(ValueError, match="kein Zertifikat"):
        configgen.generate_config(cluster["cluster"], cluster["node"])


def test_generate_route_rules(env, cluster):
    db = env["db"]
    be_app = db.execute(
        "INSERT INTO backends (cluster_id, name, mode, balance) VALUES (?, 'app', 'http', 'roundrobin')",
        (cluster["cluster"]["id"],),
    )
    be_admin = db.execute(
        "INSERT INTO backends (cluster_id, name, mode, balance) VALUES (?, 'admin', 'http', 'roundrobin')",
        (cluster["cluster"]["id"],),
    )
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, default_backend_id, rules)"
        " VALUES (?, 'http_in', 80, ?, ?)",
        (
            cluster["cluster"]["id"],
            be_app,
            '[{' 
            '"backend": "app", "condition": "if { hdr(host) -i app.example.com }"},'
            '{"backend": "admin", "condition": "if { path_beg /admin }"}'
            ']',
        ),
    )
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "use_backend app if { hdr(host) -i app.example.com }" in cfg
    assert "use_backend admin if { path_beg /admin }" in cfg


def test_extra_blocks(env, cluster):
    db = env["db"]
    db.execute(
        "UPDATE clusters SET global_extra = 'tune.ssl.default-dh-param 2048',"
        " defaults_extra = 'option forwardfor' WHERE id = ?",
        (cluster["cluster"]["id"],),
    )
    fresh = db.one("SELECT * FROM clusters WHERE id = ?", (cluster["cluster"]["id"],))
    cfg = configgen.generate_config(fresh, cluster["node"])
    assert "    tune.ssl.default-dh-param 2048" in cfg
    assert "    option forwardfor" in cfg
