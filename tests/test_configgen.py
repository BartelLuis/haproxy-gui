import pytest

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


def test_generate_dual_stack_frontend_binds(env, cluster):
    db = env["db"]
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, bind_family)"
        " VALUES (?, 'dual', 443, 'dual')",
        (cluster["cluster"]["id"],),
    )
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "    bind *:443" in cfg
    assert "    bind :::443 v6only" in cfg


def test_generate_ipv6_aware_frontend_rate_limit(env, cluster):
    env["db"].execute(
        "INSERT INTO frontends (cluster_id, name, port, rate_limit_requests,"
        " rate_limit_period) VALUES (?, 'limited', 443, 20, 10)",
        (cluster["cluster"]["id"],),
    )
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "stick-table type ip size 100k expire 30s store http_req_rate(10s)" in cfg
    assert "http-request track-sc0 src,ipmask(32,64)" in cfg
    assert "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }" in cfg


def test_generate_ipv6_stats_socket(env, cluster):
    node = dict(cluster["node"], socket_type="tcp", socket_host="2001:db8::10")
    cfg = configgen.generate_config(cluster["cluster"], node)
    assert "stats socket ipv6@2001:db8::10:9999 level operator" in cfg


def test_generate_remote_tcp_socket_defaults_to_node_address(env, cluster):
    node = dict(cluster["node"], is_local=0, socket_type="tcp", socket_host="")
    cfg = configgen.generate_config(cluster["cluster"], node)
    assert f"stats socket ipv4@{node['host']}:9999 level operator" in cfg


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


def test_ssl_frontend_uses_separate_certificate_and_key(env, cluster):
    db = env["db"]
    cert_id = db.execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES (?, ?, ?)",
        ("example.com", '["example.com"]', "manual"),
    )
    db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, cert_id)"
        " VALUES (?, 'https', 443, 1, ?)",
        (cluster["cluster"]["id"], cert_id),
    )
    node = dict(cluster["node"], cert_dir="/etc/haproxy/certs")
    cfg = configgen.generate_config(cluster["cluster"], node)
    assert "ssl-load-extra-del-ext" in cfg.split("defaults\n", 1)[0]
    assert "bind *:443 ssl crt /etc/haproxy/certs/example.com.crt alpn h2,http1.1" in cfg
    assert "ssl-key-file" not in cfg


def _make_ssl_server(env, cluster, host, ssl_verify, check):
    be_id = env["db"].execute(
        "INSERT INTO backends (cluster_id, name) VALUES (?, 'secure')",
        (cluster["cluster"]["id"],),
    )
    env["db"].execute(
        'INSERT INTO servers (backend_id, name, host, port, "check", ssl, ssl_verify)'
        " VALUES (?, 'app1', ?, 443, ?, 1, ?)",
        (be_id, host, check, ssl_verify),
    )


@pytest.mark.parametrize(("host", "ssl_verify", "check", "expected"), [
    ("10.0.0.5", 0, 1, "server app1 10.0.0.5:443 check ssl verify none check-ssl"),
    ("10.0.0.5", 0, 0, "server app1 10.0.0.5:443 ssl verify none"),
    (
        "app.example.com", 1, 1,
        "server app1 app.example.com:443 check ssl verify required ca-file @system-ca"
        " sni str(app.example.com) verifyhost app.example.com"
        " check-ssl check-sni app.example.com",
    ),
    (
        "app.example.com", 1, 0,
        "server app1 app.example.com:443 ssl verify required ca-file @system-ca"
        " sni str(app.example.com) verifyhost app.example.com",
    ),
])
def test_ssl_backend_server_sets_explicit_verification(
    env, cluster, host, ssl_verify, check, expected
):
    _make_ssl_server(env, cluster, host, ssl_verify, check)
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert f"\n    {expected}\n" in cfg


@pytest.mark.parametrize("host", ["10.0.0.5", "2001:db8::5"])
def test_ssl_backend_verification_rejects_ip_host(env, cluster, host):
    _make_ssl_server(env, cluster, host, 1, 1)
    with pytest.raises(ValueError, match="Hostnamen"):
        configgen.generate_config(cluster["cluster"], cluster["node"])


def test_init_db_migrates_existing_ssl_servers_to_verify_none(env, cluster):
    db = env["db"]
    conn = db.get_db()
    conn.executescript(
        """
        DROP TABLE servers;
        CREATE TABLE servers (
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
        """
    )
    be_id = db.execute(
        "INSERT INTO backends (cluster_id, name) VALUES (?, 'legacy')",
        (cluster["cluster"]["id"],),
    )
    db.execute(
        "INSERT INTO servers (backend_id, name, host, port, ssl)"
        " VALUES (?, 'old', '10.0.0.6', 443, 1)",
        (be_id,),
    )

    db.init_db()

    assert db.one("SELECT ssl_verify FROM servers WHERE name = 'old'") == {"ssl_verify": 0}
    cfg = configgen.generate_config(cluster["cluster"], cluster["node"])
    assert "\n    server old 10.0.0.6:443 check ssl verify none check-ssl\n" in cfg


def test_generate_route_rules(env, cluster):
    db = env["db"]
    be_app = db.execute(
        "INSERT INTO backends (cluster_id, name, mode, balance) VALUES (?, 'app', 'http', 'roundrobin')",
        (cluster["cluster"]["id"],),
    )
    db.execute(
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


def _add_cert(env, name):
    return env["db"].execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES (?, ?, 'manual')",
        (name, f'["{name}"]'),
    )


def _bind_lines(cfg):
    return [line.strip() for line in cfg.splitlines() if line.strip().startswith("bind ")]


def test_ssl_frontend_binds_all_certificates_in_order(env, cluster):
    from app.services import certmap

    cert_ids = [_add_cert(env, name) for name in ("c.example.com", "a.example.com", "b.example.com")]
    fid = env["db"].execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl) VALUES (?, 'https', 443, 1)",
        (cluster["cluster"]["id"],),
    )
    certmap.save_frontend_certs(fid, cert_ids)
    node = dict(cluster["node"], cert_dir="/etc/haproxy/certs")
    cfg = configgen.generate_config(cluster["cluster"], node)
    assert _bind_lines(cfg) == [
        "bind *:443 ssl crt /etc/haproxy/certs/c.example.com.crt"
        " crt /etc/haproxy/certs/a.example.com.crt"
        " crt /etc/haproxy/certs/b.example.com.crt alpn h2,http1.1"
    ]


def test_ssl_frontend_adds_certificates_of_routed_backends(env, cluster):
    from app.services import certmap

    db = env["db"]
    cid = cluster["cluster"]["id"]
    own, shared, web_cert, api_cert, admin_cert, other_cert = (
        _add_cert(env, name)
        for name in ("own", "shared", "web-cert", "api-cert", "admin-cert", "other-cert")
    )
    backends = {
        name: db.execute("INSERT INTO backends (cluster_id, name) VALUES (?, ?)", (cid, name))
        for name in ("web", "api", "admin", "other")
    }
    certmap.save_backend_certs(backends["web"], [web_cert])
    certmap.save_backend_certs(backends["api"], [api_cert, shared])
    certmap.save_backend_certs(backends["admin"], [admin_cert])
    certmap.save_backend_certs(backends["other"], [other_cert])
    fid = db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, default_backend_id, rules)"
        " VALUES (?, 'https', 443, 1, ?, ?)",
        (
            cid,
            backends["web"],
            '[{"backend": "api", "condition": "host_api"},'
            ' {"backend": "admin", "condition": ""}]',
        ),
    )
    certmap.save_frontend_certs(fid, [own, shared])
    cfg = configgen.generate_config(cluster["cluster"], dict(cluster["node"], cert_dir="/c"))
    # Regeln ohne Bedingung erzeugen kein use_backend – deren Zertifikate fehlen daher.
    assert _bind_lines(cfg) == [
        "bind *:443 ssl crt /c/own.crt crt /c/shared.crt crt /c/web-cert.crt"
        " crt /c/api-cert.crt alpn h2,http1.1"
    ]


def test_ssl_frontend_can_rely_on_backend_certificates(env, cluster):
    from app.services import certmap

    be_id = _make_backend_cluster(env, cluster["cluster"])
    certmap.save_backend_certs(be_id, [_add_cert(env, "app.example.com")])
    env["db"].execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, default_backend_id)"
        " VALUES (?, 'https', 443, 1, ?)",
        (cluster["cluster"]["id"], be_id),
    )
    cfg = configgen.generate_config(cluster["cluster"], dict(cluster["node"], cert_dir="/c"))
    assert _bind_lines(cfg) == ["bind *:443 ssl crt /c/app.example.com.crt alpn h2,http1.1"]


def test_ssl_frontend_certificate_limit_fits_haproxy_line_limit(env, cluster):
    from app.services import certmap

    cert_ids = [
        _add_cert(env, f"site{i}.example.com") for i in range(certmap.MAX_FRONTEND_CERTS + 1)
    ]
    fid = env["db"].execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, bind_family)"
        " VALUES (?, 'https', 443, 1, 'dual')",
        (cluster["cluster"]["id"],),
    )
    certmap.save_frontend_certs(fid, cert_ids)
    with pytest.raises(ValueError, match=f"maximal {certmap.MAX_FRONTEND_CERTS}"):
        configgen.generate_config(cluster["cluster"], cluster["node"])

    certmap.save_frontend_certs(fid, cert_ids[:-1])
    node = dict(cluster["node"], cert_dir="/etc/haproxy/certs")
    binds = _bind_lines(configgen.generate_config(cluster["cluster"], node))
    assert len(binds) == 2
    for bind in binds:
        words = bind.split()
        assert words.count("crt") == certmap.MAX_FRONTEND_CERTS
        # HAProxy liest höchstens 64 Wörter pro Konfigurationszeile (MAX_LINE_ARGS).
        assert len(words) <= 64
