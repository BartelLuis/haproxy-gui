from app.services import certmap


def _cert(db, name):
    return db.execute(
        "INSERT INTO certificates (name, domains, dns_provider) VALUES (?, ?, 'manual')",
        (name, f'["{name}"]'),
    )


def _backend(db, cluster_id, name):
    return db.execute(
        "INSERT INTO backends (cluster_id, name) VALUES (?, ?)", (cluster_id, name)
    )


def _frontend(db, cluster_id, name, use_ssl=True, default_backend_id=None, rules="[]"):
    return db.execute(
        "INSERT INTO frontends (cluster_id, name, port, use_ssl, default_backend_id, rules)"
        " VALUES (?, ?, 443, ?, ?, ?)",
        (cluster_id, name, int(use_ssl), default_backend_id, rules),
    )


def test_routed_backend_ids_follow_generated_rules():
    backends = [{"id": 1, "name": "web"}, {"id": 2, "name": "api"}, {"id": 3, "name": "admin"}]
    rules = [
        {"backend": " api ", "condition": "host_api"},
        {"backend": "admin", "condition": "  "},
        {"backend": "unknown", "condition": "host_unknown"},
        {"backend": "web", "condition": "path_web"},
        "kaputt",
    ]
    assert certmap.routed_backend_ids(1, rules, backends) == [1, 2]
    assert certmap.routed_backend_ids(
        99, '[{"backend": "admin", "condition": "is_admin"}]', backends
    ) == [3]
    assert certmap.routed_backend_ids(None, "kein json", backends) == []


def test_effective_cert_ids_put_own_certificates_first():
    backend_certs = {1: [3, 7], 2: [8, 7], 4: [9]}
    assert certmap.effective_cert_ids([5, 3], [1, 2], backend_certs) == [5, 3, 7, 8]
    assert certmap.effective_cert_ids([], [2], backend_certs) == [8, 7]


def test_saved_links_replace_legacy_column(env, cluster):
    db = env["db"]
    first, second = _cert(db, "first.example.com"), _cert(db, "second.example.com")
    fid = _frontend(db, cluster["cluster"]["id"], "https")
    db.execute("UPDATE frontends SET cert_id = ? WHERE id = ?", (first, fid))
    assert certmap.frontend_cert_ids() == {fid: [first]}

    certmap.save_frontend_certs(fid, [second, first, second])
    assert certmap.frontend_cert_ids() == {fid: [second, first]}
    assert db.one("SELECT cert_id FROM frontends WHERE id = ?", (fid,))["cert_id"] == second

    certmap.save_frontend_certs(fid, [])
    assert certmap.frontend_cert_ids() == {}
    assert db.one("SELECT cert_id FROM frontends WHERE id = ?", (fid,))["cert_id"] is None


def test_deleting_certificate_removes_its_links(env, cluster):
    db = env["db"]
    cid = cluster["cluster"]["id"]
    first, second = _cert(db, "first.example.com"), _cert(db, "second.example.com")
    fid = _frontend(db, cid, "https")
    bid = _backend(db, cid, "web")
    certmap.save_frontend_certs(fid, [first, second])
    certmap.save_backend_certs(bid, [second])

    db.execute("DELETE FROM certificates WHERE id = ?", (second,))
    assert certmap.frontend_cert_ids() == {fid: [first]}
    assert certmap.backend_cert_ids() == {}

    db.execute("DELETE FROM certificates WHERE id = ?", (first,))
    assert certmap.frontend_cert_ids() == {}
    assert db.one("SELECT cert_id FROM frontends WHERE id = ?", (fid,))["cert_id"] is None


def test_usage_and_effective_certificates(env, cluster):
    db = env["db"]
    cid = cluster["cluster"]["id"]
    own, web_cert, api_cert, unused_cert, plain_cert = (
        _cert(db, name)
        for name in ("own", "web-cert", "api-cert", "unused-cert", "plain-cert")
    )
    web, api, other = (_backend(db, cid, name) for name in ("web", "api", "other"))
    certmap.save_backend_certs(web, [web_cert])
    certmap.save_backend_certs(api, [api_cert])
    certmap.save_backend_certs(other, [unused_cert])
    https = _frontend(
        db, cid, "https", default_backend_id=web,
        rules='[{"backend": "api", "condition": "host_api"}]',
    )
    certmap.save_frontend_certs(https, [own])
    plain = _frontend(db, cid, "plain", use_ssl=False)
    certmap.save_frontend_certs(plain, [plain_cert])

    [frontend] = certmap.ssl_frontends(cid)
    assert frontend["cert_ids"] == [own]
    assert frontend["effective_cert_ids"] == [own, web_cert, api_cert]
    assert certmap.used_cert_ids(cid) == {own, web_cert, api_cert}
    assert certmap.clusters_using_cert(api_cert) == [cid]
    assert certmap.clusters_using_cert(unused_cert) == []
    assert certmap.clusters_using_cert(plain_cert) == []

    usage = certmap.cert_usage()
    assert usage[own] == [{"type": "frontend", "id": https, "name": "https", "cluster": "Local"}]
    assert usage[web_cert] == [{"type": "backend", "id": web, "name": "web", "cluster": "Local"}]
    assert usage[plain_cert] == [
        {"type": "frontend", "id": plain, "name": "plain", "cluster": "Local"}
    ]


def test_backend_change_problems(env, cluster):
    db = env["db"]
    cid = cluster["cluster"]["id"]
    cert = _cert(db, "app.example.com")
    web = _backend(db, cid, "web")
    certmap.save_backend_certs(web, [cert])
    _frontend(db, cid, "by-default", default_backend_id=web)
    _frontend(db, cid, "by-rule", rules='[{"backend": "web", "condition": "host_web"}]')
    _frontend(db, cid, "no-ssl", use_ssl=False, default_backend_id=web)

    assert certmap.backend_change_problems(web, cid, "web", [cert]) == []
    assert certmap.backend_change_problems(web, cid, "web", []) == [
        "SSL-Frontend 'by-default' hätte danach kein Zertifikat mehr",
        "SSL-Frontend 'by-rule' hätte danach kein Zertifikat mehr",
    ]
    assert certmap.backend_change_problems(web, cid, "renamed", [cert]) == [
        "SSL-Frontend 'by-rule' hätte danach kein Zertifikat mehr",
    ]
    other_cluster = db.execute("INSERT INTO clusters (name) VALUES ('Other')")
    assert certmap.backend_change_problems(web, other_cluster, "web", [cert]) == [
        "SSL-Frontend 'by-default' hätte danach kein Zertifikat mehr",
        "SSL-Frontend 'by-rule' hätte danach kein Zertifikat mehr",
    ]


def test_backend_change_problems_respect_certificate_limit(env, cluster):
    db = env["db"]
    cid = cluster["cluster"]["id"]
    certs = [_cert(db, f"site{i}.example.com") for i in range(certmap.MAX_FRONTEND_CERTS + 1)]
    fid = _frontend(db, cid, "big", rules='[{"backend": "extra", "condition": "is_extra"}]')
    certmap.save_frontend_certs(fid, certs[:-1])

    # Neues Backend, auf das eine bestehende Regel bereits per Name verweist.
    assert certmap.backend_change_problems(None, cid, "extra", [certs[0]]) == []
    assert certmap.backend_change_problems(None, cid, "extra", [certs[-1]]) == [
        f"SSL-Frontend 'big' hätte danach {certmap.MAX_FRONTEND_CERTS + 1} Zertifikate"
        f" (maximal {certmap.MAX_FRONTEND_CERTS})",
    ]
