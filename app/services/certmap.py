"""Zuordnung von Zertifikaten zu Frontends und Backends (SNI).

Ein SSL-Frontend lädt seine eigenen Zertifikate und zusätzlich die Zertifikate
aller Backends, an die es weiterleitet (Default-Backend und use_backend-Regeln).
HAProxy wählt anhand der SNI das passende Zertifikat; das erste ist das
Standard-Zertifikat für Clients ohne bzw. mit unbekannter SNI.
"""

import json

from .. import db as dbmod

# HAProxy erlaubt höchstens 64 Wörter pro Konfigurationszeile; jedes Zertifikat
# belegt auf der bind-Zeile zwei davon ("crt <pfad>").
MAX_FRONTEND_CERTS = 25

_FRONTEND_CERTS_SQL = (
    "SELECT fc.frontend_id AS owner_id, fc.cert_id, fc.position"
    " FROM frontend_certs fc JOIN frontends f ON f.id = fc.frontend_id"
    " WHERE ? IS NULL OR f.cluster_id = ?"
    " UNION ALL"
    # Frontends aus älteren Versionen kennen nur frontends.cert_id.
    " SELECT f.id, f.cert_id, 0 FROM frontends f"
    " WHERE f.cert_id IS NOT NULL AND (? IS NULL OR f.cluster_id = ?)"
    " AND NOT EXISTS (SELECT 1 FROM frontend_certs fc WHERE fc.frontend_id = f.id)"
    " ORDER BY owner_id, position, cert_id"
)
_BACKEND_CERTS_SQL = (
    "SELECT bc.backend_id AS owner_id, bc.cert_id, bc.position"
    " FROM backend_certs bc JOIN backends b ON b.id = bc.backend_id"
    " WHERE ? IS NULL OR b.cluster_id = ?"
    " ORDER BY owner_id, position, cert_id"
)


def unique_ids(ids):
    return list(dict.fromkeys(ids))


def _grouped(rows):
    result = {}
    for row in rows:
        result.setdefault(row["owner_id"], []).append(row["cert_id"])
    return result


def frontend_cert_ids(cluster_id=None):
    """{frontend_id: [cert_id, ...]} – eigene Zertifikate, das erste ist der Standard."""
    return _grouped(dbmod.q(_FRONTEND_CERTS_SQL, (cluster_id,) * 4))


def backend_cert_ids(cluster_id=None):
    """{backend_id: [cert_id, ...]} in gespeicherter Reihenfolge."""
    return _grouped(dbmod.q(_BACKEND_CERTS_SQL, (cluster_id,) * 2))


def save_frontend_certs(frontend_id, cert_ids):
    cert_ids = unique_ids(cert_ids)
    conn = dbmod.get_db()
    with conn:
        conn.execute("DELETE FROM frontend_certs WHERE frontend_id = ?", (frontend_id,))
        conn.executemany(
            "INSERT INTO frontend_certs (frontend_id, cert_id, position) VALUES (?, ?, ?)",
            [(frontend_id, cert_id, pos) for pos, cert_id in enumerate(cert_ids)],
        )
        # frontends.cert_id spiegelt das Standard-Zertifikat für ältere Versionen.
        conn.execute(
            "UPDATE frontends SET cert_id = ? WHERE id = ?",
            (cert_ids[0] if cert_ids else None, frontend_id),
        )


def save_backend_certs(backend_id, cert_ids):
    cert_ids = unique_ids(cert_ids)
    conn = dbmod.get_db()
    with conn:
        conn.execute("DELETE FROM backend_certs WHERE backend_id = ?", (backend_id,))
        conn.executemany(
            "INSERT INTO backend_certs (backend_id, cert_id, position) VALUES (?, ?, ?)",
            [(backend_id, cert_id, pos) for pos, cert_id in enumerate(cert_ids)],
        )


def routed_backend_ids(default_backend_id, rules, backends):
    """Backends (desselben Clusters), an die ein Frontend weiterleitet."""
    ids_by_name = {b["name"]: b["id"] for b in backends}
    routed = [default_backend_id] if default_backend_id in ids_by_name.values() else []
    if isinstance(rules, str):
        try:
            rules = json.loads(rules or "[]")
        except ValueError:
            rules = []
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        name = str(rule.get("backend") or "").strip()
        # Wie in configgen: Regeln ohne Bedingung erzeugen kein use_backend.
        if name in ids_by_name and str(rule.get("condition") or "").strip():
            routed.append(ids_by_name[name])
    return unique_ids(routed)


def effective_cert_ids(own_ids, backend_ids, backend_certs):
    """Eigene Zertifikate zuerst, danach die der Backends – ohne Duplikate."""
    inherited = [cid for bid in backend_ids for cid in backend_certs.get(bid, [])]
    return unique_ids([*own_ids, *inherited])


def _backends_by_cluster(cluster_id=None):
    result = {}
    for b in dbmod.q(
        "SELECT id, cluster_id, name FROM backends WHERE ? IS NULL OR cluster_id = ?",
        (cluster_id, cluster_id),
    ):
        result.setdefault(b["cluster_id"], []).append(b)
    return result


def annotate_frontends(frontends, cluster_id=None):
    """Ergänzt cert_ids (eigene), cert_id (Standard) und effective_cert_ids."""
    own = frontend_cert_ids(cluster_id)
    backend_certs = backend_cert_ids(cluster_id)
    backends = _backends_by_cluster(cluster_id)
    for fe in frontends:
        fe["cert_ids"] = own.get(fe["id"], [])
        fe["cert_id"] = fe["cert_ids"][0] if fe["cert_ids"] else None
        fe["effective_cert_ids"] = effective_cert_ids(
            fe["cert_ids"],
            routed_backend_ids(
                fe.get("default_backend_id"),
                fe.get("rules"),
                backends.get(fe["cluster_id"], []),
            ),
            backend_certs,
        )
    return frontends


def ssl_frontends(cluster_id=None):
    frontends = dbmod.q(
        "SELECT id, cluster_id, name, default_backend_id, rules FROM frontends"
        " WHERE use_ssl = 1 AND (? IS NULL OR cluster_id = ?) ORDER BY name",
        (cluster_id, cluster_id),
    )
    return annotate_frontends(frontends, cluster_id)


def used_cert_ids(cluster_id):
    """Alle Zertifikate, die SSL-Frontends des Clusters laden."""
    return {cid for fe in ssl_frontends(cluster_id) for cid in fe["effective_cert_ids"]}


def clusters_using_cert(cert_id):
    return sorted(
        {fe["cluster_id"] for fe in ssl_frontends() if cert_id in fe["effective_cert_ids"]}
    )


def cert_usage():
    """{cert_id: [{type, id, name, cluster}, ...]} – direkte Zuordnungen."""
    usage = {}
    owners = (
        (
            "frontend",
            frontend_cert_ids(),
            "SELECT f.id, f.name, c.name AS cluster FROM frontends f"
            " JOIN clusters c ON c.id = f.cluster_id ORDER BY c.name, f.name",
        ),
        (
            "backend",
            backend_cert_ids(),
            "SELECT b.id, b.name, c.name AS cluster FROM backends b"
            " JOIN clusters c ON c.id = b.cluster_id ORDER BY c.name, b.name",
        ),
    )
    for kind, links, sql in owners:
        for row in dbmod.q(sql):
            for cert_id in links.get(row["id"], []):
                usage.setdefault(cert_id, []).append(
                    {"type": kind, "id": row["id"], "name": row["name"],
                     "cluster": row["cluster"]}
                )
    return usage


def backend_change_problems(backend_id, cluster_id, name, cert_ids):
    """Prüft SSL-Frontends, die durch eine Backend-Änderung ihr letztes Zertifikat
    verlieren oder das Zertifikatslimit überschreiten würden."""
    old = (
        dbmod.one("SELECT cluster_id FROM backends WHERE id = ?", (backend_id,))
        if backend_id
        else None
    )
    affected = {cluster_id} | ({old["cluster_id"]} if old else set())
    placeholder_id = backend_id or 0
    problems = []
    for cid in sorted(affected):
        frontends = ssl_frontends(cid)
        if not frontends:
            continue
        backends = _backends_by_cluster(cid).get(cid, [])
        certs_before = backend_cert_ids(cid)
        backends_after = [b for b in backends if b["id"] != backend_id]
        certs_after = dict(certs_before)
        if cid == cluster_id:
            backends_after.append({"id": placeholder_id, "name": name})
            certs_after[placeholder_id] = unique_ids(cert_ids)
        for fe in frontends:
            after = effective_cert_ids(
                fe["cert_ids"],
                routed_backend_ids(fe["default_backend_id"], fe["rules"], backends_after),
                certs_after,
            )
            before = fe["effective_cert_ids"]
            if before and not after:
                problems.append(
                    f"SSL-Frontend '{fe['name']}' hätte danach kein Zertifikat mehr"
                )
            elif len(after) > MAX_FRONTEND_CERTS and len(after) > len(before):
                problems.append(
                    f"SSL-Frontend '{fe['name']}' hätte danach {len(after)} Zertifikate"
                    f" (maximal {MAX_FRONTEND_CERTS})"
                )
    return problems
