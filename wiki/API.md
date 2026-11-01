# REST-API Referenz

Alle Endpunkte unter `/api`. Authentifizierung per `Authorization: Bearer hg_<token>`
(API-Token) oder per Session-Cookie nach Login.

## Authentifizierung

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| POST | `/api/auth/login` | Login `{username, password, totp?}` → `{token, role}` |
| POST | `/api/auth/logout` | Cookie löschen |
| GET | `/api/auth/me` | Aktueller Benutzer |

## Cluster & Nodes

| Methode | Pfad | Rolle | Beschreibung |
|---------|------|-------|--------------|
| GET | `/api/clusters` | viewer+ | Alle Cluster inkl. Nodes |
| POST/PUT/DELETE | `/api/clusters[/{id}]` | operator+ | Cluster verwalten |
| POST/PUT/DELETE | `/api/nodes[/{id}]` | **admin** | Nodes verwalten |
| POST | `/api/nodes/{id}/test` | operator+ | Verbindungstest |
| GET | `/api/clusters/{id}/config` | viewer+ | Generierte Config |
| POST | `/api/clusters/{id}/deploy` | operator+ | `{validate_only, node_ids?}` |

## Frontends & Backends

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET/POST/PUT/DELETE | `/api/frontends[/{id}]` | Frontends (Binds, SSL, Zertifikate `cert_ids`, ACLs, Regeln) |
| GET/POST/PUT/DELETE | `/api/backends[/{id}]` | Backends inkl. Server (`ssl`, `ssl_verify`: CA- und Hostname-Prüfung, nur mit `ssl` und DNS-Hostname) und Zertifikaten (`cert_ids`) |

`cert_ids` ist eine geordnete Liste von Zertifikats-IDs (SNI); beim Frontend ist das
erste Zertifikat der Standard. `GET /api/frontends` liefert zusätzlich
`effective_cert_ids`: alle Zertifikate, die das Frontend lädt, inklusive derer seiner
Backends (Default-Backend und `use_backend`-Regeln mit Bedingung). Das ältere Feld
`cert_id` bleibt kompatibel: Ohne `cert_ids` ersetzt es nur das Standard-Zertifikat,
weitere Zertifikate bleiben erhalten. Fehlt `cert_ids` beim Bearbeiten eines Backends,
bleibt dessen Zuordnung unverändert. Pro Frontend sind inklusive Backend-Zertifikaten
höchstens 25 Zertifikate möglich; Änderungen, nach denen ein SSL-Frontend kein
Zertifikat mehr hätte, werden mit `400` abgelehnt.

## Zertifikate

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/dns-providers` | Verfügbare DNS-Provider |
| GET | `/api/acme/settings` | Globale DNS-Resolver lesen (viewer+) |
| PUT | `/api/acme/settings` | Globale DNS-Resolver ändern (nur admin), `{dns_resolvers: [...]}` |
| GET/POST/DELETE | `/api/certificates[/{id}]` | Zertifikate lesen/löschen, mit `POST` über Let's Encrypt DNS-01 anlegen; `GET` liefert `source` (`acme`/`imported`) und in `used_by` die zugeordneten Frontends und Backends |
| POST | `/api/certificates/import` | PEM oder PFX/P12 importieren (operator+), liefert `{id}` |
| PUT | `/api/certificates/{id}/import` | Importiertes Zertifikat ersetzen (operator+), liefert `{ok: true}`; ID, Name und Zuordnungen bleiben erhalten |
| POST | `/api/certificates/{id}/renew` | Let's-Encrypt-Zertifikat erneuern; für importierte Zertifikate nicht verfügbar |
| PUT | `/api/certificates/{id}/auto-renew` | `{auto_renew: bool}`; für importierte Zertifikate nicht aktivierbar |
| POST | `/api/certificates/{id}/deploy` | Auf Nodes verteilen |
| GET | `/api/certificates/{id}/challenge` | Manuelle DNS-Challenge lesen |
| POST | `/api/certificates/{id}/confirm` | Manuelle DNS bestätigen |

### Import

Beide Import-Endpunkte erwarten JSON. Beim Anlegen zusätzlich `name` angeben;
beim Ersetzen ist der bestehende Name unveränderlich.

- **PEM:** `format: "pem"` (Standard), `certificate_pem` (Zertifikat/Fullchain),
  `private_key_pem` (entfällt bei kombiniertem PEM), optional `chain_pem` und `password`.
- **PFX/PKCS#12:** `format: "pkcs12"`, `pkcs12_base64` (Base64 des binären Dateiinhalts),
  optional `password`. Nicht mit PEM-Feldern kombinieren.

Domains (DNS-/IP-SAN, CN nur ohne SAN) und `not_after` werden aus dem Zertifikat
gelesen; `source` ist `imported`, `status` ist `active`, `auto_renew` ist `false`.
Zertifikatsmaterial und Schlüssel müssen zusammenpassen und zum Importzeitpunkt
gültig sein. Mitgelieferte Zwischenzertifikate werden geordnet und ihre
Ausstellersignaturen geprüft; identische Zertifikate werden dedupliziert.
Maximal 1 MiB PEM-Material insgesamt bzw. 1 MiB dekodierte PFX/P12-Daten und
32 Zertifikate inklusive Kette. Ungültige Importe werden mit `400` abgelehnt,
ohne bestehende Zertifikate zu verändern.

Import-Passwörter werden nicht gespeichert, private Schlüssel verschlüsselt
gespeichert und nicht über `GET` zurückgegeben. Import und Ersetzen lösen **kein**
Deployment aus; danach `/api/certificates/{id}/deploy` bzw. den Cluster-Deploy
aufrufen. Bestehende Let's-Encrypt-Einträge lassen sich nicht per Import überschreiben.
`renew`, das Aktivieren von Auto-Renew und DNS-Challenges werden für importierte
Zertifikate mit `400` abgelehnt.

### ACME-DNS-Resolver

`dns_resolvers` ist eine Liste von IPv4-/IPv6-Adressen mit optionalem Port,
z. B. `{"dns_resolvers": ["9.9.9.9", "1.1.1.1", "[2620:fe::fe]:53"]}`.
IPv6 mit Port muss als `[Adresse]:Port` angegeben werden; ohne Port sind die
Klammern optional. Ports bestehen nur aus ASCII-Ziffern und liegen zwischen 1 und 65535.
Ohne gespeicherte Einstellung gelten `9.9.9.9:53` und `1.1.1.1:53`.
Die API ergänzt Port `53`, normalisiert IP-Adressen und entfernt doppelte Einträge.
Eine leere Liste nutzt wieder die Standard-Resolver von lego. Änderungen werden
dauerhaft gespeichert und gelten für die nächste Ausstellung oder Erneuerung,
auch bei manuellem DNS; ungültige Adressen oder Ports werden zurückgewiesen.
Die autoritativen DNS-Prüfungen und die Validierung durch Let's Encrypt bleiben unverändert.

## Monitoring & Runtime

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/overview` | Cluster + Node-Status |
| GET | `/api/stats/nodes/{id}/stat` | HAProxy-Statistiken (`show stat`-Felder; `type` numerisch, zusätzlich `type_name`: frontend/backend/server/listener) |
| POST | `/api/stats/nodes/{id}/server-state` | Server ready/drain/maint (502 mit HAProxy-Meldung bei Fehler) |
| GET | `/api/stats/nodes/{id}/tables` | Stick-Tables |
| GET/POST | `/api/stats/nodes/{id}/maps…` | Maps lesen/bearbeiten |
| GET | `/api/logs/nodes/{id}?lines=N` | HAProxy-Logs |
| GET | `/api/nodes/{id}/metrics` | CPU/RAM/Disk |

## Versionen & Config

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/clusters/{id}/versions` | Deploy-Historie |
| GET | `/api/versions/{id}` | Config-Inhalt |
| GET | `/api/versions/{id}/diff?other=N` | Diff |
| POST | `/api/versions/{id}/rollback` | Rollback |
| GET | `/api/tools/compare?…` | Config zweier Nodes vergleichen |

## Benutzer, MFA, LDAP, Alerts (admin)

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET/POST/PUT/DELETE | `/api/users[/{id}]` | Benutzerverwaltung |
| GET/POST/DELETE | `/api/tokens[/{id}]` | API-Tokens |
| GET | `/api/audit` | Audit-Log |
| POST | `/api/users/me/mfa/setup` | MFA-Setup starten (QR + Secret) |
| POST | `/api/users/me/mfa/confirm` | MFA aktivieren `{code}` |
| POST | `/api/users/me/mfa/disable` | MFA deaktivieren `{code}` |
| GET/PUT | `/api/ldap/settings` | LDAP/AD konfigurieren |
| GET/PUT | `/api/alerts/settings` | Alerts (Webhook/SMTP) |

## Beispiel: Deploy per CI

```bash
TOKEN="hg_…"
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"validate_only":false}' \
  http://localhost:8080/api/clusters/1/deploy
```
