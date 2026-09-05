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
| GET/POST/PUT/DELETE | `/api/frontends[/{id}]` | Frontends (Binds, SSL, ACLs, Regeln) |
| GET/POST/PUT/DELETE | `/api/backends[/{id}]` | Backends inkl. Server |

## Zertifikate

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/dns-providers` | Verfügbare DNS-Provider |
| GET/POST/DELETE | `/api/certificates[/{id}]` | Zertifikate (Let's Encrypt DNS-01) |
| POST | `/api/certificates/{id}/renew` | Erneuern |
| POST | `/api/certificates/{id}/deploy` | Auf Nodes verteilen |
| GET | `/api/certificates/{id}/challenge` | Manuelle DNS-Challenge lesen |
| POST | `/api/certificates/{id}/confirm` | Manuelle DNS bestätigen |

## Monitoring & Runtime

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/overview` | Cluster + Node-Status |
| GET | `/api/stats/nodes/{id}/stat` | HAProxy-Statistiken |
| POST | `/api/stats/nodes/{id}/server-state` | Server ready/drain/maint |
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
