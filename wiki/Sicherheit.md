# Sicherheit & Härtung

Das Tool steuert Server, die im Internet erreichbar sind. Diese Seite beschreibt die
eingebauten Schutzmechanismen und empfohlene Maßnahmen für den produktiven Betrieb.

## Eingebaute Schutzmechanismen

| Bereich | Maßnahme |
|---------|----------|
| **Authentifizierung** | PBKDF2-gehashte Passwörter, optionale **MFA (TOTP)**, Rollen (admin/operator/viewer) |
| **Login-Schutz** | Rate-Limiting (5 Versuche / 5 Min → 5 Min Sperre), Audit aller Login-Ereignisse |
| **Sessions** | HMAC-signierte Tokens, `HttpOnly` + `SameSite=Lax`, `Secure` bei HTTPS, 12 h TTL |
| **SSH** | Host-Key-Verifizierung (TOFU, `/data/known_hosts`), MITM-Erkennung, Keys/Passwörter verschlüsselt in der DB |
| **Secrets** | SSH-Keys, DNS-Credentials, SMTP-/LDAP-Passwörter mit Fernet verschlüsselt (Master-Key `/data/secret.key`, `0600`) |
| **Injection-Schutz** | Serverseitige Validierung aller Namen/Pfade/Hosts; Shell-Quoting; kein `shell=True` mehr lokal |
| **Runtime-Socket** | TCP-Socket bindet nicht auf `*`, sondern auf die angegebene/Loopback-Adresse; `level operator` |
| **API-Tokens** | `hg_…`-Tokens mit eigener Rolle, nur Hash gespeichert |
| **Audit-Log** | Alle Schreibaktionen, Logins und Fehlversuche nachvollziehbar |

## Empfehlungen für den Produktivbetrieb

1. **TLS zwingend verwenden.** Die GUI selbst spricht HTTP – stelle sie hinter einen
   Reverse-Proxy mit TLS (z. B. den eingebetteten HAProxy selbst, Caddy oder Nginx)
   oder nutze SSH-Port-Forwarding. Ohne TLS laufen Passwörter und Session-Tokens im
   Klartext.
2. **ADMIN_PASSWORD setzen** und das Default-Passwort `admin` sofort ändern.
3. **MFA aktivieren** für alle Benutzer (siehe unten).
4. **Kleinste Rechte:** Node-Verwaltung/Deploy ist `admin`-only; vergib `operator`/`viewer`
   für reine Lese-/Betriebsaufgaben.
5. **Volume `/data` schützen:** enthält DB und Master-Key. Dateirechte `0600`, Backup
   verschlüsseln, Zugriff auf den Host beschränken.
6. **SSH:** dedizierten Benutzer mit eingeschränkten `sudo`-Rechten verwenden
   (nur `haproxy`-Reload), Passwort-Auth auf den Nodes deaktivieren, Key-Auth erzwingen.
7. **Netz:** Die GUI-Port (8080) nicht direkt öffentlich exponieren – Firewall/VPN/Proxy.
8. **TCP-Runtime-Socket:** nur auf Loopback/Management-IP binden, nie auf `0.0.0.0`.

## MFA (Zwei-Faktor) einrichten

1. Einloggen → unten links **Mein Konto** → **MFA einrichten**
2. QR-Code mit einer Authenticator-App scannen (Aegis, Bitwarden, Google Authenticator, …)
   oder das Secret manuell eingeben
3. Den 6-stelligen Code eingeben und **Aktivieren**
4. Ab jetzt verlangt der Login Benutzername + Passwort + aktuellen TOTP-Code

MFA gilt für lokale Benutzer. LDAP-Benutzer werden über das LDAP/AD abgesichert
(dort ggf. MFA auf IdP-Seite erzwingen).

## Sicherheitsaudit

Der Code wurde einem Security-Review unterzogen; die wichtigsten behobenen Punkte:

- SSH-MITM durch fehlende Host-Key-Prüfung → **TOFU-Verifizierung** implementiert
- Command-Injection über Node-Felder (`config_path`, `reload_cmd`, …) → **Validierung + Quoting**
- Path-Traversal über Zertifikatsnamen → **Pfad-Sandbox** (`_safe_path`)
- Runtime-Admin-Socket offen auf `0.0.0.0` → **Loopback/Operator-Level**
- Kein Login-Rate-Limit → **Rate-Limiting + Lockout + Audit**
- Secrets im Klartext → **Fernet-Verschlüsselung** in der DB

Gefundene Schwachstellen bitte als Issue melden.
