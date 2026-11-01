# HAProxy GUI

> **Hinweis:** Dieses Projekt wurde vollständig **KI-gestützt entwickelt** (GitHub Copilot,
> Modell: Kimi K3). Es ist Open Source – Beiträge und Fehlerberichte sind willkommen.

Web-Oberfläche zur Verwaltung von **HAProxy** mit **Multi-Cluster-Support** und automatischen
**Let's-Encrypt-Zertifikaten über DNS-Validierung (DNS-01)** – komplett in einem Docker-Container.

![CI](https://github.com/BartelLuis/haproxy-gui/actions/workflows/ci.yml/badge.svg)
![GHCR](https://github.com/BartelLuis/haproxy-gui/actions/workflows/publish.yml/badge.svg)
![Security](https://github.com/BartelLuis/haproxy-gui/actions/workflows/security.yml/badge.svg)
![CodeQL](https://github.com/BartelLuis/haproxy-gui/actions/workflows/codeql.yml/badge.svg)
![Coverage](https://github.com/BartelLuis/haproxy-gui/actions/workflows/coverage.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/BartelLuis/haproxy-gui)
![License](https://img.shields.io/github/license/BartelLuis/haproxy-gui)

> 📖 **Dokumentation:** Ausführliche Anleitungen findest du im **[Wiki](wiki/Home.md)** –
> [Installation](wiki/Installation.md) · [Quickstart](wiki/Getting-Started.md) ·
> [Host anlegen](wiki/Host-anlegen.md) · [Sicherheit & MFA](wiki/Sicherheit.md) ·
> [REST-API](wiki/API.md) · [Entwicklung](wiki/Entwicklung.md)

## Features

- **Multi-Cluster:** Beliebig viele HAProxy-Cluster mit je mehreren Nodes
  - Remote-Nodes werden per **SSH** verwaltet (Config-Push, Validierung, Reload)
  - Eingebetteter **Local-Cluster**: HAProxy läuft direkt im Container (optional)
- **Dual-Stack:** GUI und eingebetteter HAProxy lauschen über IPv4 und IPv6;
  Frontends können IPv4, IPv6 oder beide Familien verwenden; Server- und VIP-Felder
  akzeptieren IPv6-Literale
- **Konfigurations-Management:** Frontends (Binds, SSL, ACLs, `use_backend`-Regeln),
  Backends (Balance-Algorithmen, Health-Checks, Server) – daraus wird pro Node eine
  `haproxy.cfg` generiert
- **Sicheres Deploy:** Upload → `haproxy -c` Validierung auf dem Node → Backup der alten
  Config → Aktivierung → Reload (systemd / `haproxy -sf` / Docker / SIGUSR2)
- **Let's Encrypt via DNS-Validierung** über [lego](https://go-acme.github.io/lego/)
  (u. a. Cloudflare, Route53, DigitalOcean, **Hetzner Cloud**, Azure, DuckDNS, deSEC, IONOS,
  netcup, OVH, **Technitium DNS**, **manuelles DNS**)
  - Wildcard-Zertifikate möglich
  - **Mehrere Zertifikate pro Frontend (SNI):** HAProxy wählt das passende Zertifikat
    anhand des Hostnamens; Zertifikate lassen sich wie beim Nginx Proxy Manager auch
    direkt einem Backend zuordnen und werden dann von allen SSL-Frontends geladen,
    die auf dieses Backend weiterleiten
  - **Technitium DNS:** eigener DNS-Server via Webhook-Provider angebunden
    (Server-URL + API-Token)
  - **Manuelles DNS:** der TXT-Record wird in der GUI angezeigt, du legst ihn selbst
    in deiner DNS-Zone an und bestätigst per Klick
  - Automatische Erneuerung (< 30 Tage Restlaufzeit) und Verteilung auf die Nodes
    (bei manuellem DNS ohne Auto-Renew – dort erscheint die neue Challenge in der GUI)
  - Globale ACME-DNS-Resolver in der GUI konfigurierbar (Standard: `9.9.9.9`, `1.1.1.1`)
- **Live-Monitoring** über die HAProxy Runtime-API: Status aller Proxys/Server,
  Server zur Laufzeit aktivieren / drainen / in Wartung nehmen
- **Auth & Benutzerverwaltung:** mehrere Benutzer mit Rollen
  (`admin` / `operator` / `viewer`), PBKDF2-Passwort-Hashing, **MFA (TOTP)**,
  Session-Cookies + Bearer-Token, **API-Tokens** (`hg_…`) für CI/CD-Automatisierung,
  **LDAP / Active Directory Login** mit Gruppen→Rollen-Mapping,
  Login-Rate-Limiting, verschlüsselte Secrets in der DB, SSH-Host-Key-Verifizierung
- **Audit-Log:** alle Änderungen (Logins, Deploys, CRUD) nachvollziehbar
- **Config-Versionierung:** jeder Deploy wird versioniert (30 Versionen pro Node),
  Diff-Ansicht gegen die aktuelle Config, **Rollback** mit einem Klick
- **Logs-Viewer:** HAProxy-Logs pro Node (lokal aus Logdatei, remote via
  journalctl/syslog), mit Auto-Refresh
- **Alerts:** Webhook (Slack/Discord/Mattermost) und E-Mail (SMTP) bei
  Node-Ausfall/Wiederherstellung, ablaufenden Zertifikaten und Deploy-Fehlern
- **Runtime-Verwaltung:** Stick-Tables anzeigen/leeren, Map-Dateien anzeigen und
  Einträge zur Laufzeit hinzufügen/löschen
- **Node-Metriken:** CPU, Load, RAM und Disk pro Node (lokal via /proc, remote via SSH)
- **Keepalived/VRRP:** Hochverfügbarkeit mit virtueller IP – Config-Generierung,
  mehrere IPv4/IPv6-VIPs, Unicast-Peers, optionaler HAProxy-Health-Check, Deploy und
  Dienst-Status pro Node
- **HTTP-Rate-Limits:** Pro Frontend konfigurierbar; IPv6-Clients werden per `/64`
  zusammengefasst
- **Tools:** TCP-Port-Scanner und Config-Vergleich zwischen zwei Nodes eines Clusters

## Schnellstart

**Vorgefertigtes Image von GHCR** (wird bei jedem Push auf `main` gebaut, amd64 + arm64):

```bash
export ADMIN_PASSWORD='replace-with-a-strong-unique-password'

# Variante 1: Docker Compose (empfohlen) – nutzt das GHCR-Image, kein Build
docker compose up -d

# Variante 2: docker run
docker run -d --name haproxy-gui \
  -p 8080:8080 -p 80:80 -p 443:443 \
  -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  -v haproxy-gui-data:/data \
  ghcr.io/bartelluis/haproxy-gui:latest
```

**Oder selbst aus dem Quellcode bauen:**

```bash
docker compose -f docker-compose.build.yml up -d --build
```

GUI öffnen: <http://localhost:8080> (Login: `admin` / Wert von `ADMIN_PASSWORD`)

## Einfacher Reverse Proxy

Ein minimaler Reverse-Proxy kann mit einem Frontend und einem Backend aufgebaut werden:

```haproxy
frontend http_in
    bind *:80
    bind :::80 v6only
    mode http
    default_backend app_backend

backend app_backend
    mode http
    balance roundrobin
    option httpchk GET /
    server app1 127.0.0.1:8080 check
```

Das ist der klassische Grundaufbau für das Routing von HTTP-Anfragen auf einen internen Dienst wie eine Webanwendung oder API. In dieser GUI kannst du das über die Bereiche Frontends und Backends konfigurieren, ohne die Datei manuell zu bearbeiten.

Das Compose-Netzwerk aktiviert IPv6. Dafür muss der Docker-Host IPv6-Netzwerke
unterstützen und IPv6-Routing bereitstellen. Frontend-Binds in der GUI können
auf IPv4, IPv6 oder beide Familien gesetzt werden. Bei einem Docker-Setup ohne
IPv6-Unterstützung kann `enable_ipv6: true` im Compose-Netzwerk entfernt werden;
der GUI-Listener fällt dann auf die verfügbaren Socket-Familien zurück.
Für die GUI hinter einem Reverse-Proxy `TRUSTED_PROXIES` nur auf die tatsächlichen
Proxy-Netze setzen; andere `X-Forwarded-For`-Header werden beim Login ignoriert.

### Mehrere Backends per Host oder Pfad

Im Frontend-Dialog gibt es jetzt eine einfache URL-Routing-Funktion:

- `app.example.com` → Backend `app`
- `/admin` → Backend `admin`
- `api.example.com` + `/api` → Backend `api`

Damit lassen sich mehrere Backends mit unterschiedlichen URLs ohne manuelle ACLs konfigurieren. HAProxy erzeugt die dafür nötigen `use_backend`-Regeln automatisch.

### Backends mit SSL

Mit dem Haken **SSL** spricht HAProxy den Backend-Server per TLS an. Ohne
**Zert. prüfen** wird verschlüsselt, das Server-Zertifikat aber nicht geprüft
(`verify none`) – geeignet für interne Dienste mit selbstsignierten Zertifikaten.
Mit **Zert. prüfen** erzeugt die GUI:

```haproxy
server app1 app.example.com:443 check ssl verify required ca-file @system-ca sni str(app.example.com) verifyhost app.example.com check-ssl check-sni app.example.com
```

Dann muss der Host ein DNS-Name sein, dessen Zertifikat von einer System-CA des
Nodes signiert ist; `@system-ca` setzt HAProxy 2.6 oder neuer voraus.

## Umgebungsvariablen

| Variable                | Standard | Beschreibung                                   |
| ----------------------- | -------- | ---------------------------------------------- |
| `ADMIN_USER`            | `admin`  | Initialer Admin-Benutzer (weitere in der GUI)   |
| `ADMIN_PASSWORD`        | –        | Erforderlich für die Ersteinrichtung; muss ein starkes, individuelles Passwort sein |
| `APP_SECRET`            | automatisch | Optionaler Schlüssel für Sessions und verschlüsselte Secrets; ohne Angabe wird er dauerhaft unter `HG_DATA/app_secret` gespeichert |
| `GUI_PORT`              | `8080`   | Port des Web-Interfaces                         |
| `GUI_HOST`              | `""`     | Listen-Host; leer bindet IPv4 und IPv6, `0.0.0.0` nur IPv4 |
| `TRUSTED_PROXIES`       | leer     | Kommagetrennte Proxy-CIDRs, deren `X-Forwarded-For` vertraut wird |
| `ENABLE_API_DOCS`       | `false`  | Aktiviert interaktive API-Dokumentation unter `/docs` |
| `ENABLE_LOCAL_HAPROXY`  | `true`   | Eingebetteten HAProxy (Cluster „Local") starten |
| `HG_DATA`               | `/data`  | Datenverzeichnis (DB, Zertifikate, Config)      |
| `SSH_TCP_MAXSEG`        | `1024` unter Linux, sonst `0` | Maximale TCP-Segmentgröße für ausgehende SSH-Verbindungen; `0` deaktiviert die Begrenzung |

`TRUSTED_PROXIES` ist nur bei einem vorgeschalteten Reverse-Proxy zu setzen.
Trage ausschließlich dessen tatsächliche Netzbereiche ein, da diese Clients
`X-Forwarded-For` liefern dürfen. Der Container startet Uvicorn ohne dessen
automatische Proxy-Header-Umschreibung, damit die GUI diese Prüfung selbst
durchführen kann. Bei manuellem Uvicorn-Start ebenfalls `--no-proxy-headers`
verwenden.

## Rollen

| Rolle      | Rechte                                                        |
| ---------- | ------------------------------------------------------------- |
| `viewer`   | Nur lesen (Dashboard, Config-Vorschau, Logs, Stats)            |
| `operator` | Alles außer Benutzer-/Token-Verwaltung und Alert-Einstellungen |
| `admin`    | Vollzugriff                                                    |

## REST-API für Automatisierung

Unter **Benutzer → + API-Token** einen Token erzeugen und verwenden:

```bash
curl -H "Authorization: Bearer hg_…" http://localhost:8080/api/clusters
# Deploy auslösen:
curl -X POST -H "Authorization: Bearer hg_…" -H "Content-Type: application/json" \
  -

## LDAP / Active Directory Login

Unter **Benutzer → LDAP konfigurieren** (nur Admins) einrichten:

| Feld             | Beispiel (AD)                                              |
| ---------------- | ---------------------------------------------------------- |
| Server-URI       | `ldaps://dc01.firma.local:636`                              |
| Base-DN          | `dc=firma,dc=local`                                         |
| User-Filter      | `(&(objectClass=user)(sAMAccountName={username}))`          |
| Service-Bind-DN  | `cn=svc-haproxy,ou=service,dc=firma,dc=local`               |
| Gruppe → admin   | `cn=haproxy-admins,ou=groups,dc=firma,dc=local`             |
| Gruppe → operator| `cn=haproxy-ops,ou=groups,dc=firma,dc=local`                |

- Sind **Gruppen-DNs konfiguriert**, können sich nur Mitglieder dieser Gruppen anmelden
  (Rolle = passende Gruppe). Ohne Gruppen erhalten LDAP-Benutzer die **Standard-Rolle**.
- Lokale Benutzer (Tabelle „Benutzer") funktionieren weiterhin – LDAP ist ein Fallback,
  wenn kein lokaler Benutzer passt.
- `ldap://` ohne TLS-Prüfung oder `ldaps://` mit Zertifikatsprüfung (Haken „TLS") möglich.

## Tests & CI

Die Test-Suite ([tests/](tests/)) enthält Unit-Tests (Auth, Config-Generator, Services)
sowie HTTP-Integrationstests, die die App als echten Prozess starten:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

**GitHub Actions** ([ci.yml](.github/workflows/ci.yml)) führt bei jedem Push/PR aus:

1. **Tests** unter Python 3.11 und 3.13 (Compile-Check + pytest)
2. **Docker-Build** des Images mit Layer-Caching
3. **Container-Smoke-Test:** Container starten → GUI erreichbar → Login →
   Local-Cluster via API prüfen → eingebetteter HAProxy muss via Runtime-API antworten

**Image-Publishing** ([publish.yml](.github/workflows/publish.yml)) baut bei jedem Push
auf `main` und bei Tags `v*` ein Multi-Arch-Image (linux/amd64 + linux/arm64) und lädt
es nach **ghcr.io** hoch (`ghcr.io/bartelluis/haproxy-gui`). Tags: `latest`, Branch,
`sha-<kurz>`, und bei Releases `v1.2.3`, `1.2`, `1`. Es werden nur die Standard-
`GITHUB_TOKEN`-Rechte (`packages: write`) genutzt – kein zusätzliches Secret nötig.d '{"validate_only": false}' http://localhost:8080/api/clusters/1/deploy
```

## Remote-Nodes einbinden

Voraussetzungen auf dem Node:

1. **HAProxy** installiert
2. **SSH-Zugang** (Key oder Passwort) für einen Benutzer mit Schreibrecht auf die Config
3. **Runtime-Socket** in der `haproxy.cfg`:
   ```
   stats socket /var/run/haproxy/admin.sock mode 660 level admin
   ```
4. **socat** installiert (für Runtime-Befehle via SSH) – alternativ Socket-Typ `TCP` wählen
   und z. B. `stats socket ipv4@10.0.0.1:9999 level admin` bzw.
   `stats socket ipv6@2001:db8::1:9999 level admin` konfigurieren

Danach in der GUI unter **Cluster & Nodes** → *+ Node* die Verbindungsdaten eintragen
und mit *Test* prüfen. Der Runtime-Socket-Pfad wird in die generierte Config übernommen.

### Kleine SSH-Befehle funktionieren, größere Uploads laufen in einen Timeout

Bei größenabhängigen Übertragungsproblemen begrenzt die GUI unter Linux standardmäßig
die TCP-Segmentgröße ihrer ausgehenden SSH-Verbindungen auf `1024` Bytes. Das gilt
für Befehle und Dateiübertragungen einschließlich SFTP. Die Einstellung wirkt pro
Verbindung; die MTU des Docker-Netzwerks oder Hosts wird dabei nicht geändert.
Ein erfolgreicher Test mit kleineren Segmenten grenzt das Problem auf größenabhängiges
Transportverhalten ein, beweist aber keine fehlerhafte Path-MTU-Erkennung als Ursache.

Mit `SSH_TCP_MAXSEG` lässt sich der Wert anpassen; `SSH_TCP_MAXSEG: "0"` im
`environment`-Abschnitt von Compose deaktiviert die Begrenzung. Ohne eigenen Eintrag
gilt der Standard automatisch. TCP kann wegen zusätzlicher TCP-Optionen beispielsweise
`1012` statt `1024` melden. Kleinere Segmente können den Durchsatz verringern.
Hintergrund: [Linux-Dokumentation zu TCP_MAXSEG](https://man7.org/linux/man-pages/man7/tcp.7.html).

Damit die Korrektur aktiv wird, das aktualisierte Image laden und den Container
neu erstellen:

```bash
docker compose pull
docker compose up -d --force-recreate
```

Bei lokalem Build stattdessen
`docker compose -f docker-compose.build.yml up -d --build --force-recreate` verwenden.
Auch geänderte Compose-Umgebungsvariablen erfordern ein Neuerstellen des Containers;
ein einfacher `docker compose restart` übernimmt weder ein neues Image noch diese Änderungen.

### Reload-Kommando (pro Node konfigurierbar)

| Umgebung            | Kommando                                                        |
| ------------------- | --------------------------------------------------------------- |
| systemd             | `systemctl reload haproxy` (Standard-Fallback)                  |
| Prozess             | `haproxy -D -f /etc/haproxy/haproxy.cfg -sf $(pidof haproxy)`   |
| Docker-Container    | `docker kill -s HUP haproxy`                                    |
| Master-Worker (-W)  | `sigusr2` (wird zu `kill -USR2 $(cat /run/haproxy/master.pid)`) |

## Zertifikate (DNS-01)

1. **Zertifikate → + Neues Zertifikat**
2. Domains eintragen (Wildcard `*.example.com` möglich), DNS-Provider wählen und die
   benötigten API-Credentials eintragen (z. B. Cloudflare: `CLOUDFLARE_DNS_API_TOKEN`)
3. Die Ausstellung läuft im Hintergrund (DNS-Propagation: ca. 1–2 Minuten)
4. Das Zertifikat einem SSL-Frontend oder einem Backend zuordnen
   (siehe [Mehrere Zertifikate (SNI)](#mehrere-zertifikate-sni)) und die Config deployen –
   Zertifikat und Schlüssel werden als `.crt` und `.key` auf die Nodes kopiert (`cert_dir`).
   Zusätzlich wird eine `.pem`-Datei mit Zertifikat und Schlüssel atomar aktualisiert,
   damit bestehende HAProxy-Konfigurationen mit diesem Dateipfad weiterhin funktionieren.
   Alle drei Dateien erhalten die Dateirechte `600`.
5. **Auto-Renew** erneuert Zertifikate ab < 30 Tagen Restlaufzeit und verteilt sie neu

### Mehrere Zertifikate (SNI)

Ein SSL-Frontend kann mehrere Zertifikate laden. HAProxy liefert per SNI jeweils das
Zertifikat aus, das zum angefragten Hostnamen passt (auch Wildcards):

- **Frontend → Zertifikate (SNI):** eigene Zertifikate in beliebiger Reihenfolge.
  Das erste ist das Standard-Zertifikat für Clients ohne oder mit unbekanntem Hostnamen.
- **Backend → Zertifikate (SNI):** Wie beim Nginx Proxy Manager gehört das Zertifikat
  zum Dienst. Jedes SSL-Frontend, das auf das Backend weiterleitet (Default-Backend oder
  `use_backend`-Regel mit Bedingung), lädt dessen Zertifikate automatisch und braucht
  dann kein eigenes Zertifikat. Diese Zertifikate werden den Clients präsentiert; die
  Verbindung zu den Servern steuert weiterhin [Backends mit SSL](#backends-mit-ssl).
- Reihenfolge auf der `bind`-Zeile: eigene Zertifikate, dann die des Default-Backends,
  dann die der Regel-Backends; doppelte Zuordnungen werden nur einmal geladen. Backends,
  die nur über „Zusätzliche Zeilen“ angesprochen werden, werden nicht berücksichtigt.
- Pro Frontend sind insgesamt höchstens **25 Zertifikate** möglich, weil HAProxy maximal
  64 Wörter pro Konfigurationszeile verarbeitet. Änderungen, nach denen ein SSL-Frontend
  kein Zertifikat mehr hätte oder das Limit überschreiten würde, werden abgelehnt.
- Die Spalte **Verwendet in** auf der Zertifikatsseite zeigt alle Zuordnungen. Beim
  Löschen eines Zertifikats werden diese entfernt.

```haproxy
bind *:443 ssl crt /etc/haproxy/certs/example.com.crt crt /etc/haproxy/certs/shop.example.org.crt alpn h2,http1.1
```

### DNS-Server für ACME

Unter **Zertifikate → DNS-Server** können Administratoren die globalen DNS-Resolver
ändern. Standardmäßig werden `9.9.9.9:53` und `1.1.1.1:53` verwendet, auch bei
bestehenden Installationen ohne gespeicherte ACME-DNS-Einstellung.
IPv4- und IPv6-Adressen sind möglich, optional mit Port, z. B. `9.9.9.9:5353`
oder `[2620:fe::fe]:53`. Mehrere Server können durch Zeilenumbrüche, Leerzeichen,
Kommas oder Semikolons getrennt werden; ohne Port gilt `53`.

Die Einstellung wird in der Datenbank gespeichert und gilt ab der nächsten
Ausstellung oder Erneuerung für alle DNS-Provider, einschließlich Technitium und
manuellem DNS. Ein leeres Feld aktiviert wieder die Standard-Resolver von lego
(System-DNS, ersatzweise Google-DNS, wenn keine System-Resolver ermittelt werden).
Laufende Ausstellungen werden nicht umgestellt.

Die Server werden über `lego --dns.resolvers` für rekursive DNS-Abfragen verwendet,
etwa zur CNAME-Auflösung und Ermittlung der DNS-Zone. Die autoritativen
Propagationsprüfungen und die unabhängige DNS-Validierung durch Let's Encrypt
bleiben unverändert.

### Zertifikate auf Nodes übertragen

Zertifikate und Konfigurationen werden über den normalen SSH-Kanal übertragen.
Die Zieldatei wird erst ersetzt, nachdem Dateigröße und SHA-256 der temporären
Datei geprüft wurden. Auf den Nodes werden dafür `sh`, `mktemp`, `cat`, `wc`,
`sha256sum`, `chmod`, `stat`, `mv` und `rm` benötigt.

Weitere lego-Provider lassen sich in [app/services/certs.py](app/services/certs.py)
(`PROVIDERS`) ergänzen – lego unterstützt
[über 100 DNS-Provider](https://go-acme.github.io/lego/dns/).

## Lokale Entwicklung (ohne Docker)

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
$env:HG_DATA = "./data"       # Windows PowerShell
$env:ADMIN_PASSWORD = "replace-with-a-strong-unique-password"
uvicorn app.main:app --reload --port 8080
```

Für Zertifikats-Ausstellung muss `lego` im `PATH` liegen (unter Windows z. B. als
`lego.exe` aus den GitHub-Releases).

## Sicherheitshinweise

- `ADMIN_PASSWORD` ändern und die GUI nicht ungeschützt ins Internet stellen
  (z. B. hinter ein eigenes TLS-Frontend legen)
- Das `/data`-Volume sichern und nicht löschen: Es enthält auch den automatisch
  generierten Anwendungsschlüssel für Sessions und verschlüsselte Secrets.
- SSH-Keys und DNS-Credentials liegen in `/data/haproxy-gui.db` – Volume schützen
- Der TCP-Stats-Socket hat keine Authentifizierung – nur an interne/localhost-Adressen binden
