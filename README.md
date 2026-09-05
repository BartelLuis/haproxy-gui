# HAProxy GUI

> **Hinweis:** Dieses Projekt wurde vollständig **KI-gestützt entwickelt** (GitHub Copilot,
> Modell: Kimi K3). Es ist Open Source – Beiträge und Fehlerberichte sind willkommen.

Web-Oberfläche zur Verwaltung von **HAProxy** mit **Multi-Cluster-Support** und automatischen
**Let's-Encrypt-Zertifikaten über DNS-Validierung (DNS-01)** – komplett in einem Docker-Container.

![CI](https://github.com/BartelLuis/haproxy-gui/actions/workflows/ci.yml/badge.svg)

![Architektur](docs/architektur.png)

## Features

- **Multi-Cluster:** Beliebig viele HAProxy-Cluster mit je mehreren Nodes
  - Remote-Nodes werden per **SSH** verwaltet (Config-Push, Validierung, Reload)
  - Eingebetteter **Local-Cluster**: HAProxy läuft direkt im Container (optional)
- **Konfigurations-Management:** Frontends (Binds, SSL, ACLs, `use_backend`-Regeln),
  Backends (Balance-Algorithmen, Health-Checks, Server) – daraus wird pro Node eine
  `haproxy.cfg` generiert
- **Sicheres Deploy:** Upload → `haproxy -c` Validierung auf dem Node → Backup der alten
  Config → Aktivierung → Reload (systemd / `haproxy -sf` / Docker / SIGUSR2)
- **Let's Encrypt via DNS-Validierung** über [lego](https://go-acme.github.io/lego/)
  (u. a. Cloudflare, Route53, DigitalOcean, Hetzner, Azure, DuckDNS, deSEC, IONOS, netcup, OVH)
  - Wildcard-Zertifikate möglich
  - Automatische Erneuerung (< 30 Tage Restlaufzeit) und Verteilung auf die Nodes
- **Live-Monitoring** über die HAProxy Runtime-API: Status aller Proxys/Server,
  Server zur Laufzeit aktivieren / drainen / in Wartung nehmen
- **Auth & Benutzerverwaltung:** mehrere Benutzer mit Rollen
  (`admin` / `operator` / `viewer`), PBKDF2-Passwort-Hashing, Session-Cookies +
  Bearer-Token, **API-Tokens** (`hg_…`) für CI/CD-Automatisierung,
  **LDAP / Active Directory Login** mit Gruppen→Rollen-Mapping
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
  Deploy und Dienst-Status pro Node
- **Tools:** TCP-Port-Scanner und Config-Vergleich zwischen zwei Nodes eines Clusters

## Schnellstart

```bash
docker compose up -d --build
# oder ohne Compose:
docker build -t haproxy-gui .
docker run -d --name haproxy-gui \
  -p 8080:8080 -p 80:80 -p 443:443 \
  -e ADMIN_PASSWORD='sicheres-passwort' \
  -v haproxy-gui-data:/data \
  haproxy-gui
```

GUI öffnen: <http://localhost:8080> (Standard-Login: `admin` / Wert von `ADMIN_PASSWORD`)

## Umgebungsvariablen

| Variable                | Standard | Beschreibung                                   |
| ----------------------- | -------- | ---------------------------------------------- |
| `ADMIN_USER`            | `admin`  | Initialer Admin-Benutzer (weitere in der GUI)   |
| `ADMIN_PASSWORD`        | `admin`  | Initiales Admin-Passwort – **unbedingt setzen!** |
| `GUI_PORT`              | `8080`   | Port des Web-Interfaces                         |
| `ENABLE_LOCAL_HAPROXY`  | `true`   | Eingebetteten HAProxy (Cluster „Local") starten |
| `HG_DATA`               | `/data`  | Datenverzeichnis (DB, Zertifikate, Config)      |

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

Um das CI-Badge in dieser Datei zu aktivieren, `DEIN-USER` im Badge-Link oben durch
den eigenen GitHub-Nutzer ersetzen.d '{"validate_only": false}' http://localhost:8080/api/clusters/1/deploy
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
   und `stats socket ipv4@10.0.0.1:9999 level admin` konfigurieren

Danach in der GUI unter **Cluster & Nodes** → *+ Node* die Verbindungsdaten eintragen
und mit *Test* prüfen. Der Runtime-Socket-Pfad wird in die generierte Config übernommen.

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
4. Das Zertifikat in einem SSL-Frontend auswählen und die Config deployen –
   die PEM-Dateien werden automatisch mit auf die Nodes kopiert (`cert_dir`)
5. **Auto-Renew** erneuert Zertifikate ab < 30 Tagen Restlaufzeit und verteilt sie neu

Weitere lego-Provider lassen sich in [app/services/certs.py](app/services/certs.py)
(`PROVIDERS`) ergänzen – lego unterstützt
[über 100 DNS-Provider](https://go-acme.github.io/lego/dns/).

## Lokale Entwicklung (ohne Docker)

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
$env:HG_DATA = "./data"       # Windows PowerShell
$env:ADMIN_PASSWORD = "admin"
uvicorn app.main:app --reload --port 8080
```

Für Zertifikats-Ausstellung muss `lego` im `PATH` liegen (unter Windows z. B. als
`lego.exe` aus den GitHub-Releases).

## Sicherheitshinweise

- `ADMIN_PASSWORD` ändern und die GUI nicht ungeschützt ins Internet stellen
  (z. B. hinter ein eigenes TLS-Frontend legen)
- SSH-Keys und DNS-Credentials liegen in `/data/haproxy-gui.db` – Volume schützen
- Der TCP-Stats-Socket hat keine Authentifizierung – nur an interne/localhost-Adressen binden
