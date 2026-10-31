# Installation

## Voraussetzungen

- Docker (und optional Docker Compose)
- Einen oder mehrere HAProxy-Server (oder den eingebetteten Local-Cluster)

## Variante A: Vorgefertigtes Image (empfohlen)

Das Image wird bei jedem Push automatisch gebaut (amd64 + arm64).

```bash
export ADMIN_PASSWORD='replace-with-a-strong-unique-password'
docker compose up -d
```

oder ohne Compose:

```bash
docker run -d --name haproxy-gui \
  -p 8080:8080 -p 80:80 -p 443:443 \
  -e ADMIN_PASSWORD='replace-with-a-strong-unique-password' \
  -v haproxy-gui-data:/data \
  ghcr.io/bartelluis/haproxy-gui:latest
```

## Variante B: Selbst aus dem Quellcode bauen

```bash
git clone https://github.com/BartelLuis/haproxy-gui.git
cd haproxy-gui
export ADMIN_PASSWORD='replace-with-a-strong-unique-password'
docker compose -f docker-compose.build.yml up -d --build
```

## Umgebungsvariablen

| Variable | Standard | Beschreibung |
|----------|----------|--------------|
| `ADMIN_USER` | `admin` | Initialer Admin-Benutzer |
| `ADMIN_PASSWORD` | – | Für die Ersteinrichtung erforderlich; starkes, individuelles Passwort verwenden |
| `GUI_PORT` | `8080` | Port der Web-GUI |
| `GUI_HOST` | leer | Listen-Host; leer bindet IPv4 und IPv6, `0.0.0.0` nur IPv4 |
| `TRUSTED_PROXIES` | leer | Kommagetrennte Proxy-CIDRs, deren `X-Forwarded-For` vertraut wird |
| `ENABLE_API_DOCS` | `false` | Aktiviert die interaktive API-Dokumentation unter `/docs` |
| `ENABLE_LOCAL_HAPROXY` | `true` | Eingebetteten HAProxy (Cluster „Local") starten |
| `TOKEN_TTL_HOURS` | `12` | Gültigkeitsdauer von Session-Tokens |
| `HG_DATA` | `/data` | Datenverzeichnis (DB, Zertifikate, Configs) |

## Ports

| Port | Zweck |
|------|-------|
| `8080` | Web-GUI |
| `80` / `443` | Eingebetteter HAProxy (optional) |

## Erster Start

1. `ADMIN_PASSWORD` setzen und Container starten
2. GUI öffnen: `http://<host>:8080`
3. Login: `admin` / Wert von `ADMIN_PASSWORD`
4. **Sofort:** MFA aktivieren – siehe
   [Sicherheit](Sicherheit)

## TLS für die GUI

Die GUI selbst spricht HTTP. Für den produktiven Betrieb hinter einen TLS-Reverse-Proxy
legen, z. B. den eingebetteten HAProxy selbst, Caddy oder Nginx. Details: [Sicherheit](Sicherheit).

## Update

```bash
docker compose pull
docker compose up -d
```

Alle Daten bleiben im Volume `haproxy-gui-data` erhalten.

Das Compose-Netzwerk aktiviert IPv6; der Docker-Host muss dafür IPv6-Netzwerke
und IPv6-Routing unterstützen. `TRUSTED_PROXIES` nur setzen, wenn die GUI hinter
einem Reverse-Proxy läuft, und nur die tatsächlichen Proxy-Netze eintragen.
