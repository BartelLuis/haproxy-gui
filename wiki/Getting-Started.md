# Erste Schritte / Quickstart

Ziel: In 5 Minuten von null zu einem laufenden Load-Balancer.

## 1. Starten

```bash
docker compose up -d
```

GUI öffnen: `http://localhost:8080` → Login `admin` / dein `ADMIN_PASSWORD`.

## 2. Cluster & Node

Beim ersten Start existiert bereits der Cluster **„Local"** mit einem Node **„local"** –
das ist der eingebettete HAProxy im selben Container. Du kannst sofort loslegen.

Um einen **externen** Server einzubinden: siehe **[Host anlegen](Host-anlegen)**.

## 3. Backend anlegen

1. **Backends** → **+ Neues Backend**
2. Name: `web`, Mode: `http`, Balance: `roundrobin`
3. Server hinzufügen: `web1  10.0.0.1  8080` (Haken bei „Check")
4. Speichern

## 4. Frontend anlegen

1. **Frontends** → **+ Neues Frontend**
2. Name: `http_in`, Bind-IP: `*`, Port: `80`, Mode: `http`
3. Default-Backend: `web`
4. Speichern

## 5. Deployen

1. **Config & Deploy** → Cluster „Local"
2. **Konfiguration anzeigen** – Vorschau prüfen
3. **Validieren + Deployen + Reload**

Fertig – der HAProxy läuft. Unter **Dashboard** siehst du den Live-Status.

## 6. TLS mit Let's Encrypt (optional)

1. **Zertifikate** → **+ Neues Zertifikat**
2. Domains eintragen (z. B. `example.com`, `*.example.com`), DNS-Provider wählen,
   API-Credentials eintragen → Ausstellung läuft automatisch
3. Ein **SSL-Frontend** (Port 443) anlegen, das Zertifikat auswählen,
   optional „HTTP→HTTPS Redirect"
4. Deployen

Details und alle DNS-Provider: siehe Features / Zertifikate.

## Nächste Schritte

- **[Host anlegen](Host-anlegen)** – externe Nodes einbinden
- **[Sicherheit](Sicherheit)** – MFA aktivieren, TLS, RBAC
- **Versionen** – Deploy-Historie & Rollback
- **Keepalived** – Hochverfügbarkeit mit virtueller IP
