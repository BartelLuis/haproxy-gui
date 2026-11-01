# Erste Schritte / Quickstart

Ziel: In 5 Minuten von null zu einem laufenden Load-Balancer.

## 1. Starten

```bash
export ADMIN_PASSWORD='replace-with-a-strong-unique-password'
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
   – für HTTPS-Backends zusätzlich „SSL“, optional „Zert. prüfen“ (Host als DNS-Name, HAProxy ≥ 2.6)
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

1. **Zertifikate** → **+ Let's Encrypt**
2. Domains eintragen (z. B. `example.com`, `*.example.com`), DNS-Provider wählen,
   API-Credentials eintragen → Ausstellung läuft automatisch
3. Ein **SSL-Frontend** (Port 443) anlegen und unter **Zertifikate (SNI)** ein oder
   mehrere Zertifikate hinzufügen (das erste ist der Standard), optional
   „HTTP→HTTPS Redirect". Alternativ das Zertifikat wie beim Nginx Proxy Manager im
   **Backend** zuordnen – SSL-Frontends, die dorthin weiterleiten, laden es automatisch.
4. Deployen

Details und alle DNS-Provider: siehe Features / Zertifikate.

### Vorhandene Zertifikate verwenden

Statt Let's Encrypt kannst du unter **Zertifikate → Importieren** vorhandene
PEM-Dateien (Zertifikat/Fullchain und privater Schlüssel) oder eine PFX/P12-Datei
hochladen. PEM-Text kann alternativ eingefügt werden; bei verschlüsseltem Material
das Passwort angeben. Domains und Ablaufdatum werden automatisch erkannt.
Anschließend wie oben einem Frontend oder Backend zuordnen und deployen.

Importierte Zertifikate haben kein Auto-Renew. Über **Ersetzen** kannst du eine neue
Version importieren, ohne Zuordnungen zu verlieren. **Verteilen** muss danach separat
ausgeführt werden, damit HAProxy die neue Version verwendet.

## Nächste Schritte

- **[Host anlegen](Host-anlegen)** – externe Nodes einbinden
- **[Sicherheit](Sicherheit)** – MFA aktivieren, TLS, RBAC
- **Versionen** – Deploy-Historie & Rollback
- **Keepalived** – Hochverfügbarkeit mit virtueller IP
