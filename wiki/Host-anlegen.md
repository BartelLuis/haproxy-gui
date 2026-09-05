# Host / Node anlegen

Diese Anleitung beschreibt, wie du einen HAProxy-Server (Node) in die Verwaltung aufnimmst.

## Voraussetzungen auf dem Ziel-Server

1. **HAProxy installiert** (z. B. `apt install haproxy` / `dnf install haproxy`)
2. **SSH-Server erreichbar** und ein Benutzer mit Schreibrecht auf die HAProxy-Config
   (empfohlen: ein dedizierter User mit `sudo`-Rechten nur für `haproxy`-Reload,
   nicht zwingend `root`)
3. **socat** installiert (für die Runtime-API via SSH):
   ```bash
   apt install socat        # Debian/Ubuntu
   dnf install socat        # RHEL/Fedora
   ```
4. **Runtime-Socket** in der `haproxy.cfg` aktivieren (im `global`-Abschnitt):
   ```
   global
       stats socket /var/run/haproxy/admin.sock mode 660 level admin
   ```
   Danach `systemctl reload haproxy`.

## Schritt 1: SSH-Zugang vorbereiten

Am sichersten ist ein **SSH-Key** statt Passwort.

Auf deinem Admin-Rechner (oder im Container) einen Key erzeugen:

```bash
ssh-keygen -t ed25519 -f haproxy-gui-key -N ""
```

Den **Public Key** auf den Node kopieren:

```bash
ssh-copy-id -i haproxy-gui-key.pub benutzer@node-ip
```

## Schritt 2: Node in der GUI anlegen

1. In der GUI: **Cluster & Nodes** → Cluster auswählen → **+ Node**
2. Felder ausfüllen:

| Feld | Beispiel | Hinweis |
|------|----------|---------|
| **Cluster** | Produktion | Ziel-Cluster |
| **Name** | `lb-01` | Nur Buchstaben/Zahlen/`._-` (wird validiert) |
| **Host / IP** | `203.0.113.10` | Hostname oder IP |
| **Läuft lokal** | ☐ | nur für den eingebetteten Container-HAProxy |
| **SSH-Port** | `22` | |
| **SSH-Benutzer** | `haproxy-admin` | |
| **SSH-Private-Key** | `-----BEGIN OPENSSH PRIVATE KEY-----…` | Inhalt des Private Keys (wird verschlüsselt gespeichert) |
| **SSH-Passwort** | | alternativ Passwort-Auth (wird verschlüsselt gespeichert) |
| **Config-Pfad** | `/etc/haproxy/haproxy.cfg` | wird validiert |
| **Zertifikats-Verzeichnis** | `/etc/haproxy/certs` | Ziel für Let's-Encrypt-PEMs |
| **Runtime-Socket-Typ** | `via SSH (socat)` | empfohlen – kein offener Port nötig |
| **Socket-Pfad** | `/var/run/haproxy/admin.sock` | |
| **Reload-Kommando** | *(leer)* | Standard: `systemctl reload haproxy` |

3. **Speichern**, dann auf **Test** klicken.
   - Beim **ersten** Verbinden wird der SSH-Host-Key automatisch akzeptiert und in
     `/data/known_hosts` gespeichert (Trust-On-First-Use).
   - Ändert sich der Key später, wird die Verbindung mit einer **MITM-Warnung** blockiert.

## Schritt 3: Konfiguration verteilen

1. Frontends/Backends für den Cluster anlegen.
2. **Config & Deploy** → Cluster wählen → **Konfiguration anzeigen** (Vorschau prüfen).
3. **Nur validieren** – führt `haproxy -c` auf dem Node aus, ohne etwas zu ändern.
4. **Validieren + Deployen + Reload** – lädt die Config hoch, validiert, legt ein Backup
   (`haproxy.cfg.bak`) an und lädt HAProxy neu.

Jeder Deploy wird in **Versionen** gespeichert und kann dort per Diff verglichen oder
per **Rollback** wiederhergestellt werden.

## Reload-Kommandos je nach Umgebung

| Umgebung | Reload-Kommando |
|----------|-----------------|
| systemd | *(leer lassen)* oder `systemctl reload haproxy` |
| Prozess | `haproxy -D -f /etc/haproxy/haproxy.cfg -sf $(pidof haproxy)` |
| Docker | `docker kill -s HUP haproxy` |
| Master-Worker (`-W`) | `sigusr2` |

## Troubleshooting

| Problem | Lösung |
|---------|--------|
| Test schlägt fehl: „socat fehlgeschlagen" | `socat` auf dem Node installieren |
| Test schlägt fehl: „Host-Key … geändert" | Echten Wechsel prüfen; ggf. Eintrag in `/data/known_hosts` löschen und neu vertrauen |
| Test schlägt fehl: „SSH-Verbindung fehlgeschlagen" | Host/Port/Benutzer/Key prüfen, Firewall |
| „Permission denied" beim Deploy | SSH-User braucht Schreibrecht auf Config-Pfad & Zert-Verzeichnis |
