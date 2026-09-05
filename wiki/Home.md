# HAProxy GUI – Wiki

Willkommen im Wiki von **HAProxy GUI** – dem Multi-Cluster-Verwaltungs-Tool für HAProxy
mit Let's Encrypt (DNS-01), RBAC, MFA und Live-Monitoring.

## Inhalte

### Erste Schritte
- **[Installation](Installation)** – Docker, Docker Compose, GHCR-Image, Env-Variablen
- **[Erste Schritte / Quickstart](Getting-Started)** – erster Login, erster Cluster, erstes Deploy

### Hosts & Betrieb
- **[Host anlegen](Host-anlegen)** – Node einbinden (SSH, socat, Runtime-Socket, Deploy)
- **[Sicherheit & Härtung](Sicherheit)** – Schutzmechanismen, MFA, TLS, RBAC, Best Practices

### Features
- **Multi-Cluster & Nodes** – Config-Generierung, sicheres Deploy mit Validierung & Rollback
- **Zertifikate** – Let's Encrypt DNS-01 (Cloudflare, Hetzner Cloud, Technitium, manuell u. v. m.)
- **Keepalived / VRRP** – Hochverfügbarkeit mit virtueller IP
- **Monitoring** – Live-Stats, Metriken, Logs, Alerts (Webhook/SMTP)
- **Benutzer & API** – Rollen, MFA, API-Tokens, Audit-Log

### Referenz
- **[REST-API](API)** – Automatisierung per API-Token
- **[Entwicklung & Tests](Entwicklung)** – lokal laufen lassen, pytest, CI

---

> Dieses Projekt wurde vollständig KI-gestützt entwickelt (GitHub Copilot, Modell: Kimi K3).
