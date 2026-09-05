# Entwicklung & Tests

## Lokale Entwicklung (ohne Docker)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

$env:HG_DATA = "./data"         # Windows PowerShell
$env:ADMIN_PASSWORD = "admin"
uvicorn app.main:app --reload --port 8080
```

GUI: `http://localhost:8080`

## Tests

Die Suite ([tests/](../tests)) enthält Unit- und HTTP-Integrationstests:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

- `test_auth.py` – Passwörter, Tokens, Rollen, API-Tokens
- `test_configgen.py` – Config-Generierung (inkl. Validierung)
- `test_services.py` – Keepalived, Alerts, Metriken, LDAP, Zertifikate
- `test_api.py` – Integrationstests gegen einen echten Server-Prozess

## CI / CD

- **[ci.yml](../.github/workflows/ci.yml)** – Tests (Python 3.11/3.13), Docker-Build,
  Container-Smoke-Test bei jedem Push/PR
- **[publish.yml](../.github/workflows/publish.yml)** – Multi-Arch-Image (amd64/arm64)
  nach ghcr.io bei Push auf `main` und Tags `v*`

## Projektstruktur

```
app/
  main.py            FastAPI-App, Router-Registrierung
  auth.py            Login, Tokens, MFA-Rollen, Secret-Encryption, Rate-Limit
  db.py              SQLite-Schema, Audit-Helfer
  routers/           API-Endpunkte (clusters, frontends, backends, certs, …)
  services/          Logik (sshclient, runtime, configgen, certs, totp, …)
  static/            Web-GUI (index.html, app.js, style.css)
tests/               pytest-Suite
wiki/                Dokumentation
Dockerfile           All-in-One-Image (HAProxy + Python + lego)
```

## Sicherheit

Vor einem Release bitte [Sicherheit](Sicherheit) lesen – das Tool steuert produktive
Server. Gefundene Schwachstellen bitte als Issue melden.
