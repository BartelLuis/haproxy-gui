#!/bin/bash
set -e

DATA_DIR="${HG_DATA:-/data}"
mkdir -p "$DATA_DIR/haproxy" "$DATA_DIR/acme" /run/haproxy

# Bootstrap-Konfiguration, damit der eingebettete HAProxy sauber startet
if [ ! -s "$DATA_DIR/haproxy/haproxy.cfg" ]; then
  cp /bootstrap/haproxy.cfg "$DATA_DIR/haproxy/haproxy.cfg"
fi

if [ "${ENABLE_LOCAL_HAPROXY:-true}" = "true" ]; then
  echo "[entrypoint] Starte eingebetteten HAProxy (master-worker)..."
  # Ohne -D, im Hintergrund: Logs landen via 'log stdout' in der Logdatei
  haproxy -W -f "$DATA_DIR/haproxy/haproxy.cfg" -p /run/haproxy/master.pid \
    >> "$DATA_DIR/haproxy/haproxy.log" 2>&1 &
fi

echo "[entrypoint] Starte Web-GUI auf Port ${GUI_PORT:-8080}..."
exec uvicorn app.main:app --host 0.0.0.0 --port "${GUI_PORT:-8080}"
