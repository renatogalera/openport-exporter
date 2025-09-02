#!/usr/bin/env sh
set -e

BIN="/usr/bin/openport-exporter"
SERVICE="openport-exporter.service"

# Try to grant CAP_NET_RAW to enable SYN scan when running as non-root (optional)
if command -v setcap >/dev/null 2>&1; then
  setcap cap_net_raw+eip "$BIN" || true
fi

# Systemd integration: reload, enable, and (re)start
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE" || systemctl start "$SERVICE" || true
fi

echo "[openport-exporter] Installed. Default config at /etc/openport-exporter/config.yaml"
echo "[openport-exporter] Service managed with systemd (unit: $SERVICE)."
