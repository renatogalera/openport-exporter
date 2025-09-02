#!/usr/bin/env sh
set -e

USER="openport"
GROUP="openport"
CONF_DIR="/etc/openport-exporter"

# Create system user/group if missing
if ! getent group "$GROUP" >/dev/null 2>&1; then
  groupadd -r "$GROUP" || true
fi
if ! id "$USER" >/dev/null 2>&1; then
  useradd -r -g "$GROUP" -s /usr/sbin/nologin -d /nonexistent "$USER" || true
fi

# Ensure config directory exists
mkdir -p "$CONF_DIR"
chmod 755 "$CONF_DIR"
