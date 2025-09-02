#!/usr/bin/env sh
set -e

SERVICE="openport-exporter.service"
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$SERVICE" || true
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true
fi
