#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$BASE_DIR/config.yaml"
[[ ${1:-} != "--config" ]] || CONFIG="${2:?missing config path}"

echo "==> Starting HAProxy"
systemctl daemon-reload
systemctl enable haproxy.service
# apt may have auto-started HAProxy with its package-default configuration.
# A restart is mandatory so the freshly rendered configuration is loaded.
systemctl restart haproxy.service
systemctl --no-pager -l status haproxy.service

echo "==> Running VM-side health-check"
python3 "$BASE_DIR/tools/healthcheck.py" --scope vm --config "$CONFIG"
