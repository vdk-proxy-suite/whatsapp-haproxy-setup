#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$BASE_DIR/config.yaml"
[[ ${1:-} != "--config" ]] || CONFIG="${2:?missing config path}"
source "$BASE_DIR/lib/common.sh"

echo "==> Capturing current HAProxy state"
backup_dir="$(create_backup)"
echo "Backup: $backup_dir"

echo "==> Stopping existing HAProxy service and processes"
systemctl stop haproxy.service >/dev/null 2>&1 || true
for _ in 1 2 3 4 5; do
  pgrep -x haproxy >/dev/null 2>&1 || break
  sleep 1
done
if pgrep -x haproxy >/dev/null 2>&1; then
  pkill -TERM -x haproxy || true
  sleep 1
fi
if pgrep -x haproxy >/dev/null 2>&1; then
  echo "Unable to stop all HAProxy processes" >&2
  exit 1
fi
