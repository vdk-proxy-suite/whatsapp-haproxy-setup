#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-all}"
if [[ $# -gt 0 ]]; then shift; fi
CONFIG="$BASE_DIR/config.yaml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="${2:?--config requires a path}"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 [all|0|1|2|3] [--config PATH]" >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Configuration not found: $CONFIG" >&2
  echo "Create it first: cp '$BASE_DIR/config.example.yaml' '$BASE_DIR/config.yaml'" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "==> Installing YAML parser dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-yaml
fi

source "$BASE_DIR/lib/common.sh"
require_file "$CONFIG"
python3 "$BASE_DIR/tools/config.py" validate --config "$CONFIG" --reject-example

rollback_armed=0
on_error() {
  local rc=$?
  trap - ERR
  if [[ $rollback_armed -eq 1 ]]; then
    echo "==> Mandatory step failed; restoring the previous HAProxy state" >&2
    restore_latest_backup || true
  fi
  exit "$rc"
}
trap on_error ERR

run_step() {
  local number="$1"
  "$BASE_DIR/steps/${number}-"*.sh --config "$CONFIG"
}

case "$ACTION" in
  all)
    run_step 00
    rollback_armed=1
    run_step 01
    run_step 02
    run_step 03
    rollback_armed=0
    ;;
  0|1|2|3) run_step "0$ACTION" ;;
  *)
    echo "Usage: sudo $0 [all|0|1|2|3] [--config PATH]" >&2
    exit 2
    ;;
esac

echo "==> setuphaproxy action '$ACTION' completed"
