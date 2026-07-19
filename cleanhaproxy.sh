#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
ASSUME_YES=0
KEEP_BACKUPS=0
PURGE_SETUP=0
PURGE_UFW=0
PURGE_PACKAGE=0

usage() {
  cat <<'EOF'
Usage: sudo ./cleanhaproxy.sh [options]

Stops HAProxy and removes the WhatsApp proxy installation managed by this package.

Options:
  --dry-run       Show actions without changing the system (default without --yes)
  --yes           Perform the cleanup
  --purge-package Remove the Ubuntu haproxy package as well
  --keep-backups  Preserve /var/backups/whatsapp-haproxy
  --purge-setup   Also remove this extracted setup directory
  --purge-ufw     Delete UFW rules described by the saved setup YAML
  -h, --help      Show this help

Cloud firewall/security-group rules and the global systemd journal are never changed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --yes) ASSUME_YES=1 ;;
    --purge-package) PURGE_PACKAGE=1 ;;
    --keep-backups) KEEP_BACKUPS=1 ;;
    --purge-setup) PURGE_SETUP=1 ;;
    --purge-ufw) PURGE_UFW=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ $ASSUME_YES -eq 0 ]]; then DRY_RUN=1; fi
if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  echo "Real cleanup must run as root" >&2
  exit 1
fi

print_command() { printf '  '; printf '%q ' "$@"; printf '\n'; }
run() { print_command "$@"; [[ $DRY_RUN -eq 1 ]] || "$@"; }
try_run() { print_command "$@"; [[ $DRY_RUN -eq 1 ]] || "$@" || true; }
remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then run rm -rf -- "$path"; fi
}

saved_config=""
if [[ -f /etc/haproxy/setup.yaml ]]; then
  saved_config=/etc/haproxy/setup.yaml
elif [[ -f "$BASE_DIR/config.yaml" ]]; then
  saved_config="$BASE_DIR/config.yaml"
fi

echo "==> Mode: $([[ $DRY_RUN -eq 1 ]] && echo dry-run || echo cleanup)"
echo "==> Stopping HAProxy"
try_run systemctl disable --now haproxy.service
try_run systemctl stop haproxy.service
try_run pkill -TERM -x haproxy
if [[ $DRY_RUN -eq 0 ]]; then
  for _ in 1 2 3 4 5; do
    pgrep -x haproxy >/dev/null 2>&1 || break
    sleep 1
  done
fi
if pgrep -x haproxy >/dev/null 2>&1; then try_run pkill -KILL -x haproxy; fi

if [[ $PURGE_UFW -eq 1 ]]; then
  echo "==> Removing explicitly requested UFW rules"
  if [[ -n "$saved_config" && -f "$BASE_DIR/tools/config.py" && -x "$(command -v python3 || true)" && -x "$(command -v ufw || true)" ]]; then
    while IFS= read -r port; do
      try_run ufw --force delete allow "$port/tcp"
    done < <(python3 "$BASE_DIR/tools/config.py" ports --config "$saved_config")
  else
    echo "Saved YAML, Python config tool, or UFW is unavailable; skipping UFW cleanup"
  fi
fi

echo "==> Removing HAProxy configuration, certificates, logs and runtime state"
for path in \
  /etc/haproxy \
  /var/log/haproxy \
  /var/lib/haproxy \
  /var/cache/haproxy \
  /run/haproxy \
  /run/haproxy.pid \
  /run/haproxy-master.sock; do
  remove_path "$path"
done
if [[ $KEEP_BACKUPS -eq 0 ]]; then
  remove_path /var/backups/whatsapp-haproxy
else
  echo "==> Preserving /var/backups/whatsapp-haproxy"
fi

if [[ $PURGE_PACKAGE -eq 1 ]]; then
  echo "==> Purging the HAProxy package (no broad apt autoremove)"
  try_run apt-get purge -y haproxy
fi
try_run systemctl daemon-reload
try_run systemctl reset-failed haproxy.service

if [[ $PURGE_SETUP -eq 1 ]]; then
  resolved_base="$(readlink -f "$BASE_DIR")"
  if [[ -z "$resolved_base" || "$resolved_base" == "/" || ! -f "$resolved_base/cleanhaproxy.sh" || ! -d "$resolved_base/steps" ]]; then
    echo "Refusing to remove unsafe setup path: $resolved_base" >&2
    exit 1
  fi
  echo "==> Removing standalone setup directory"
  run rm -rf -- "$resolved_base"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "==> Dry-run complete; nothing was changed. Re-run with --yes to execute."
else
  if pgrep -x haproxy >/dev/null 2>&1; then
    echo "Cleanup failed: an HAProxy process is still running" >&2
    exit 1
  fi
  echo "==> HAProxy cleanup complete"
fi
