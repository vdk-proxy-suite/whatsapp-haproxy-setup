#!/usr/bin/env bash
set -Eeuo pipefail

BACKUP_ROOT="/var/backups/whatsapp-haproxy"

require_file() {
  [[ -f "$1" ]] || { echo "Required file not found: $1" >&2; return 1; }
}

cfg_get() {
  python3 "$BASE_DIR/tools/config.py" get --config "$CONFIG" --path "$1"
}

create_backup() {
  local stamp dir
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="$BACKUP_ROOT/$stamp"
  mkdir -p "$dir"

  if dpkg-query -W -f='${Status}' haproxy 2>/dev/null | grep -q 'install ok installed'; then
    echo "PACKAGE_PREEXISTED=1" > "$dir/state.env"
  else
    echo "PACKAGE_PREEXISTED=0" > "$dir/state.env"
  fi
  if systemctl is-enabled haproxy.service >/dev/null 2>&1; then
    echo "SERVICE_WAS_ENABLED=1" >> "$dir/state.env"
  else
    echo "SERVICE_WAS_ENABLED=0" >> "$dir/state.env"
  fi
  if systemctl is-active haproxy.service >/dev/null 2>&1; then
    echo "SERVICE_WAS_ACTIVE=1" >> "$dir/state.env"
  else
    echo "SERVICE_WAS_ACTIVE=0" >> "$dir/state.env"
  fi

  [[ ! -d /etc/haproxy ]] || tar -C / -czf "$dir/etc-haproxy.tar.gz" etc/haproxy
  [[ ! -f /etc/default/haproxy ]] || cp -a /etc/default/haproxy "$dir/default-haproxy"
  systemctl status haproxy.service --no-pager -l > "$dir/service-status.txt" 2>&1 || true
  ss -lntup > "$dir/listeners.txt" 2>&1 || true
  haproxy -vv > "$dir/haproxy-version.txt" 2>&1 || true
  ln -sfn "$dir" "$BACKUP_ROOT/latest"
  echo "$dir"
}

restore_latest_backup() {
  local dir
  dir="$(readlink -f "$BACKUP_ROOT/latest" 2>/dev/null || true)"
  [[ -n "$dir" && -d "$dir" && -f "$dir/state.env" ]] || {
    echo "No HAProxy backup is available for rollback" >&2
    return 1
  }

  # shellcheck disable=SC1090
  source "$dir/state.env"
  systemctl stop haproxy.service >/dev/null 2>&1 || true
  rm -rf -- /etc/haproxy
  if [[ -f "$dir/etc-haproxy.tar.gz" ]]; then
    tar -C / -xzf "$dir/etc-haproxy.tar.gz"
  fi
  if [[ -f "$dir/default-haproxy" ]]; then
    cp -a "$dir/default-haproxy" /etc/default/haproxy
  fi
  if [[ ${PACKAGE_PREEXISTED:-0} -eq 0 ]] && dpkg-query -W -f='${Status}' haproxy 2>/dev/null | grep -q 'install ok installed'; then
    apt-get purge -y haproxy >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload
  if [[ ${SERVICE_WAS_ENABLED:-0} -eq 1 ]]; then
    systemctl enable haproxy.service >/dev/null 2>&1 || true
  else
    systemctl disable haproxy.service >/dev/null 2>&1 || true
  fi
  if [[ ${SERVICE_WAS_ACTIVE:-0} -eq 1 ]]; then
    systemctl start haproxy.service
  fi
}
