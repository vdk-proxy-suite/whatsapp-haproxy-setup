#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$BASE_DIR/config.yaml"
[[ ${1:-} != "--config" ]] || CONFIG="${2:?missing config path}"
source "$BASE_DIR/lib/common.sh"

python3 "$BASE_DIR/tools/config.py" validate --config "$CONFIG" --reject-example
public_ip="$(cfg_get server.public_ip)"
regen="$(cfg_get certificate.regenerate_on_setup)"
ssl_dir=/etc/haproxy/ssl
pem="$ssl_dir/proxy.whatsapp.net.pem"
generate=0

mkdir -p /etc/haproxy "$ssl_dir" /run/haproxy
chmod 700 "$ssl_dir"
if [[ ! -f "$pem" || "$regen" == "true" ]]; then
  generate=1
elif ! openssl x509 -in "$pem" -checkend 86400 -noout >/dev/null 2>&1; then
  generate=1
elif ! openssl x509 -in "$pem" -noout -ext subjectAltName 2>/dev/null | grep -Fq "IP Address:$public_ip"; then
  generate=1
fi

if [[ $generate -eq 1 ]]; then
  echo "==> Generating self-signed TLS certificate for $public_ip"
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' EXIT
  python3 "$BASE_DIR/tools/config.py" openssl-config --config "$CONFIG" --output "$tmp/openssl.cnf"
  ca_cn="wa-ca-$(openssl rand -hex 16)"
  leaf_cn="wa-$(openssl rand -hex 16).net"
  ca_days="$(cfg_get certificate.ca_validity_days)"
  leaf_days="$(cfg_get certificate.validity_days)"
  openssl genrsa -out "$tmp/ca-key.pem" 4096
  openssl req -x509 -new -nodes -key "$tmp/ca-key.pem" -days "$ca_days" \
    -out "$tmp/ca.pem" -subj "/CN=$ca_cn"
  openssl genrsa -out "$tmp/proxy.whatsapp.net.key" 4096
  openssl req -new -key "$tmp/proxy.whatsapp.net.key" -out "$tmp/proxy.whatsapp.net.csr" \
    -subj "/CN=$leaf_cn" -config "$tmp/openssl.cnf"
  openssl x509 -req -in "$tmp/proxy.whatsapp.net.csr" -CA "$tmp/ca.pem" \
    -CAkey "$tmp/ca-key.pem" -CAcreateserial -out "$tmp/proxy.whatsapp.net.crt" \
    -days "$leaf_days" -extensions v3_req -extfile "$tmp/openssl.cnf"
  cat "$tmp/proxy.whatsapp.net.key" "$tmp/proxy.whatsapp.net.crt" > "$tmp/proxy.whatsapp.net.pem"
  install -m 600 -o root -g root "$tmp/ca-key.pem" "$ssl_dir/ca-key.pem"
  install -m 644 -o root -g root "$tmp/ca.pem" "$ssl_dir/ca.pem"
  install -m 600 -o root -g root "$tmp/proxy.whatsapp.net.key" "$ssl_dir/proxy.whatsapp.net.key"
  install -m 644 -o root -g root "$tmp/proxy.whatsapp.net.crt" "$ssl_dir/proxy.whatsapp.net.crt"
  install -m 600 -o root -g root "$tmp/proxy.whatsapp.net.pem" "$pem"
  trap - EXIT
  rm -rf -- "$tmp"
else
  echo "==> Reusing valid TLS certificate for $public_ip"
fi

echo "==> Rendering and validating HAProxy configuration"
tmp_cfg="$(mktemp)"
trap 'rm -f -- "$tmp_cfg"' EXIT
python3 "$BASE_DIR/tools/config.py" render-haproxy --config "$CONFIG" --output "$tmp_cfg"
haproxy -c -f "$tmp_cfg"
install -m 640 -o root -g haproxy "$tmp_cfg" /etc/haproxy/haproxy.cfg
install -m 600 -o root -g root "$CONFIG" /etc/haproxy/setup.yaml
trap - EXIT
rm -f -- "$tmp_cfg"

if [[ "$(cfg_get server.manage_ufw)" == "true" ]]; then
  if ! command -v ufw >/dev/null 2>&1; then
    apt-get install -y ufw
  fi
  while IFS= read -r port; do
    ufw allow "$port/tcp"
  done < <(python3 "$BASE_DIR/tools/config.py" ports --config "$CONFIG")
fi
