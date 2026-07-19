#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$BASE_DIR/config.yaml"
[[ ${1:-} != "--config" ]] || CONFIG="${2:?missing config path}"
source "$BASE_DIR/lib/common.sh"

# shellcheck disable=SC1091
source /etc/os-release
if [[ ${ID:-} != "ubuntu" || ${VERSION_ID:-} != "24.04" ]]; then
  echo "This package is validated for Ubuntu 24.04; found ${ID:-unknown} ${VERSION_ID:-unknown}" >&2
  exit 1
fi

echo "==> Installing HAProxy and runtime dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y haproxy openssl ca-certificates python3 python3-yaml

minimum="$(cfg_get install.minimum_version)"
installed="$(haproxy -v | awk 'NR==1 {print $3}' | cut -d- -f1)"
if ! dpkg --compare-versions "$installed" ge "$minimum"; then
  echo "HAProxy $installed is older than required $minimum" >&2
  exit 1
fi
echo "Installed HAProxy $installed"
