#!/usr/bin/env bash
# GOLDEN SOPR installer — installs golden-sopr + `sopr` symlink.
# Module path stays github.com/soprpack/soprpack; display name GOLDEN SOPR.
#   bash <(curl -fsSL https://raw.githubusercontent.com/zarem9335-source/GOLDEN-SOPR/main/install.sh)
#   BP_BUILD_FROM_SOURCE=1 bash install.sh   # build from source (needs Go)
set -euo pipefail

REPO="zarem9335-source/GOLDEN-SOPR"
BIN="golden-sopr"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/golden-sopr"      # new home; legacy /etc/soprpack is symlinked as fallback
LEGACY_DIR="/etc/soprpack"
SERVICE="golden-sopr.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Web panel port: avoid 2096 (x-ui holds it on many servers) — pick the
# first free port in 2097-2105, like the VPNSOPR fix.
pick_port() {
  for p in $(seq 2097 2105); do
    if ! (ss -ltn 2>/dev/null | grep -q ":$p ") && ! (netstat -ltn 2>/dev/null | grep -q ":$p "); then
      echo "$p"; return
    fi
  done
  echo 2097
}
PANEL_PORT="${PANEL_PORT:-$(pick_port)}"

mkdir -p "$CONFIG_DIR"
# Legacy fallback: old config path keeps working.
if [ ! -e "$LEGACY_DIR" ]; then
  ln -sfn "$CONFIG_DIR" "$LEGACY_DIR"
fi

install_binary() {
  local src="$1"
  install -m 0755 "$src" "$INSTALL_DIR/$BIN"
  ln -sfn "$INSTALL_DIR/$BIN" "$INSTALL_DIR/sopr"
  echo "Installed $INSTALL_DIR/$BIN (+ symlink $INSTALL_DIR/sopr)"
}

if [ "${BP_BUILD_FROM_SOURCE:-0}" = "1" ]; then
  command -v go >/dev/null || { echo "Go is required for BP_BUILD_FROM_SOURCE=1" >&2; exit 1; }
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  if [ -f go.mod ]; then SRC="."; else
    git clone --depth 1 "https://github.com/$REPO.git" "$TMP/src" || { echo "git clone failed" >&2; exit 1; }
    SRC="$TMP/src"
  fi
  # proxy.golang.org returns 403 from many Iran servers, so retry the
  # build with other module proxies instead of failing outright.
  build_src() { (cd "$SRC" && go build -trimpath -o "$TMP/$BIN" .); }
  if ! build_src; then
    echo "Go module download failed, retrying with GOPROXY=direct ..."
    if ! (export GOPROXY=direct GOSUMDB=off; build_src); then
      echo "Retrying with GOPROXY=https://goproxy.cn,direct ..."
      (export GOPROXY=https://goproxy.cn,direct GOSUMDB=off; build_src) || { echo "Source build failed — use the release binary install instead (no Go needed)." >&2; exit 1; }
    fi
  fi
  install_binary "$TMP/$BIN"
else
  # Latest release asset: golden-sopr-linux-<arch> (+ .sha256 if published).
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
  [ -n "$TAG" ] || { echo "Could not determine latest release; retry with BP_BUILD_FROM_SOURCE=1" >&2; exit 1; }
  ASSET="$BIN-linux-$GOARCH"
  URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"
  echo "Downloading $URL ..."
  # Download under the asset name (golden-sopr-linux-amd64), NOT $BIN:
  # the published .sha256 file lists that exact name, so sha256sum -c
  # below must find a file with that name in $TMP.
  curl -fsSL "$URL" -o "$TMP/$ASSET" || { echo "Download failed — the release may not have $ASSET yet; use BP_BUILD_FROM_SOURCE=1" >&2; exit 1; }
  if curl -fsSL "https://github.com/$REPO/releases/download/$TAG/$ASSET.sha256" -o "$TMP/$ASSET.sha256" 2>/dev/null; then
    (cd "$TMP" && sha256sum -c "$ASSET.sha256") || { echo "Checksum verification FAILED" >&2; exit 1; }
    echo "Checksum OK."
  else
    echo "No published checksum for this asset — skipping verification."
  fi
  install_binary "$TMP/$ASSET"
fi

# systemd unit (single service; per-tunnel runs are `golden-sopr run --tunnel NAME`).
cat > "/etc/systemd/system/$SERVICE" <<EOF
[Unit]
Description=GOLDEN SOPR tunnel engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BIN monitor --config $CONFIG_DIR/config.json
Environment=SOPR_CONFIG=$CONFIG_DIR/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload 2>/dev/null || true
systemctl enable "$SERVICE" 2>/dev/null || true

echo
echo "✨ GOLDEN SOPR installed."
echo "   Binary:  $INSTALL_DIR/$BIN  (also: sopr)"
echo "   Config:  $CONFIG_DIR/config.json  (legacy $LEGACY_DIR also works)"
echo "   Panel:   http://127.0.0.1:$PANEL_PORT  (default admin/admin123 — change it!)"
echo "   Service: $SERVICE"
echo "   Run:     sudo golden-sopr"
