#!/usr/bin/env bash
set -euo pipefail
sudo apt update
sudo apt install -y openjdk-17-jre-headless radare2 apktool curl unzip
JADX_VER="${JADX_VER:-1.5.1}"
curl -L -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
sudo mkdir -p /opt/jadx && sudo unzip -q /tmp/jadx.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
sudo ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
echo "Versions:"
jadx --version || true
apktool --version || true
r2 -v || true
echo "Done. Ensure /usr/local/bin is in your PATH."
