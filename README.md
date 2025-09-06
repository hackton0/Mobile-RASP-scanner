# Mobile RASP Scanner — by Hackton0

Static RASP dashboard for Android APKs. Optional **decompile** (JADX → fallback apktool), **endpoint/URI extraction**, and **DEX/native** checks. One-click **Export PDF** and **Export CSVs**.

## Features
- Decompile via **jadx**, auto-fallback to **apktool** (resources included)
- Endpoint/URI extraction: raw URLs, Retrofit + baseUrl, OkHttp, WebView bridges, manifest deep links
- RASP detections from DEX/native (radare2 optional)
- Clean dark UI, filters; export **PDF** & **CSVs**

---

## Prerequisites

### Python
- Python 3.9+
- Pip

### External tools (install system-wide; must be in your PATH)
- **jadx** – preferred Java/Kotlin decompiler  
- **apktool** – Smali/resources decompiler (fallback)  
- **radare2** – optional native analysis

### Debian/Ubuntu/Kali quick install
```bash
sudo apt update
sudo apt install -y openjdk-17-jre-headless radare2 apktool curl unzip
JADX_VER=1.5.1
curl -L -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
sudo mkdir -p /opt/jadx && sudo unzip -q /tmp/jadx.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
sudo ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
jadx --version && apktool --version && r2 -v

