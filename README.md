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

### Install and Run
- pip install -r requirements.txt
- uvicorn app:app --host 0.0.0.0 --port 8000

### Open http://127.0.0.1:8000

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


<img width="1918" height="733" alt="image" src="https://github.com/user-attachments/assets/ccd0dbd5-c2a9-4a69-b2c7-137dfbeb9c60" />
<img width="1894" height="834" alt="image" src="https://github.com/user-attachments/assets/6274f2a3-f577-4c89-8bf9-89003022dbab" />
<img width="1903" height="837" alt="image" src="https://github.com/user-attachments/assets/b41802fe-f1e1-4b47-a1b0-5ca2e200f031" />
<img width="1770" height="831" alt="image" src="https://github.com/user-attachments/assets/57039bf5-c5db-40f1-ab15-718ce6fc8708" />




