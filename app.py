#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RASP Web Dashboard — single-file FastAPI app

What it shows (no files written):
- RASP Detections (anti-debug, hook, root, integrity, vendors)
- SDK Inventory (>=2 signals: package/lib/manifest/asset) incl. Protectt.ai
- Native Libraries (.so list)
- Native Analysis (imports + strings) via radare2 (optional) + a lite scanner (no r2)
- Native Suspects: ranks .so files most likely implementing RASP, with reasons
- DEX -> lib linkage from System.loadLibrary()

Start:
  pip install fastapi uvicorn
  uvicorn app:app --host 0.0.0.0 --port 8000

Optional native analysis:
  Install radare2 (r2) and tick "Native (radare2)" in the UI.
"""

import io, os, re, time, zipfile, hashlib, shutil, subprocess
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
import shutil
import subprocess
import os
import re
from fastapi import Request
from fastapi import Header
from fastapi import Query

# ---------------- Helpers ----------------
PRINTABLE_SET = set(range(32, 127))

def extract_strings(b: bytes, minlen=4) -> List[str]:
    out, cur = [], bytearray()
    for ch in b:
        if ch in PRINTABLE_SET and ch not in (9, 10, 13):
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode('ascii', errors='ignore'))
            cur.clear()
    if len(cur) >= minlen:
        out.append(cur.decode('ascii', errors='ignore'))
    return out

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def which(x: str) -> str:
    return shutil.which(x) or ""

def strip_prefix(s: str, pre: str) -> str:
    return s[len(pre):] if s.startswith(pre) else s

def strip_suffix(s: str, suf: str) -> str:
    return s[:-len(suf)] if s.endswith(suf) else s

# ---------------- Rules ----------------
def R(name, pattern, severity, category, why, advice, weight=1):
    return {'name':name,'pattern':pattern,'severity':severity,'category':category,
            'why':why,'advice':advice,'weight':weight,'_re':re.compile(pattern,re.I)}

RASP_RULES = [
    # Debug / hook / root / integrity
    R('Android Debug API', r'Landroid/os/Debug;->(?:isDebuggerConnected|waitForDebugger)', 'high','debug',
      'Checks if a debugger is attached / waits for one.', 'Run without debugger or hook these APIs.', 3),
    R('TracerPid (/proc/self/status)', r'TracerPid|/proc/self/status', 'high','debug',
      'Reads /proc/self/status to detect tracing.', 'Avoid attaching debugger or fake TracerPid via hooks.', 3),
    R('/proc/self/maps scan', r'/proc/self/maps', 'high','hook',
      'Scans loaded libs to detect hooks/gadgets.', 'Avoid gadgets; compare with stock ROM.', 3),
    R('ptrace/prctl', r'\bptrace\b|\bprctl\b|PR_SET_DUMPABLE', 'medium','debug',
      'Native anti-debug primitives.', 'Hook ptrace/prctl; test on stock device.', 2),

    R('Frida artifacts', r'frida[-_ ]?gadget|libfrida-gadget|gum-js-loop|frida-server', 'high','hook',
      'Frida runtime references present.', 'Do not load gadget in baseline tests.', 4),
    R('Xposed/EdXposed', r'\bxposed\b|\bedxposed\b', 'high','hook',
      'Hook framework likely detected.', 'Disable modules and retry.', 3),
    R('Magisk/Zygisk/Riru', r'\bmagisk\b|\bzygisk\b|\briru\b', 'high','root',
      'Root/injection frameworks referenced.', 'Use a non-root baseline device.', 3),

    R('SafetyNet', r'com\.google\.android\.gms\.safetynet|SafetyNetAttestation', 'info','integrity',
      'Google SafetyNet integration present.', 'Server likely verifies tokens.', 1),
    R('Play Integrity', r'com\.google\.android\.play\.core\.integrity|IntegrityManager', 'info','integrity',
      'Play Integrity API present.', 'Server likely verifies tokens.', 1),

    # Vendors (precise) — strong evidence gating is applied later
    R('Promon Shield', r'(?:(?:L)?com/(?:promon|promonshield)/|com\.promon\.|PromonShield|libpromon\.so)', 'high','vendor',
      'Commercial RASP SDK detected.', 'Expect strong runtime hardening.', 4),
    R('OneSpan/VASCO', r'(?:(?:L)?com/(?:onespan|vasco/digipass)/|com\.onespan\.|com\.vasco\.digipass|OneSpanMobile|VASCOGuard|libdigipass\.so)', 'high','vendor',
      'App shielding / RASP SDK detected.', 'Plan clean devices; hook/root checks likely.', 3),
    R('AppSealing', r'(?:(?:L)?io/appsealing/|io\.appsealing\.|AppSealing|libappsealing\.so)', 'high','vendor',
      'RASP SDK detected.', 'Debugger/root/hook blocks likely.', 3),
    R('Zimperium', r'(?:(?:L)?com/zimperium/|com\.zimperium\.|libzanti-?rasp?\.so)', 'high','vendor',
      'Mobile security / RASP SDK detected.', 'Telemetry & hardening likely.', 3),
    R('Wultra/Malwarelytics', r'(?:(?:L)?com/wultra/|com\.wultra\.|malwarelytics|libmalwarelytics\.so)', 'high','vendor',
      'RASP / anti-malware SDK detected.', 'Device health checks likely.', 3),
    R('Pradeo', r'(?:(?:L)?com/pradeo/|com\.pradeo\.|libpradeo\.so)', 'high','vendor',
      'RASP/MTD SDK detected.', 'Root/emulator/hook checks likely.', 3),
    R('Appdome', r'(?:(?:L)?com/appdome/|com\.appdome\.|Appdome|libappdome\.so)', 'high','vendor',
      'No-code RASP platform detected.', 'Comprehensive anti-tamper likely.', 3),
    R('Protectt.ai', r'(?:(?:L)?ai/protectt/|ai\.protectt\.|com\.protectt\.|Protectt(?:AI)?|libprotectt(?:ai)?\.so)',
      'high','vendor', 'Protectt.ai RASP/App shielding indicators.', 'Expect anti-debug/hook/root; test on clean device.', 3),

    # Helpful context heuristics (medium)
    R('Dynamic code loading', r'(DexClassLoader|PathClassLoader)', 'medium','tamper',
      'Loads code at runtime; protectors may hide checks.', 'Behavior may vary across devices.', 2),
    R('LD_PRELOAD detection', r'LD_PRELOAD', 'medium','hook',
      'Detects library injection via LD_PRELOAD.', 'Ensure env does not set LD_PRELOAD.', 2),
]

SEV_SCORE = {'high':4,'medium':2,'low':1,'info':1}

# vendor false-positive gating
_VENDOR_LIB_RX  = re.compile(r'lib(?:digipass|promon|appsealing|zimperium|malwarelytics|pradeo|appdome|protectt(?:ai)?)\.so', re.I)
_VENDOR_DESC_RX = re.compile(r'Lcom/(?:onespan|vasco/digipass|promon(?:shield)?|appdome|zimperium|wultra|pradeo|ai/protectt|com/protectt)/', re.I)
_VENDOR_PKG_RX  = re.compile(r'com\.(?:onespan|vasco\.digipass|promon(?:shield)?|appdome|zimperium|wultra|pradeo|protectt)\.', re.I)
def vendor_strong(text: str) -> bool:
    t = text or ""
    return bool(_VENDOR_LIB_RX.search(t) or _vendor_desc_hit(t:=t) or _vendor_pkg_hit(t))

def _vendor_desc_hit(t: str) -> bool:
    return bool(_VENDOR_DESC_RX.search(t))

def _vendor_pkg_hit(t: str) -> bool:
    return bool(_VENDOR_PKG_RX.search(t))

# ---------------- SDK signatures (multi-signal) ----------------
SDK_SIGNATURES = {
    "OneSpan": {
        "packages":[r"^com\.onespan\.", r"^com\.vasco\.digipass"],
        "libs":[r"^libdigipass\.so$"],
        "manifest":[r"com\.onespan\.", r"com\.vasco\.digipass"],
        "assets":[r"onespan", r"digipass"],
    },
    "Promon Shield": {"packages":[r"^com\.promon", r"^com\.promonshield"], "libs":[r"^libpromon\.so$"], "assets":[r"promon"]},
    "AppSealing": {"packages":[r"^io\.appsealing\."], "libs":[r"^libappsealing\.so$"], "assets":[r"appsealing"]},
    "Zimperium": {"packages":[r"^com\.zimperium\."], "libs":[r"^libzanti(?:-rasp)?\.so$"]},
    "Malwarelytics": {"packages":[r"^com\.wultra\."], "libs":[r"^libmalwarelytics\.so$"]},
    "Pradeo": {"packages":[r"^com\.pradeo\."], "libs":[r"^libpradeo\.so$"]},
    "Appdome": {"packages":[r"^com\.appdome\."], "libs":[r"^libappdome\.so$"]},
    "Protectt.ai": {"packages":[r"^ai\.protectt\.", r"^com\.protectt\."], "libs":[r"^libprotectt(?:ai)?\.so$"], "assets":[r"protectt", r"protectt\.ai"], "manifest":[r"ai\.protectt\.", r"com\.protectt\."]},
    # common infra for visibility
    "Firebase": {"packages":[r"^com\.google\.firebase\."], "assets":[r"google-services\.json"]},
    "Crashlytics": {"packages":[r"^com\.google\.firebase\.crashlytics", r"^com\.crashlytics\.android"], "assets":[r"crashlytics\-build\.properties"]},
    "Play Services": {"packages":[r"^com\.google\.android\.gms\."]},
    "OkHttp": {"packages":[r"^okhttp3\."]},
    "Retrofit": {"packages":[r"^retrofit2\."]},
    "Kotlin": {"packages":[r"^kotlin(\.|x\.)"]},
}

# ---------------- APK helpers ----------------
def list_native_libs(zf: zipfile.ZipFile) -> List[str]:
    return [os.path.basename(i.filename) for i in zf.infolist() if i.filename.endswith(".so")]

def read_manifest_text(zf: zipfile.ZipFile) -> str:
    try:
        data = zf.read("AndroidManifest.xml")
        try: return data.decode("utf-8")
        except UnicodeDecodeError:
            return re.sub(rb'[^ -~]+', b' ', data).decode('ascii','ignore')
    except KeyError:
        return ""

def list_assets(zf: zipfile.ZipFile) -> List[str]:
    out=[]
    for info in zf.infolist():
        p = info.filename.lower()
        if p.startswith("assets/"):
            out.append(os.path.basename(p))
    return out

def collect_packages_from_dex_strings(strings: List[str]) -> Set[str]:
    pk=set()
    for s in strings:
        m=re.search(r"L([a-zA-Z0-9_/$.]+);", s)
        if m: pk.add(m.group(1).replace('/','.').replace('$','.'))
    return pk

def detect_sdks(pkgs:Set[str], libs:List[str], manifest_txt:str, assets:List[str]) -> List[Dict[str,Any]]:
    out=[]
    for sdk, sig in SDK_SIGNATURES.items():
        hits=[]
        for rx in sig.get("packages",[]):
            r=re.compile(rx)
            if any(r.match(p) for p in pkgs): hits.append(("package",rx))
        for rx in sig.get("libs",[]):
            r=re.compile(rx,re.I)
            if any(r.match(os.path.basename(x)) for x in libs): hits.append(("lib",rx))
        if manifest_txt:
            for rx in sig.get("manifest",[]):
                if re.search(rx, manifest_txt): hits.append(("manifest",rx))
        for rx in sig.get("assets",[]):
            r=re.compile(rx,re.I)
            if any(r.search(a) for a in assets): hits.append(("asset",rx))
        if len({t for t,_ in hits}) >= 2:
            out.append({"sdk":sdk,"version":None,"evidence":hits})
    return out

# ---------------- radare2 helpers ----------------
def r2_present() -> bool:
    return bool(which("r2"))

def r2_strings(so_path: Path) -> List[Tuple[int, str]]:
    if not r2_present(): return []
    r = subprocess.run(['r2','-2qc','izz; q', str(so_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    res=[]
    for line in r.stdout.splitlines():
        m = re.search(r'^(0x[0-9a-fA-F]+).*?\s+([\x20-\x7e]{4,})$', line)
        if m: res.append((int(m.group(1),16), m.group(2).strip()))
    return res

def r2_imports(so_path: Path) -> List[str]:
    if not r2_present(): return []
    r = subprocess.run(['r2','-2qc','ii~name; q', str(so_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    names=[]
    for line in r.stdout.splitlines():
        parts=line.strip().split()
        if parts: names.append(parts[-1])
    return names

def r2_xrefs_to_import(so_path: Path, sym: str) -> List[Dict[str,Any]]:
    if not r2_present(): return []
    script=f"ii~{sym}\n?e sym.imp.{sym}\naxt sym.imp.{sym}\n"
    r = subprocess.run(['r2','-2qc', script+'q', str(so_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    hits=[]
    for line in r.stdout.splitlines():
        m=re.search(r'^(0x[0-9a-fA-F]+).*?from\s+([^\s]+)', line)
        if m: hits.append({'xref_from':m.group(1),'function':m.group(2)})
    return hits

# ---------------- Core Scan ----------------
NATIVE_STR_RULES = [
    ("TracerPid", re.compile(r"\bTracerPid\b", re.I), "high", 3),
    ("/proc/self/status", re.compile(r"/proc/self/status", re.I), "high", 3),
    ("/proc/self/maps", re.compile(r"/proc/self/maps", re.I), "high", 2),
    ("frida", re.compile(r"\bfrida\b", re.I), "high", 2),
    ("xposed", re.compile(r"\bxposed|edxposed\b", re.I), "high", 2),
    ("magisk", re.compile(r"\bmagisk|zygisk|riru\b", re.I), "high", 2),
    ("Java_", re.compile(r"\bJava_[A-Za-z0-9_]+\b"), "info", 1),
]

VENDOR_LIB_HINT = re.compile(
    r"^lib(?:digipass|promon|appsealing|zimperium|malwarelytics|pradeo|appdome|protectt(?:ai)?)\.so$",
    re.I
)

def dex_find_loadlibs(all_strings: List[str]) -> Set[str]:
    names = set()
    blob = "\n".join(all_strings)
    for m in re.finditer(r'loadLibrary\s*\(\s*"?([A-Za-z0-9._-]+)"?\s*\)', blob):
        names.add(strip_suffix(strip_prefix(m.group(1), "lib"), ".so"))
    for m in re.finditer(r'lib([A-Za-z0-9._-]+)\.so', blob):
        names.add(m.group(1))
    return {n.strip() for n in names if n.strip()}

def native_lite_scan(zf: zipfile.ZipFile) -> List[Dict[str,Any]]:
    """Scan native libs without r2 (strings only)."""
    findings = []
    for info in zf.infolist():
        if not info.filename.endswith(".so"): continue
        so_name = os.path.basename(info.filename)
        data = zf.read(info)
        s = "\n".join(extract_strings(data, 4))
        for what, rx, sev, _ in NATIVE_STR_RULES:
            for m in rx.finditer(s):
                findings.append({
                    "lib": so_name, "kind": "string",
                    "severity": sev, "what": what,
                    "evidence": {"needle": m.group(0)[:160]}
                })
    return findings

def rank_native_suspects(native_analysis: List[Dict[str,Any]], native_libs: List[str],
                         dex_loadlibs: Set[str]) -> List[Dict[str,Any]]:
    """Aggregate evidence per lib and compute a suspicion score."""
    per = {lib: {"lib":lib, "score":0, "reasons":[]} for lib in native_libs}
    lib_set = set(native_libs)
    # r2/imports + strings from analysis
    for row in native_analysis:
        lib = row.get("lib")
        if lib not in per: continue
        what = (row.get("what") or "").lower()
        ev = row.get("evidence") or {}
        if row.get("kind") == "import":
            if "import:ptrace" in what: per[lib]["score"] += 4; per[lib]["reasons"].append("imports ptrace")
            if "import:prctl"  in what: per[lib]["score"] += 4; per[lib]["reasons"].append("imports prctl")
            if "import:seccomp" in what: per[lib]["score"] += 2; per[lib]["reasons"].append("imports seccomp")
        if row.get("kind") == "string":
            needle = (ev.get("needle") or "").lower()
            if "tracerpid" in needle or "/proc/self/status" in needle:
                per[lib]["score"] += 3; per[lib]["reasons"].append("anti-debug strings")
            if "/proc/self/maps" in needle:
                per[lib]["score"] += 2; per[lib]["reasons"].append("maps scan string")
            if "frida" in needle or "xposed" in needle or "magisk" in needle:
                per[lib]["score"] += 2; per[lib]["reasons"].append("hook/root strings")
            if needle.startswith("java_"):
                per[lib]["score"] += 1; per[lib]["reasons"].append("JNI exported function")
    # vendor-looking names
    for lib in lib_set:
        if VENDOR_LIB_HINT.match(lib):
            per[lib]["score"] += 5
            per[lib]["reasons"].append("vendor-like .so name")
    # linkage from DEX loadLibrary()
    low = {x.lower() for x in dex_loadlibs}
    for lib in lib_set:
        base = strip_suffix(strip_prefix(lib.lower(), "lib"), ".so")
        if base in low:
            per[lib]["score"] += 1
            per[lib]["reasons"].append("referenced via System.loadLibrary")
    suspects = sorted(per.values(), key=lambda x: x["score"], reverse=True)
    return [s for s in suspects if s["score"] > 0]

def scan_bytes(apk_bytes: bytes, use_r2: bool, deep: bool, decomp: bool=False) -> Dict[str,Any]:
    rep: Dict[str,Any] = {"summary":{}}
    rep["sha256"] = sha256_bytes(apk_bytes)
    zf = zipfile.ZipFile(io.BytesIO(apk_bytes), 'r')

    libs = list_native_libs(zf)
    manifest_txt = read_manifest_text(zf)
    assets = list_assets(zf)
    dexes = [(i.filename, zf.read(i)) for i in zf.infolist() if i.filename.endswith(".dex") or i.filename.startswith("classes")]

    rasp_detections: List[Dict[str,Any]] = []
    native_analysis: List[Dict[str,Any]] = []
    all_strings: List[str] = []

    # DEX pass (rules only; secrets disabled)
    for name, data in dexes:
        strings = extract_strings(data,4); all_strings += strings
        blob = "\n".join(strings)
        for rule in RASP_RULES:
            for m in rule['_re'].finditer(blob):
                excerpt = blob[max(0, m.start()-120): m.end()+120].replace("\n"," ")
                if rule['category']=='vendor' and not vendor_strong(excerpt):
                    continue
                rasp_detections.append({
                    "file": name, "type":"dex",
                    "severity": rule['severity'], "category": rule['category'],
                    "what": rule['name'], "why": rule['why'], "try": rule['advice'],
                    "needle": m.group(0)
                })

    # Native analysis (r2 heavy pass)
    if use_r2 and r2_present():
        tmp = Path("/tmp/rasp_web_libs"); tmp.mkdir(parents=True, exist_ok=True)
        for info in zf.infolist():
            if not info.filename.endswith(".so"): continue
            so_name = os.path.basename(info.filename)
            so_path = tmp / so_name
            so_path.write_bytes(zf.read(info))

            imps = set(r2_imports(so_path))
            strs = r2_strings(so_path)

            for sym in ("ptrace","prctl","seccomp","syscall"):
                if sym in imps:
                    item={"lib":so_name,"kind":"import","what":f"Import:{sym}","severity":"medium",
                          "evidence":{"symbol":sym}}
                    if deep:
                        item["evidence"]["xrefs"]=r2_xrefs_to_import(so_path,sym)
                    native_analysis.append(item)

            for off, txt in strs:
                for nm, rx, sev, _ in NATIVE_STR_RULES:
                    if rx.search(txt):
                        native_analysis.append({"lib":so_name,"kind":"string","what":nm,"severity":sev,
                                                "evidence":{"byte_offset":off,"needle":txt}})

    # Native lite pass (always on; fills gaps if r2 missing)
    native_analysis += native_lite_scan(zf)

    # Score + SDK Inventory + linkage

    # Optional decompilation pass (jadx/apktool)
    endpoints: List[Dict[str,Any]] = []
    decomp_meta = {"used": None, "files": 0}
    if decomp:
        try:
            decomp_hits, endpoints, pretty_manifest, meta = decompile_and_scan(apk_bytes)
            if pretty_manifest:
                manifest_txt = pretty_manifest or manifest_txt
            if decomp_hits:
                rasp_detections.extend(decomp_hits)
            decomp_meta = meta
        except Exception:
            pass
    overall = sum(SEV_SCORE.get(x["severity"],1) for x in rasp_detections)
    risk = "GREEN" if overall < 25 else ("AMBER" if overall < 60 else "RED")
    pkgs = collect_packages_from_dex_strings(all_strings)
    sdk_inventory = detect_sdks(pkgs, libs, manifest_txt, assets)
    loadlibs = dex_find_loadlibs(all_strings)
    native_suspects = rank_native_suspects(native_analysis, libs, loadlibs)

    rep["summary"] = {
        "risk": risk,
        "overall_score": overall,
        "dex_count": len(dexes),
        "lib_count": len(libs),
        "sdk_list": [x["sdk"] + (f" {x['version']}" if x.get("version") else "") for x in sdk_inventory] or [],
    }
    rep["rasp_detections"] = rasp_detections
    rep["sdk_inventory"] = sdk_inventory
    rep["native_libs"] = libs
    rep["native_analysis"] = native_analysis
    rep["native_suspects"] = native_suspects
    rep["endpoints"] = endpoints
    rep["decomp"] = decomp_meta
    rep["dex_loadlibs"] = sorted(loadlibs)
    return rep

# ---------------- Web App ----------------
app = FastAPI(title="RASP Web Dashboard")

@app.get("/", response_class=HTMLResponse)
def index():
    # No f-strings here — HTML/JS contains braces
    return HTMLResponse("""
<!DOCTYPE html><html><head><meta charset="utf-8" />
<title>Mobile RASP Scanner</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
  --bg:#0b1220; --panel:#121a2b; --muted:#94a3b8; --text:#e5e7eb; --accent:#60a5fa;
  --ok:#10b981; --warn:#f59e0b; --bad:#ef4444; --line:#1f2a44;
}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,Segoe UI,Roboto,Arial}
.wrap{max-width:1100px;margin:24px auto;padding:0 16px}
h1{font-size:28px;margin:8px 0 16px 0} .muted{color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px;margin:12px 0;box-shadow:0 6px 20px rgb(0 0 0 / 0.25)}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
button{background:var(--accent);color:#081228;border:0;border-radius:10px;padding:8px 14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.6;cursor:not-allowed}
.badge{display:inline-block;background:#0f1628;color:#cbd5e1;border:1px solid #24324f;padding:6px 10px;border-radius:999px;margin-right:8px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:#a5b4fc;text-align:left;background:#101729;position:sticky;top:0;z-index:1}
tr.sev-high{background:rgba(239,68,68,.08)} tr.sev-medium{background:rgba(245,158,11,.08)} tr.sev-info{background:rgba(96,165,250,.08)}
input[type="text"]{background:#0c1324;border:1px solid var(--line);color:var(--text);padding:8px 10px;border-radius:8px;width:260px}
.hidden{display:none}
.small{font-size:12px}
footer{color:#64748b;font-size:12px;margin:18px 0 40px}
.clickable{cursor:pointer}

/* ===== Classic UI overrides ===== */
:root {
  --bg: #0f1621;
  --card: #131b26;
}
body { font-size: 14px; }
.container { max-width: 1100px; margin: 28px auto; }
.card {
  background: var(--card);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 12px;
  padding: 14px;
  margin: 14px 0;
}
.row { display:flex; gap:12px; align-items:center; flex-wrap: wrap; }
.badge {
  background: #0d111a;
  border: 1px solid rgba(255,255,255,0.08);
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
}
table { width:100%; border-collapse: separate; border-spacing: 0; }
thead th { position: sticky; top: 0; background: var(--card); z-index: 1; }
td, th { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.06); }
tbody tr:nth-child(odd){ background: #0f1621; }
tbody tr:nth-child(even){ background: #0c121b; }
#pill-counts { display:flex; gap:10px; flex-wrap: wrap; overflow:auto; }
#decompUsed { white-space: nowrap; }
#endp .small { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size: 12px; }
#errorBar { margin-top: 8px; }
#scanBusy { margin-left: 8px; color: #9aa3b2; }
button#scanBtn { padding: 8px 16px; border-radius: 12px; }


/* Styled file input button */
input[type="file"]{
  color: var(--text);
  background: transparent;
  border: none;
}
input[type="file"]::file-selector-button{
  background: var(--accent);
  color: #081228;
  border: 0;
  border-radius: 10px;
  padding: 8px 14px;
  font-weight: 600;
  cursor: pointer;
  margin-right: 12px;
}
input[type="file"]::file-selector-button:hover{ filter: brightness(1.06); }
input[type="file"]::file-selector-button:active{ transform: translateY(1px); }
/* WebKit fallback */
input[type="file"]::-webkit-file-upload-button{
  background: var(--accent);
  color: #081228;
  border: 0;
  border-radius: 10px;
  padding: 8px 14px;
  font-weight: 600;
  cursor: pointer;
  margin-right: 12px;
}

</style>
</head>
<body>
<div id="errorBar" style="display:none;background:#fee;color:#900;padding:10px;border:1px solid #f88;margin:10px 0;border-radius:8px;"></div>
<div class="wrap">
  <h1>Mobile RASP Scanner 
  <span class="muted small">— upload an APK to analyze</span>
  <span class="badge small" style="margin-left:3px">by hackton0</span>
  </h1>

  <div class="card">
    <div class="row">
      <label>APK file: <input type="file" id="apk" accept=".apk" required></label>
      <label><input type="checkbox" id="use_r2"> Native (radare2)</label>
      <label><input type="checkbox" id="deep"> Deep xrefs</label>
      <label><input type="checkbox" id="decomp"> Decompile (jadx/apktool)</label>
      <button id="scanBtn" type="button">Scan</button> <span id="scanBusy" class="muted hidden">⏳ scanning…</span>
      <span id="busy" class="muted hidden">⏳ scanning…</span>
    </div>
    <div id="err" style="color:#fca5a5;font-weight:600;margin-top:8px"></div>
  </div>

  <div id="results" class="hidden">
  
  <div class="card">
  <div class="row">
    <button type="button" onclick="exportPDF()">Export PDF</button>
    <button type="button" onclick="exportCSVs()">Export CSVs</button>
    <span class="muted small">Tip: the PDF export opens a print dialog automatically.</span>
  </div>
</div>
  
    <div class="card">
      <span class="badge" id="pill-risk">Risk: -</span>
      <span class="badge" id="pill-score">Score: -</span>
      <span class="badge" id="pill-sdks">SDKs: -</span>
      <span class="badge" id="pill-counts">DEX: - | Libs: -</span>
      <span class="badge small muted" id="sha">sha256: -</span>
      <span class="badge small muted" id="loadlibs">loadLibrary(): -</span>
      <span class="badge small muted" id="decompUsed">decomp: -</span>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">RASP Detections</h3><input id="q1" placeholder="filter..." oninput="filterTable('rasp','q1')"></div>
      <table id="rasp"><thead><tr>
        <th style="width:18%">File</th><th>Type</th><th>Severity</th><th>Category</th><th>What</th><th>Why</th><th>Try</th><th>Needle</th>
      </tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">SDK Inventory</h3><input id="q2" placeholder="filter..." oninput="filterTable('inv','q2')"></div>
      <table id="inv"><thead><tr>
        <th style="width:30%">SDK</th><th>Version</th><th>Signals</th>
      </tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">Native Suspects (most likely RASP)</h3><input id="qS" placeholder="filter..." oninput="filterTable('sus','qS')"></div>
      <table id="sus"><thead><tr>
        <th style="width:30%">Library</th><th>Score</th><th>Reasons</th>
      </tr></thead><tbody></tbody></table>
      <div class="small muted">Tip: click a suspect to filter the tables below by that library.</div>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">Native Libraries</h3><input id="qL" placeholder="filter..." oninput="filterTable('libs','qL')"></div>
      <table id="libs"><thead><tr><th>Library (.so)</th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">Endpoints & URIs</h3><input id="qE" type="search" placeholder="filter..." oninput="filterTable('endp','qE')"></div>
      <table id="endp"><thead><tr>
        <th style="width:28%">File</th><th>Kind</th><th>Value</th><th>Note</th>
      </tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <div class="row"><h3 style="margin:0">Native Analysis</h3><input id="q4" placeholder="filter..." oninput="filterTable('nat','q4')"></div>
      <table id="nat"><thead><tr>
        <th style="width:28%">Library</th><th>Kind</th><th>Severity</th><th>What</th><th>Evidence</th>
      </tr></thead><tbody></tbody></table>
    </div>
  </div>

  <footer>Note: Static analysis only. Obfuscation/protectors may hide signals. Use authorized apps only.</footer>
</div>


<script>
function esc(s){ return (s||"").toString().replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function filterTable(id, qid) {
  let q = document.getElementById(qid).value.toLowerCase();
  document.querySelectorAll('#'+id+' tbody tr').forEach(tr=>{
    tr.style.display = [...tr.cells].some(td => td.innerText.toLowerCase().includes(q)) ? '' : 'none';
  });
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('scanBtn').addEventListener('click', uploadApk);
});
async 
function clickFilterByLib(lib){
  // set filters to lib across tables
  ['qL','q4'].forEach(id => { const el = document.getElementById(id); if (el) { el.value = lib; el.dispatchEvent(new Event('input')); }});
}
function render(d){
  document.getElementById('results').classList.remove('hidden');
  document.getElementById('pill-risk').textContent  = 'Risk: ' + (d.summary.risk||'-');
  document.getElementById('pill-score').textContent = 'Score: ' + (d.summary.overall_score||0);
  document.getElementById('pill-sdks').textContent  = 'SDKs: ' + ((d.summary.sdk_list||[]).join(', ') || 'None');
  document.getElementById('pill-counts').textContent= 'DEX: ' + (d.summary.dex_count||0) + ' | Libs: ' + (d.summary.lib_count||0);
  document.getElementById('sha').textContent        = 'sha256: ' + (d.sha256||'-');
  document.getElementById('loadlibs').textContent   = 'loadLibrary(): ' + ((d.dex_loadlibs||[]).join(', ') || '-');
  const used=(d.decomp&&d.decomp.used)||'-'; const files=(d.decomp&&d.decomp.files)||0; const badge=document.getElementById('decompUsed'); badge.textContent='decomp: '+used+' ('+files+' files)'; badge.title = (used==='apktool' ? 'Fell back to apktool (JADX missing or 0 files).' : (used==='jadx' && files===0 ? 'JADX produced 0 files.' : ''));

  // RASP
  const rtb = document.querySelector('#rasp tbody'); rtb.innerHTML='';
  (d.rasp_detections||[]).forEach(x=>{
    const tr=document.createElement('tr');
    if(x.severity==='high') tr.classList.add('sev-high'); else if(x.severity==='medium') tr.classList.add('sev-medium'); else if(x.severity==='info') tr.classList.add('sev-info');
    tr.innerHTML = `<td>${esc(x.file)}</td><td>${esc(x.type)}</td><td>${esc(x.severity)}</td><td>${esc(x.category)}</td>
                    <td>${esc(x.what)}</td><td>${esc(x.why)}</td><td>${esc(x.try)}</td><td class="small">${esc(x.needle||'')}</td>`;
    rtb.appendChild(tr);
  });

  // SDKs
  const itb = document.querySelector('#inv tbody'); itb.innerHTML='';
  (d.sdk_inventory||[]).forEach(x=>{
    const signals = Array.from(new Set((x.evidence||[]).map(e=>e[0]))).join(', ');
    const tr=document.createElement('tr');
    tr.innerHTML = `<td>${esc(x.sdk)}</td><td>${esc(x.version||'')}</td><td>${esc(signals)}</td>`;
    itb.appendChild(tr);
  });

  // Native suspects
  const stb = document.querySelector('#sus tbody'); stb.innerHTML='';
  (d.native_suspects||[]).forEach(s=>{
    const tr=document.createElement('tr'); tr.classList.add('clickable');
    tr.innerHTML = `<td>${esc(s.lib)}</td><td>${esc(s.score)}</td><td>${esc((s.reasons||[]).join(', '))}</td>`;
    tr.addEventListener('click', ()=>clickFilterByLib(s.lib));
    stb.appendChild(tr);
  });

  // Endpoints & URIs
  { const etb = document.querySelector('#endp tbody'); if(etb){ etb.innerHTML=''; (d.endpoints||[]).forEach(e=>{ const tr=document.createElement('tr'); tr.innerHTML = `<td>${esc(e.file||'')}</td><td>${esc(e.kind||'')}</td><td class="small">${esc(e.value||'')}</td><td>${esc(e.note||'')}</td>`; etb.appendChild(tr); }); } }

  // Native libs
  const ltb = document.querySelector('#libs tbody'); ltb.innerHTML='';
  (d.native_libs||[]).forEach(n=>{
    const tr=document.createElement('tr'); tr.innerHTML = `<td>${esc(n)}</td>`;
    ltb.appendChild(tr);
  });

  // Native analysis
  const ntb = document.querySelector('#nat tbody'); ntb.innerHTML='';
  (d.native_analysis||[]).forEach(n=>{
    const ev = esc(JSON.stringify(n.evidence||{}));
    const tr=document.createElement('tr');
    if(n.severity==='high') tr.classList.add('sev-high'); else if(n.severity==='medium') tr.classList.add('sev-medium'); else if(n.severity==='info') tr.classList.add('sev-info');
    tr.innerHTML = `<td>${esc(n.lib)}</td><td>${esc(n.kind)}</td><td>${esc(n.severity||'')}</td><td>${esc(n.what)}</td><td class="small">${ev}</td>`;
    ntb.appendChild(tr);
  });
}

function showError(msg){
  try{
    const bar=document.getElementById('errorBar');
    if(!bar){ alert(msg); return; }
    bar.textContent = (typeof msg==='string'? msg : JSON.stringify(msg));
    bar.style.display='block'; clearTimeout(window.__errTimer); window.__errTimer=setTimeout(()=>{bar.style.display='none';},6000);
  }catch(e){ console.error(e); }
}
window.uploadApk = uploadApk;


function exportPDF(){
  try{
    const container = document.querySelector('.wrap');
    if(!container){ showError('Nothing to export yet.'); return; }
    const css = `
      body{background:#fff;color:#000;font:14px system-ui,Segoe UI,Roboto,Ubuntu,sans-serif}
      .wrap{max-width:1000px;margin:0 auto}
      .card{box-shadow:none;border:1px solid #ddd !important;border-radius:10px !important}
      table{width:100%;border-collapse:collapse}
      th,td{border:1px solid #ddd;padding:8px}
      @page{size:A4;margin:12mm}
      button,#apk,#scanBtn,#scanBusy,.row input[type=checkbox],label[for=apk]{display:none !important}
    `;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>RASP Report</title><style>${css}</style></head><body>${container.outerHTML}</body></html>`;
    const w = window.open('', '_blank');
    if(!w){ showError('Popup blocked. Allow popups to export PDF.'); return; }
    w.document.open(); w.document.write(html); w.document.close(); w.focus();
    setTimeout(()=>{ try{ w.print(); } finally { w.close(); } }, 300);
  }catch(e){ showError(e); }
}

window.exportPDF = exportPDF;



document.addEventListener('DOMContentLoaded', function(){
  const btn = document.getElementById('scanBtn');
  if(btn && !btn.dataset.bound){
    btn.addEventListener('click', uploadApk);
    btn.dataset.bound = '1';
  }
});
window.uploadApk = uploadApk;


function uploadApk(){
  try{
    var btn = document.getElementById('scanBtn');
    var fi  = document.getElementById('apk');
    if(!fi || !fi.files || !fi.files[0]){ showError('Please choose an APK'); return; }
    var file = fi.files[0];
    if(btn) btn.disabled = true;

    var qs = new URLSearchParams({
      use_r2: (document.getElementById('use_r2') && document.getElementById('use_r2').checked) ? '1' : '0',
      deep:   (document.getElementById('deep')   && document.getElementById('deep').checked)   ? '1' : '0',
      decomp: (document.getElementById('decomp') && document.getElementById('decomp').checked) ? '1' : '0'
    });

    fetch('/api/scan_raw?' + qs.toString(), {
      method: 'POST',
      body: file,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': file.name }
    })
    .then(function(r){
      if(!r.ok){ return r.text().then(function(t){ throw new Error('HTTP '+r.status+': '+t); }); }
      return r.json();
    })
    .then(function(d){ window.__report=d; render(d); })
    .catch(function(e){ showError('Scan failed: '+e); })
    .finally(function(){ if(btn) btn.disabled=false; });
  }catch(e){ showError(e); }
}

document.addEventListener('DOMContentLoaded', function(){
  var btn = document.getElementById('scanBtn');
  if(btn && !btn.__bound){
    btn.addEventListener('click', uploadApk);
    btn.__bound = true;
  }
});
window.uploadApk = uploadApk;

</script>
</body></html>
    """)

@app.post("/api/scan")
async def api_scan(apk: UploadFile = File(...), use_r2: str = Form("0"), deep: str = Form("0"), decomp: str = Form("0")):
    try:
        data = await apk.read()
        rep = scan_bytes(data, use_r2=(use_r2=="1"), deep=(deep=="1"), decomp=(decomp=="1"))
        return JSONResponse(rep)
    except zipfile.BadZipFile:
        return JSONResponse({"error":"Not a valid APK (zip) file."}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ---------------- Decompiler helpers (jadx/apktool) & Endpoint extraction ----------------
def _which(bin_name: str):
    try:
        import shutil as _sh
        return _sh.which(bin_name)
    except Exception:
        return None

def jadx_present() -> bool:
    return bool(_which("jadx"))

def apktool_present() -> bool:
    return bool(_which("apktool"))

def _write_temp_apk(apk_bytes: bytes, base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    apk_path = base / "sample.apk"
    apk_path.write_bytes(apk_bytes)
    return apk_path

def _safe_read_text(p: Path, max_bytes: int = 2_000_000) -> str:
    try:
        if p.stat().st_size > max_bytes:
            return ""
        return p.read_text(errors="ignore")
    except Exception:
        return ""

def _scan_text_blob_for_rules(blob: str, source_file: str) -> List[Dict[str, Any]]:
    hits = []
    if not blob:
        return hits
    for rule in RASP_RULES:
        for m in rule['_re'].finditer(blob):
            excerpt = blob[max(0, m.start()-120): m.end()+120].replace("\\n"," ")
            if rule['category']=='vendor' and not vendor_strong(excerpt):
                continue
            hits.append({
                "file": source_file,
                "type": "decomp",
                "severity": rule['severity'],
                "category": rule['category'],
                "what": rule['name'],
                "why": rule['why'],
                "try": rule['advice'],
                "needle": m.group(0)
            })
    return hits

# Endpoint & URI extraction
_RE_URL = re.compile(r'\b(?:https?|wss?)://[^\s\'\"<>]+', re.I)
_RE_RETROFIT_ANN = re.compile(r'@\s*(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*\"([^\"]+)\"', re.I)
_RE_BASEURL = re.compile(r'\.baseUrl\(\s*\"([^\"]+)\"\s*\)', re.I)
_RE_OKHTTP_URL = re.compile(r'\bnew\s+Request\.Builder\(\)\.url\(\s*\"([^\"]+)\"', re.I)
_RE_WEBVIEW_JS = re.compile(r'addJavascriptInterface\s*\(\s*new\s+([\w$.]+)\s*\(', re.I)
_RE_WEBVIEW_ENABLE = re.compile(r'getSettings\(\)\.setJavaScriptEnabled\(\s*true\s*\)', re.I)

def extract_endpoints_from_text(text: str, source_file: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not text:
        return out
    for m in _RE_URL.finditer(text):
        out.append({"file": source_file, "kind": "url", "value": m.group(0), "note": ""})
    bases = [m.group(1) for m in _RE_BASEURL.finditer(text)]
    for m in _RE_RETROFIT_ANN.finditer(text):
        method, path = m.group(1), m.group(2)
        note = f"Retrofit @{method}"
        if bases and path.startswith("/"):
            for b in set(bases):
                out.append({"file": source_file, "kind": "retrofit", "value": b.rstrip("/") + path, "note": note})
        out.append({"file": source_file, "kind": "retrofit", "value": path, "note": note})
    for m in _RE_OKHTTP_URL.finditer(text):
        out.append({"file": source_file, "kind": "okhttp", "value": m.group(1), "note": "OkHttp Request.Builder.url"})
    if _RE_WEBVIEW_ENABLE.search(text):
        out.append({"file": source_file, "kind": "webview", "value": "JavaScript enabled", "note": "WebView JS enabled"})
    for m in _RE_WEBVIEW_JS.finditer(text):
        out.append({"file": source_file, "kind": "webview", "value": m.group(1), "note": "addJavascriptInterface(<bridge>)"})
    return out

def extract_manifest_endpoints(manifest_txt: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not manifest_txt:
        return out
    def _attr(name: str, s: str) -> List[str]:
        rx = re.compile(name + r'="([^"]+)"', re.I)
        return [m.group(1) for m in rx.finditer(s)]
    for m in re.finditer(r'<intent-filter>(.*?)</intent-filter>', manifest_txt, flags=re.S|re.I):
        block = m.group(1)
        for d in re.finditer(r'<data\\b[^>]*>', block, flags=re.I):
            tag = d.group(0)
            schemes = _attr('android:scheme', tag) or _attr('scheme', tag)
            hosts   = _attr('android:host', tag)   or _attr('host', tag)
            paths   = _attr('android:path', tag)   or _attr('path', tag) \
                      or _attr('android:pathPrefix', tag) or _attr('pathPrefix', tag) \
                      or _attr('android:pathPattern', tag) or _attr('pathPattern', tag)
            if schemes or hosts or paths:
                out.append({"file": "AndroidManifest.xml", "kind": "deeplink",
                           "value": f"{(schemes[0] if schemes else '')}://{(hosts[0] if hosts else '')}{(paths[0] if paths else '')}",
                           "note": "intent-filter <data>"})
    return out

def decompile_and_scan(apk_bytes: bytes) -> Tuple[List[Dict[str,Any]], List[Dict[str,Any]], str, Dict[str,Any]]:
    """
    Try JADX first; if missing or yields 0 files, try apktool.
    Returns (rasp_hits, endpoints, manifest_text_if_found, meta)
    meta includes {'used': 'jadx'|'apktool'|None, 'files': N}
    """
    tmp = Path("/tmp/rasp_web_decomp")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)

    apk_path = _write_temp_apk(apk_bytes, tmp)
    out_dir = tmp / "out"
    out_dir.mkdir(exist_ok=True)

    def _scan_output(out_dir: Path, used_label: str):
        extensions = {".java", ".kt", ".smali", ".xml"}
        rasp_hits: List[Dict[str,Any]] = []
        endpoints: List[Dict[str,Any]] = []
        manifest_text = ""
        file_count = 0

        for pth in out_dir.rglob("*"):
            if not pth.is_file():
                continue
            if pth.suffix.lower() not in extensions:
                continue
            file_count += 1
            text = _safe_read_text(pth)
            rel = str(pth).replace(str(out_dir)+os.sep, f"{used_label}/")
            if pth.name.lower() == "androidmanifest.xml" and not manifest_text:
                manifest_text = text
            rasp_hits.extend(_scan_text_blob_for_rules(text, source_file=rel))
            endpoints.extend(extract_endpoints_from_text(text, source_file=rel))
            if len(rasp_hits) > 10000:
                break

        endpoints.extend(extract_manifest_endpoints(manifest_text))
        return rasp_hits, endpoints, manifest_text, file_count

    used = None

    if jadx_present():
        used = "jadx"
        try:
            subprocess.run(["jadx", "-d", str(out_dir), str(apk_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
        except Exception:
            pass
        rasp_hits, endpoints, manifest_text, file_count = _scan_output(out_dir, used_label="jadx")
        if file_count == 0 and apktool_present():
            used = "apktool"
            try:
                shutil.rmtree(out_dir, ignore_errors=True)
                out_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(["apktool", "d", "-f", "-o", str(out_dir), str(apk_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
            except Exception:
                pass
            rasp_hits, endpoints, manifest_text, file_count = _scan_output(out_dir, used_label="apktool")
        return (rasp_hits, endpoints, manifest_text or "", {"used": used, "files": file_count})

    if apktool_present():
        used = "apktool"
        try:
            subprocess.run(["apktool", "d", "-f", "-o", str(out_dir), str(apk_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
        except Exception:
            pass
        rasp_hits, endpoints, manifest_text, file_count = _scan_output(out_dir, used_label="apktool")
        return (rasp_hits, endpoints, manifest_text or "", {"used": used, "files": file_count})

    return ([], [], "", {"used": None, "files": 0})


@app.post("/api/scan_raw")
async def api_scan_raw(request: Request, use_r2: str = Query("0"), deep: str = Query("0"), decomp: str = Query("0"), x_filename: str = Header(default="unknown.apk")):
    try:
        data = await request.body()
        rep = scan_bytes(data, use_r2=(use_r2=="1"), deep=(deep=="1"), decomp=(decomp=="1"))
        rep["upload"] = {"mode":"raw","filename":x_filename,"size":len(data)}
        return JSONResponse(rep)
    except Exception as e:
        return JSONResponse({"detail": f"scan_raw failure: {e!r}"}, status_code=500)


@app.get("/favicon.ico")
def favicon():
    import base64
    data = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottQAAAABJRU5ErkJggg==")
    from fastapi.responses import Response
    return Response(content=data, media_type="image/png")
