#!/usr/bin/env python3
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

# =========================
# Paths (host-mounted)
# =========================
RUNS_DIR = os.environ.get("RUNS_DIR", "/runs")
OUTDIR = os.path.join(RUNS_DIR, "output")
REPORTDIR = os.path.join(RUNS_DIR, "reports")
STATUSDIR = os.path.join(RUNS_DIR, "status")

# =========================
# Tunables / timeouts
# =========================
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "12"))
HTTP_RETRIES = int(os.environ.get("HTTP_RETRIES", "2"))

WHOIS_TIMEOUT = int(os.environ.get("WHOIS_TIMEOUT", "25"))
DIG_TIMEOUT = int(os.environ.get("DIG_TIMEOUT", "20"))

NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "900"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "600"))
ZAP_TIMEOUT = int(os.environ.get("ZAP_TIMEOUT", "900"))

ZAP_MODE = os.environ.get("ZAP_MODE", "baseline").strip().lower()   # baseline | full
ZAP_ACTIVE = os.environ.get("ZAP_ACTIVE", "0").strip() == "1"       # only used for full scan
ZAP_SPIDER_MINS = int(os.environ.get("ZAP_SPIDER_MINS", "3"))
ZAP_MAX_TIME_MINS = int(os.environ.get("ZAP_MAX_TIME_MINS", "12"))
ZAP_USE_AJAX = os.environ.get("ZAP_USE_AJAX", "1").strip() == "1"
ZAP_INCLUDE_ALPHA = os.environ.get("ZAP_INCLUDE_ALPHA", "1").strip() == "1"
ZAP_WRK = os.environ.get("ZAP_WRK", "/zap/wrk").strip()             # MUST be mounted for file outputs

SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT", "120"))
HARVESTER_TIMEOUT = int(os.environ.get("HARVESTER_TIMEOUT", "240"))

SUBDOMAIN_ENUM = os.environ.get("SUBDOMAIN_ENUM", "1").strip() == "1"
SUBDOMAIN_PROBE = os.environ.get("SUBDOMAIN_PROBE", "1").strip() == "1"
SUBDOMAIN_MAX = int(os.environ.get("SUBDOMAIN_MAX", "300"))

# Nmap profiles
# SAFE: no special privileges; works widely
# FULL: uses -sS -sV -O --osscan-guess -p-
NMAP_PROFILE = os.environ.get("NMAP_PROFILE", "SAFE").strip().upper()
NMAP_MODE = os.environ.get("NMAP_MODE", "auto").lower().strip()  # auto/ip/host

IMPORTANT_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HEADER_FIX_MAP = {
    "content-security-policy": "Add Content-Security-Policy (start Report-Only, tune, then enforce).",
    "strict-transport-security": "Enable HSTS (Strict-Transport-Security) with safe max-age; includeSubDomains only if appropriate.",
    "x-frame-options": "Add X-Frame-Options (or CSP frame-ancestors) to reduce clickjacking risk.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff to reduce MIME sniffing issues.",
    "referrer-policy": "Set Referrer-Policy (e.g., strict-origin-when-cross-origin).",
    "permissions-policy": "Set Permissions-Policy to restrict browser features you don't need.",
}

DANGEROUS_PORTS = {
    21:  "FTP exposed",
    22:  "SSH exposed",
    23:  "Telnet exposed",
    25:  "SMTP exposed (verify intent)",
    110: "POP3 exposed (verify intent)",
    143: "IMAP exposed (verify intent)",
    445: "SMB exposed",
    1433: "MSSQL exposed",
    1521: "Oracle DB exposed",
    2049: "NFS exposed",
    2375: "Docker API exposed (no TLS!)",
    3306: "MySQL exposed",
    3389: "RDP exposed",
    5432: "PostgreSQL exposed",
    5900: "VNC exposed",
    6379: "Redis exposed",
    8080: "Alt HTTP exposed (often CDN edge / alternate service)",
    8443: "Alt HTTPS exposed (often CDN edge / alternate service)",
    9200: "Elasticsearch exposed",
    27017: "MongoDB exposed",
}

# =========================
# Helpers
# =========================
def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def ensure_dirs():
    os.makedirs(OUTDIR, exist_ok=True)
    os.makedirs(REPORTDIR, exist_ok=True)
    os.makedirs(STATUSDIR, exist_ok=True)
    os.makedirs(STATUSDIR, exist_ok=True)

def safe_name_from_host(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", host)

def write_status(scan_id: str, stage: str, **extra) -> None:
    """
    Writes a small status JSON so a UI (or tail -f) can show progress.
    Files:
      /runs/status/<scan_id>.json
      /runs/status/latest.json
    """
    try:
        ensure_dirs()
        payload = {
            "scan_id": scan_id,
            "stage": stage,
            "ts": datetime.now().isoformat(timespec="seconds"),
        }
        payload.update(extra or {})
        p1 = Path(STATUSDIR) / f"{scan_id}.json"
        p2 = Path(STATUSDIR) / "latest.json"
        p1.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        p2.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        # Never crash the scan due to status writing
        pass

def run_cmd(cmd: list[str], timeout: int) -> tuple[int, str, str, str]:
    """
    Returns: (rc, stdout, stderr, status)
      status: ok | timeout | error
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or ""), (p.stderr or ""), "ok"
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return 124, out, err, "timeout"
    except Exception as e:
        return 1, "", str(e), "error"

def looks_like_url(s: str) -> bool:
    try:
        u = urlparse(s)
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False

def prompt_target() -> str:
    while True:
        s = input("Enter target URL (format: https://example.com OR http://example.com): ").strip()
        if not s.startswith(("http://", "https://")):
            print("[!] Please include scheme. Example: https://example.com")
            continue
        if not looks_like_url(s):
            print("[!] Invalid URL. Expected: https://example.com or http://example.com")
            continue
        return s

def dig_record(name: str, record: str) -> list[str]:
    rc, out, err, status = run_cmd(["dig", "+short", name, record], timeout=DIG_TIMEOUT)
    if status != "ok" or rc != 0 or not out.strip():
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]

def whois_lookup(domain: str) -> dict:
    rc, out, err, status = run_cmd(["whois", domain], timeout=WHOIS_TIMEOUT)
    text = out if out.strip() else err
    head = "\n".join(text.splitlines()[:120]).strip()
    return {
        "status": status,
        "return_code": rc,
        "whois_head": head,
        "stderr_tail": (err or "")[-400:],
    }

def detect_cdn(ns_records: list[str], headers: dict) -> str:
    ns_join = " ".join(ns_records).lower()
    if "cloudflare" in ns_join:
        return "Cloudflare"
    if "akam" in ns_join or "akamai" in ns_join:
        return "Akamai"
    if "fastly" in ns_join:
        return "Fastly"
    if "cdn77" in ns_join:
        return "CDN77"

    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    if "cf-ray" in h or "cloudflare" in h.get("server", ""):
        return "Cloudflare"
    if "akamai" in h.get("server", "") or "akamai" in h.get("x-akamai-transformed", ""):
        return "Akamai"
    return ""

# =========================
# A) Better reachability logic (less false negatives)
# =========================
def tcp_connect_test(ip: str, port: int, timeout: int = 4) -> dict:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"ok": True, "error": ""}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_attempt(url: str, method: str, timeout: int) -> dict:
    try:
        r = requests.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "site-checker/1.0"},
        )
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {
            "ok": True,
            "method": method,
            "status_code": r.status_code,
            "final_url": r.url,
            "headers": headers,
            "error": "",
        }
    except requests.RequestException as e:
        return {
            "ok": False,
            "method": method,
            "status_code": 0,
            "final_url": "",
            "headers": {},
            "error": str(e),
        }

def http_probe_sequence(target_url: str, host: str, a_records: list[str]) -> dict:
    """
    Tries: HEAD then GET, retries, and scheme fallback.
    Returns a structured result explaining DNS vs connect vs HTTP issues.
    """
    result = {
        "ok": False,
        "input_url": target_url,
        "final_url": "",
        "status_code": 0,
        "headers": {},
        "error": "",
        "attempts": [],
        "dns_a": a_records[:10],
        "tcp": {},
    }

    if a_records:
        ip = a_records[0]
        result["tcp"]["ip"] = ip
        result["tcp"]["connect_80"] = tcp_connect_test(ip, 80)
        result["tcp"]["connect_443"] = tcp_connect_test(ip, 443)

    urls = [target_url]
    if target_url.startswith("https://"):
        urls.append("http://" + target_url[len("https://"):])
    elif target_url.startswith("http://"):
        urls.append("https://" + target_url[len("http://"):])

    for u in urls:
        for _try in range(HTTP_RETRIES + 1):
            for method in ("HEAD", "GET"):
                att = http_attempt(u, method, HTTP_TIMEOUT)
                result["attempts"].append(att)
                if att["ok"]:
                    result["ok"] = True
                    result["final_url"] = att["final_url"]
                    result["status_code"] = att["status_code"]
                    result["headers"] = att["headers"]
                    result["error"] = ""
                    return result

    last_err = ""
    for a in reversed(result["attempts"]):
        if a.get("error"):
            last_err = a["error"]
            break
    result["error"] = last_err or "Unreachable from this machine/network."
    return result

# =========================
# B) Stable in the wild (never crash on tool timeouts)
# =========================
def choose_nmap_target(host: str, a_records: list[str], cdn_hint: str) -> tuple[str, str]:
    if NMAP_MODE == "host":
        return "host", host
    if NMAP_MODE == "ip":
        return ("ip", a_records[0]) if a_records else ("host", host)

    if cdn_hint and a_records:
        return "ip", a_records[0]
    return "host", host

def nmap_scan(scan_target: str, out_prefix: str) -> dict:
    out_xml = f"{out_prefix}.xml"
    out_txt = f"{out_prefix}.txt"

    if NMAP_PROFILE == "FULL":
        cmd = ["nmap", "-T4", "-sS", "-sV", "-O", "--osscan-guess", "-p-", "--open", "-oX", out_xml, "-oN", out_txt, scan_target]
    else:
        cmd = ["nmap", "-sT", "-Pn", "-T3", "-sV", "--version-light", "--top-ports", "1000", "--open",
               "--max-retries", "2", "--host-timeout", "8m", "-oX", out_xml, "-oN", out_txt, scan_target]

    rc, out, err, status = run_cmd(cmd, timeout=NMAP_TIMEOUT)
    return {
        "profile": NMAP_PROFILE,
        "scan_target": scan_target,
        "command": " ".join(cmd),
        "status": status,
        "return_code": rc,
        "stdout_tail": (out or "")[-1200:],
        "stderr_tail": (err or "")[-1200:],
        "output_xml": out_xml,
        "output_txt": out_txt,
    }

def parse_nmap_services(nmap_txt_path: str) -> dict:
    """
    Extract services + versions + OS guess lines from Nmap -oN output.
    """
    out = {"ports": [], "os_guess": "", "service_info": "", "raw_port_lines": []}
    if not nmap_txt_path or not os.path.exists(nmap_txt_path):
        return out

    in_ports = False
    ports = []

    try:
        lines = Path(nmap_txt_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return out

    for line in lines:
        l = line.rstrip("\n")

        if l.strip().startswith("PORT") and "STATE" in l and "SERVICE" in l:
            in_ports = True
            continue

        if in_ports:
            if not l.strip():
                continue
            if l.startswith(("Service Info:", "Device type:", "Running (", "OS CPE:", "Aggressive OS guesses:", "No exact OS matches")):
                in_ports = False

            m = re.match(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", l.strip())
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                svc = m.group(3)
                ver = (m.group(4) or "").strip()
                ports.append({"port": port, "proto": proto, "service": svc, "version": ver})
                out["raw_port_lines"].append(l.strip())

        if l.startswith("Aggressive OS guesses:"):
            out["os_guess"] = l.split(":", 1)[-1].strip()
        if l.startswith("Running ("):
            out["os_guess"] = l.strip()
        if l.startswith("Service Info:"):
            out["service_info"] = l.split(":", 1)[-1].strip()

    out["ports"] = ports
    return out

def parse_nmap_open_ports(nmap_txt_path: str) -> list[int]:
    ports = []
    if not nmap_txt_path or not os.path.exists(nmap_txt_path):
        return ports
    try:
        with open(nmap_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.match(r"^(\d+)/tcp\s+open\b", line.strip())
                if m:
                    ports.append(int(m.group(1)))
    except Exception:
        return ports
    return sorted(set(ports))

def nuclei_scan(url: str, out_jsonl: str) -> dict:
    cmd = ["nuclei", "-u", url, "-jsonl", "-follow-redirects", "-severity", "low,medium,high,critical", "-o", out_jsonl, "-no-color"]
    rc, out, err, status = run_cmd(cmd, timeout=NUCLEI_TIMEOUT)
    return {
        "command": " ".join(cmd),
        "status": status,
        "return_code": rc,
        "stdout_tail": (out or "")[-1200:],
        "stderr_tail": (err or "")[-1200:],
        "output_jsonl": out_jsonl,
    }

def parse_nuclei_jsonl(path: str) -> dict:
    findings = []
    if not path or not os.path.exists(path):
        return {"count": 0, "by_severity": {}, "top": [], "raw": []}

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return {"count": 0, "by_severity": {}, "top": [], "raw": []}

    by_sev = {}
    top_items = []
    seen = set()
    for item in findings:
        sev = (item.get("info", {}) or {}).get("severity") or item.get("severity") or "info"
        sev = str(sev).lower().strip()
        by_sev[sev] = by_sev.get(sev, 0) + 1

        tid = item.get("template-id") or ""
        matched = item.get("matched-at") or item.get("host") or item.get("url") or ""
        key = (tid, matched, sev)
        if tid and key not in seen:
            seen.add(key)
            top_items.append({"severity": sev, "template_id": tid, "matched": matched})
        if len(top_items) >= 8:
            break

    return {"count": len(findings), "by_severity": by_sev, "top": top_items, "raw": findings[:200]}

def zap_scan(url: str, out_prefix: str) -> dict:
    """
    Stronger ZAP scan runner.
    NOTE: output must be in a writable directory. If /zap/wrk isn't mounted,
    we fall back to /runs/output so you still get files.
    """
    out_json = f"{out_prefix}.json"
    out_html = f"{out_prefix}.html"
    out_md = f"{out_prefix}.md"

    base_cmd = ["zap-baseline.py", "-t", url, "-J", out_json, "-r", out_html, "-w", out_md, "-I"]
    base_cmd += ["-m", str(max(1, ZAP_SPIDER_MINS))]
    base_cmd += ["-T", str(max(3, ZAP_MAX_TIME_MINS))]
    if ZAP_INCLUDE_ALPHA:
        base_cmd += ["-a"]
    if ZAP_USE_AJAX:
        base_cmd += ["-j"]

    if ZAP_MODE == "full":
        if not ZAP_ACTIVE:
            return {
                "command": " ".join(base_cmd),
                "status": "skipped",
                "return_code": 0,
                "stdout_tail": "",
                "stderr_tail": "ZAP full scan requires ZAP_ACTIVE=1 (disabled by default).",
                "output_json": out_json,
                "output_html": out_html,
                "output_md": out_md,
            }
        cmd = ["zap-full-scan.py", "-t", url, "-J", out_json, "-r", out_html, "-w", out_md]
        if ZAP_USE_AJAX:
            cmd += ["-j"]
        if ZAP_INCLUDE_ALPHA:
            cmd += ["-a"]
        cmd += ["-T", str(max(10, ZAP_MAX_TIME_MINS))]
    else:
        cmd = base_cmd

    rc, out, err, status = run_cmd(cmd, timeout=ZAP_TIMEOUT)
    return {
        "command": " ".join(cmd),
        "status": status,
        "return_code": rc,
        "stdout_tail": (out or "")[-2000:],
        "stderr_tail": (err or "")[-2000:],
        "output_json": out_json,
        "output_html": out_html,
        "output_md": out_md,
    }

def parse_zap_json(zap_json_path: str) -> dict:
    if not zap_json_path or not os.path.exists(zap_json_path):
        return {"count": 0, "by_risk": {}, "top": [], "raw": {}}

    try:
        with open(zap_json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return {"count": 0, "by_risk": {}, "top": [], "raw": {}}

    alerts = []
    try:
        if isinstance(data, dict) and "site" in data and data["site"]:
            alerts = (data["site"][0] or {}).get("alerts", []) or []
    except Exception:
        alerts = []

    by_risk = {}
    top = []
    seen = set()
    for a in alerts:
        risk = (a.get("risk") or a.get("riskdesc") or "Informational").strip()
        risk_norm = risk.split(" ")[0].capitalize()
        by_risk[risk_norm] = by_risk.get(risk_norm, 0) + 1

        name = (a.get("name") or "").strip()
        if name and name not in seen:
            seen.add(name)
            top.append({"risk": risk_norm, "name": name})
        if len(top) >= 8:
            break

    return {"count": len(alerts), "by_risk": by_risk, "top": top, "raw": data}

# =========================
# C) Subdomain enumeration (multi-tool)
# =========================
def subdomain_enum(domain: str) -> dict:
    merged = set()
    details = {}

    if tool_exists("amass"):
        cmd = ["amass", "enum", "-passive", "-d", domain]
        rc, out, err, status = run_cmd(cmd, timeout=SUBFINDER_TIMEOUT)
        subs = [x.strip() for x in (out or "").splitlines() if x.strip() and x.strip().endswith(domain)]
        for x in subs:
            merged.add(x)
        details["amass"] = {"status": status, "return_code": rc, "count": len(subs), "stderr_tail": (err or "")[-800:]}
    else:
        details["amass"] = {"status": "missing", "return_code": 127, "count": 0, "stderr_tail": "amass not found"}

    if tool_exists("sublist3r"):
        tmp_out = "/tmp/sublist3r.txt"
        try:
            Path(tmp_out).unlink(missing_ok=True)
        except Exception:
            pass
        cmd = ["sublist3r", "-d", domain, "-o", tmp_out]
        rc, out, err, status = run_cmd(cmd, timeout=SUBFINDER_TIMEOUT)
        subs = []
        try:
            if Path(tmp_out).exists():
                subs = [x.strip() for x in Path(tmp_out).read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
        except Exception:
            subs = []
        subs = [x for x in subs if x.endswith(domain)]
        for x in subs:
            merged.add(x)
        details["sublist3r"] = {"status": status, "return_code": rc, "count": len(subs), "stderr_tail": (err or "")[-800:]}
    else:
        details["sublist3r"] = {"status": "missing", "return_code": 127, "count": 0, "stderr_tail": "sublist3r not found"}

    merged_list = sorted(merged)[:SUBDOMAIN_MAX]
    return {"status": "ok", "count": len(merged_list), "subs": merged_list, "tools": details}

def harvester_enum(domain: str) -> dict:
    if not tool_exists("theHarvester"):
        return {"status": "missing", "count": 0, "items": [], "stderr_tail": "theHarvester not found"}

    cmd = ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,crtsh"]
    rc, out, err, status = run_cmd(cmd, timeout=HARVESTER_TIMEOUT)

    found = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if domain in line and "." in line and "@" not in line and "http" not in line:
            found.append(line)

    found = sorted(set(found))[:SUBDOMAIN_MAX]
    return {
        "tool": "theHarvester",
        "status": status,
        "return_code": rc,
        "count": len(found),
        "items": found,
        "stderr_tail": (err or "")[-800:],
    }

def probe_subdomains(subs: list[str]) -> dict:
    results = []
    for s in subs[:50]:
        for base in (f"https://{s}", f"http://{s}"):
            att = http_attempt(base, "HEAD", 6)
            if att["ok"]:
                results.append({"subdomain": s, "url": base, "status_code": att["status_code"], "final_url": att["final_url"]})
                break
    return {"probed": min(len(subs), 50), "reachable": len(results), "results": results[:50]}

# =========================
# D) Dangerous ports deep check (safe banner grabs)
# =========================
def banner_grab(host: str, ip: str, port: int) -> dict:
    preferred = ip or ""
    base = {"port": port, "target": preferred or host, "ok": False, "summary": "", "evidence": ""}

    targets = []
    if preferred:
        targets.append(preferred)
    targets.append(host)

    conn = None
    chosen = None
    for t in targets:
        c = tcp_connect_test(t, port, timeout=6)
        if c["ok"]:
            conn = c
            chosen = t
            break
        conn = c

    if not conn or not conn["ok"]:
        base["summary"] = "connect failed"
        base["evidence"] = (conn or {}).get("error", "")
        return base

    base["target"] = chosen
    target = chosen

    if port in (80, 8080):
        url = f"http://{host}:{port}/"
        att = http_attempt(url, "HEAD", 8)
        base["ok"] = att["ok"]
        base["summary"] = f"http head {att.get('status_code', 0)}" if att["ok"] else "http head failed"
        base["evidence"] = att.get("error") or ""
        return base

    if port in (443, 8443):
        cmd = ["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", host, "-brief"]
        rc, out, err, status = run_cmd(cmd, timeout=10)
        base["ok"] = (status == "ok" and rc == 0)
        base["summary"] = "tls handshake ok" if base["ok"] else "tls handshake failed/partial"
        base["evidence"] = (out or err)[-600:]
        return base

    cmd = ["nc", "-w", "4", target, str(port)]
    rc, out, err, status = run_cmd(cmd, timeout=6)
    base["ok"] = True if status in ("ok", "timeout") else False
    base["summary"] = "banner read attempted"
    base["evidence"] = (out or err)[-600:]
    return base

def deep_check_ports(host: str, ip: str, open_ports: list[int]) -> dict:
    interesting = [p for p in open_ports if p in DANGEROUS_PORTS or p in (80, 443, 8080, 8443)]
    interesting = interesting[:20]
    results = []
    for p in interesting:
        results.append(banner_grab(host, ip, p))
    return {"checked": len(interesting), "results": results}

# =========================
# Reporting + Risk
# =========================
def compute_risk(missing_headers: list[str], nuclei_by_sev: dict, zap_by_risk: dict, open_ports: list[int]) -> str:
    if nuclei_by_sev.get("critical", 0) > 0 or nuclei_by_sev.get("high", 0) > 0:
        return "High"
    if zap_by_risk.get("High", 0) > 0:
        return "High"

    if nuclei_by_sev.get("medium", 0) > 0 or zap_by_risk.get("Medium", 0) > 0:
        return "Medium"

    for p in open_ports:
        if p in (22, 3389, 2375, 3306, 5432, 6379, 9200, 27017):
            return "Medium"

    if len(missing_headers) >= 4:
        return "Medium"

    return "Low"

def render_ports(open_ports: list[int], cdn_hint: str = "") -> str:
    if not open_ports:
        return "(none detected)"
    parts = []
    for p in open_ports:
        parts.append(f"{p}/tcp(!)" if p in DANGEROUS_PORTS else f"{p}/tcp")
    return ", ".join(parts)

def write_report(report_path: str, combined: dict) -> None:
    lines = []
    lines.append("# Website Security Health Check Report (Combined)\n")
    lines.append(f"- Date: {combined.get('timestamp')}\n")
    lines.append(f"- Target: {combined.get('target')}\n")
    lines.append(f"- Final URL: {combined.get('final_url') or '(none)'}\n")

    lines.append("\n## Security Profile (no LLM)\n\n")
    lines.append(f"- Risk level: **{combined.get('risk_level','Low')}**\n")
    if combined.get("cdn_hint"):
        lines.append(f"- CDN hint: {combined.get('cdn_hint')}\n")

    probe = combined.get("http_probe", {}) or {}
    if not probe.get("ok", False):
        lines.append(f"- Reachability: **DOWN / unreachable**\n")
        lines.append(f"  - Error: {probe.get('error','')}\n")
        lines.append(f"  - DNS A: {probe.get('dns_a', [])}\n")
        if probe.get("tcp"):
            lines.append(f"  - TCP checks: {probe.get('tcp')}\n")
        lines.append("\n## Outputs\n\n")
        lines.append(f"- Combined JSON: `{combined.get('combined_json_path','')}`\n")
        lines.append(f"- Report: `{combined.get('report_path','')}`\n")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("".join(lines))
        return

    missing = combined.get("missing_security_headers") or []
    present = combined.get("present_security_headers") or []
    if missing:
        lines.append(f"- Missing security headers: {', '.join(missing)}\n")
    else:
        lines.append("- Missing security headers: (none from checked list)\n")
    if present:
        lines.append(f"- Present security headers: {', '.join(present)}\n")

    nuclei_sum = combined.get("nuclei_summary", {}) or {}
    zap_sum = combined.get("zap_summary", {}) or {}
    nmap_sum = combined.get("nmap_summary", {}) or {}

    lines.append(f"- Nuclei findings (count): {nuclei_sum.get('count', 0)} (status={nuclei_sum.get('status','')})\n")
    lines.append(f"- ZAP alerts (count): {zap_sum.get('count', 0)} (status={zap_sum.get('status','')})\n")

    open_ports = nmap_sum.get("open_ports", []) or []
    lines.append(f"- Nmap open ports: {render_ports(open_ports, combined.get('cdn_hint',''))}\n")

    svc_list = (nmap_sum.get("services") or [])
    os_guess = (nmap_sum.get("os_guess") or "").strip()
    svc_info = (nmap_sum.get("service_info") or "").strip()

    if svc_list:
        lines.append("\n## Ports & Services (Nmap)\n\n")
        for it in svc_list[:200]:
            pnum = it.get("port")
            proto = it.get("proto", "tcp")
            svc = it.get("service", "")
            ver = it.get("version", "")
            if ver:
                lines.append(f"- {pnum}/{proto}: {svc} — {ver}\n")
            else:
                lines.append(f"- {pnum}/{proto}: {svc}\n")

        if os_guess:
            lines.append("\n### OS Guess (Nmap)\n\n")
            lines.append(f"- {os_guess}\n")
        if svc_info:
            lines.append("\n### Service Info (Nmap)\n\n")
            lines.append(f"- {svc_info}\n")

    lines.append(f"- Nmap profile: {combined.get('nmap', {}).get('profile','')}\n")

    if combined.get("subdomains"):
        lines.append(f"- Subdomain enum: {combined['subdomains'].get('count',0)} found (multi-tool)\n")
    if combined.get("harvester"):
        lines.append(f"- theHarvester: {combined['harvester'].get('count',0)} items\n")

    lines.append("\n## Notable Observations\n\n")
    if combined.get("cdn_hint"):
        lines.append("- CDN note: CDNs/WAFs may add/remove headers; validate at origin if you control it.\n")
        lines.append("- Nmap note: If behind a CDN proxy, Nmap may reflect edge infrastructure, not origin.\n")

    for p in open_ports:
        if p in DANGEROUS_PORTS:
            lines.append(f"- {DANGEROUS_PORTS[p]} — restrict/allowlist if not required.\n")
    if missing:
        lines.append("- Missing browser security headers reduces defense-in-depth.\n")

    deep = combined.get("port_deep_check", {}) or {}
    if deep.get("checked", 0) > 0:
        lines.append("\n## Port Deep Checks (safe banner grabs)\n\n")
        for r in deep.get("results", [])[:20]:
            lines.append(f"- {r.get('port')}/tcp: {r.get('summary')} ({'ok' if r.get('ok') else 'fail'})\n")

    lines.append("\n## Top Automated Findings\n\n")

    if nuclei_sum.get("top"):
        lines.append("### Nuclei (top)\n\n")
        for t in nuclei_sum["top"][:8]:
            lines.append(f"- [{t.get('severity')}] {t.get('template_id')} :: {t.get('matched')}\n")
    else:
        lines.append("### Nuclei (top)\n\n- No matches found (or scan timed out).\n")

    if zap_sum.get("top"):
        lines.append("\n### ZAP (top)\n\n")
        for t in zap_sum["top"][:8]:
            lines.append(f"- [{t.get('risk')}] {t.get('name')}\n")
    else:
        lines.append("\n### ZAP (top)\n\n- No alerts found (or scan not run / timed out).\n")

    lines.append("\n## Suggested Fixes (starting points)\n\n")
    fix_lines = []
    for h in missing:
        fix_lines.append(f"- {HEADER_FIX_MAP.get(h, f'Add header: {h}')}")

    for p in open_ports:
        if p in DANGEROUS_PORTS:
            fix_lines.append(f"- {DANGEROUS_PORTS[p]}: restrict with firewall/VPN/allowlist; disable if not needed.")

    if nuclei_sum.get("count", 0) > 0 or zap_sum.get("count", 0) > 0:
        fix_lines.append("- Validate automated findings (false positives happen), fix confirmed issues, re-run scans.")

    if not fix_lines:
        fix_lines.append("- No specific remediations from this limited scan. Keep software patched and monitor.")

    for x in fix_lines[:14]:
        lines.append(x + "\n")

    lines.append("\n## Outputs\n\n")
    lines.append(f"- Combined JSON: `{combined.get('combined_json_path','')}`\n")
    lines.append(f"- Report: `{combined.get('report_path','')}`\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))

# =========================
# Main
# =========================
def main():
    ensure_dirs()

    if len(sys.argv) >= 2 and sys.argv[1].strip():
        target = sys.argv[1].strip()
        if not looks_like_url(target):
            print("Usage: python3 site_check.py https://example.com")
            print("[!] Or run without args for interactive mode.")
            sys.exit(2)
    else:
        target = prompt_target()

    u = urlparse(target)
    host = u.hostname or ""
    if not host:
        print("[!] Invalid URL/host.")
        sys.exit(2)

    ts = now_ts()
    safe = safe_name_from_host(host)

    write_status(ts, safe, 'start', {'target': target, 'host': host})

    scan_id = f"{safe}_{ts}"
    write_status(scan_id, "init", target=target, host=host)

    combined_json_path = os.path.join(OUTDIR, f"{safe}_{ts}_combined.json")
    report_path = os.path.join(REPORTDIR, f"{safe}_{ts}_site_check_report.md")

    write_status(scan_id, "dns_recon")
    a = dig_record(host, "A")
    aaaa = dig_record(host, "AAAA")
    cname = dig_record(host, "CNAME")
    ns = dig_record(host, "NS")
    mx = dig_record(host, "MX")
    txt = dig_record(host, "TXT")

    write_status(scan_id, "reachability_probe")
    probe = http_probe_sequence(target, host, a)
    final_url = probe.get("final_url") if probe.get("ok") else ""

    cdn_hint = detect_cdn(ns, probe.get("headers") or {})

    headers = probe.get("headers") or {}
    missing_headers = [h for h in IMPORTANT_HEADERS if h not in headers]
    present_headers = [h for h in IMPORTANT_HEADERS if h in headers]

    write_status(scan_id, "whois")
    whois_info = whois_lookup(host)

    combined = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "host": host,
        "final_url": final_url,
        "http_probe": probe,
        "cdn_hint": cdn_hint,
        "dns": {"A": a, "AAAA": aaaa, "CNAME": cname, "NS": ns, "MX": mx, "TXT": txt[:20]},
        "whois": whois_info,
        "missing_security_headers": missing_headers,
        "present_security_headers": present_headers,
        "combined_json_path": combined_json_path,
        "report_path": report_path,
        "scan_id": scan_id,
    }

    if not probe.get("ok"):
        combined["risk_level"] = "Informational"
        write_report(report_path, combined)
        with open(combined_json_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        write_status(scan_id, "done_unreachable", report=report_path, combined_json=combined_json_path)
        print("\n[!] Target appears DOWN / unreachable. Wrote report and stopped before scans.")
        print(f"[+] Combined JSON: {combined_json_path}")
        print(f"[+] Combined report: {report_path}")
        return

    write_status(scan_id, "nmap")
    nmap_mode_used, scan_target = choose_nmap_target(host, a, cdn_hint)
    nmap_prefix = os.path.join(OUTDIR, f"{safe}_{ts}_nmap_{nmap_mode_used}")
    nmap_res = nmap_scan(scan_target, nmap_prefix)
    open_ports = parse_nmap_open_ports(nmap_res.get("output_txt"))
    nmap_detail = parse_nmap_services(nmap_res.get("output_txt"))

    combined["nmap"] = nmap_res
    combined["nmap_summary"] = {
        "mode": nmap_mode_used,
        "scan_target": scan_target,
        "open_ports": open_ports,
        "services": (nmap_detail or {}).get("ports", []),
        "os_guess": (nmap_detail or {}).get("os_guess", ""),
        "service_info": (nmap_detail or {}).get("service_info", ""),
    }

    write_status(scan_id, "nuclei")
    nuclei_out = os.path.join(OUTDIR, f"{safe}_{ts}_nuclei.jsonl")
    nuclei_res = nuclei_scan(final_url or target, nuclei_out)
    nuclei_sum = parse_nuclei_jsonl(nuclei_out)

    combined["nuclei"] = nuclei_res
    combined["nuclei_summary"] = {
        "count": nuclei_sum["count"],
        "by_severity": nuclei_sum["by_severity"],
        "top": nuclei_sum["top"],
        "status": nuclei_res.get("status"),
    }

    write_status(scan_id, "zap")
    # Put ZAP outputs where they are guaranteed to be writable + visible
    # If /zap/wrk is not mounted, fall back to /runs/output
    zap_base_dir = ZAP_WRK if os.path.isdir(ZAP_WRK) else OUTDIR
    try:
        os.makedirs(os.path.join(zap_base_dir, "output"), exist_ok=True)
    except Exception:
        zap_base_dir = OUTDIR
        os.makedirs(os.path.join(zap_base_dir, "output"), exist_ok=True)

    zap_prefix = os.path.join(zap_base_dir, "output", f"{safe}_{ts}_zap")
    zap_res = zap_scan(final_url or target, zap_prefix)
    zap_sum = parse_zap_json(zap_res.get("output_json"))

    combined["zap"] = zap_res
    combined["zap_summary"] = {
        "count": zap_sum["count"],
        "by_risk": zap_sum["by_risk"],
        "top": zap_sum["top"],
        "status": zap_res.get("status"),
    }

    if SUBDOMAIN_ENUM:
        write_status(scan_id, "subdomains")
        combined["subdomains"] = subdomain_enum(host)
        combined["harvester"] = harvester_enum(host)

        try:
            merged = set(combined["subdomains"].get("subs", []) or [])
            for x in (combined.get("harvester", {}) or {}).get("items", []) or []:
                if isinstance(x, str) and x.endswith(host):
                    merged.add(x.strip())
            combined["subdomains"]["subs"] = sorted(merged)[:SUBDOMAIN_MAX]
            combined["subdomains"]["count"] = len(combined["subdomains"]["subs"])
        except Exception:
            pass

        if SUBDOMAIN_PROBE and combined["subdomains"].get("subs"):
            write_status(scan_id, "subdomain_probe")
            combined["subdomain_probe"] = probe_subdomains(combined["subdomains"]["subs"])

    write_status(scan_id, "deep_ports")
    ip_for_deep = ""
    try:
        scan_target = (combined.get("nmap_summary") or {}).get("scan_target", "")
        mode_used = (combined.get("nmap_summary") or {}).get("mode", "")
        if mode_used == "ip" and scan_target and scan_target.count(".") == 3:
            ip_for_deep = scan_target
        elif a:
            ip_for_deep = a[0]
    except Exception:
        ip_for_deep = a[0] if a else ""

    combined["port_deep_check"] = deep_check_ports(host, ip_for_deep, open_ports)

    write_status(scan_id, "risk")
    combined["risk_level"] = compute_risk(
        missing_headers,
        combined["nuclei_summary"].get("by_severity", {}),
        combined["zap_summary"].get("by_risk", {}),
        open_ports,
    )

    write_status(scan_id, "writing_outputs")
    write_report(report_path, combined)
    with open(combined_json_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    write_status(scan_id, "done", report=report_path, combined_json=combined_json_path)

    write_status(ts, safe, 'done', {'combined_json': combined_json_path, 'report': report_path})

    print("\n[+] Done.")
    print(f"[+] Combined JSON: {combined_json_path}")
    print(f"[+] Combined report: {report_path}")
    print("[i] Results are in ./runs/output and ./runs/reports")

if __name__ == "__main__":
    main()
