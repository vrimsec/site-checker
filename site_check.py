#!/usr/bin/env python3
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

# =========================
# Paths (host-mounted)
# =========================
RUNS_DIR = os.environ.get("RUNS_DIR", "/runs")
OUTDIR = os.path.join(RUNS_DIR, "output")
REPORTDIR = os.path.join(RUNS_DIR, "reports")

# =========================
# Tunables
# =========================
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "12"))
WHOIS_TIMEOUT = int(os.environ.get("WHOIS_TIMEOUT", "25"))
DIG_TIMEOUT = int(os.environ.get("DIG_TIMEOUT", "20"))

# Scanners
NMAP_TOP_PORTS = int(os.environ.get("NMAP_TOP_PORTS", "1000"))
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "480"))  # seconds
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "600"))  # seconds
ZAP_TIMEOUT = int(os.environ.get("ZAP_TIMEOUT", "900"))  # seconds

# Nmap target selection:
# - auto: if CDN hint and has A record => scan IP else hostname
# - ip: always scan first A record (if present)
# - host: always scan hostname
NMAP_MODE = os.environ.get("NMAP_MODE", "auto").lower().strip()

IMPORTANT_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HEADER_FIX_MAP = {
    "content-security-policy": "Add a Content-Security-Policy (start with Report-Only, tune, then enforce).",
    "strict-transport-security": "Enable HSTS (Strict-Transport-Security) with a safe max-age; add includeSubDomains only if appropriate.",
    "x-frame-options": "Add X-Frame-Options (or use CSP frame-ancestors) to reduce clickjacking risk.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff to reduce MIME sniffing issues.",
    "referrer-policy": "Set Referrer-Policy to limit referrer leakage (e.g., strict-origin-when-cross-origin).",
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
    8080: "Alt HTTP exposed (verify admin panels)",
    8443: "Alt HTTPS exposed (verify admin panels)",
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

def run_cmd(cmd: list[str], timeout: int) -> tuple[int, str, str, str]:
    """
    Returns: (rc, stdout, stderr, status)
      status: "ok" | "timeout" | "error"
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

def ensure_dirs():
    os.makedirs(OUTDIR, exist_ok=True)
    os.makedirs(REPORTDIR, exist_ok=True)

def looks_like_url(s: str) -> bool:
    try:
        u = urlparse(s)
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False

def normalize_input_url(s: str) -> str:
    s = (s or "").strip()
    return s

def prompt_target() -> str:
    while True:
        s = input("Enter target URL (format: https://example.com OR http://example.com): ").strip()
        s = normalize_input_url(s)

        # Common user mistake: "www.domain.com" or "domain.com" without scheme
        if not s.startswith(("http://", "https://")):
            print("[!] Please include scheme. Example: https://example.com")
            continue

        if not looks_like_url(s):
            print("[!] Invalid URL. Expected: https://example.com or http://example.com")
            continue

        return s

def safe_name_from_host(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", host)

def dig_record(name: str, record: str) -> list[str]:
    rc, out, err, status = run_cmd(["dig", "+short", name, record], timeout=DIG_TIMEOUT)
    if status != "ok" or rc != 0 or not out.strip():
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]

def whois_lookup(domain: str) -> dict:
    """
    Never crash the pipeline on WHOIS issues.
    """
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
    if "edgekey" in ns_join or "edgesuite" in ns_join:
        return "Akamai"
    if "cdn77" in ns_join:
        return "CDN77"

    # Header hints (best-effort)
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    if "cf-ray" in h or "cloudflare" in h.get("server", ""):
        return "Cloudflare"
    if "akamai" in h.get("server", "") or "akamai" in h.get("x-akamai-transformed", ""):
        return "Akamai"
    return ""

def http_probe(url: str) -> dict:
    """
    Probe reachability + get final URL + headers.
    If unreachable, we still write report and stop scans.
    """
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, headers={"User-Agent": "site-checker/1.0"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {
            "ok": True,
            "status_code": r.status_code,
            "final_url": r.url,
            "headers": headers,
            "error": "",
        }
    except requests.RequestException as e:
        return {
            "ok": False,
            "status_code": 0,
            "final_url": "",
            "headers": {},
            "error": str(e),
        }

def choose_nmap_target(host: str, a_records: list[str], cdn_hint: str) -> tuple[str, str]:
    """
    Returns: (mode_used, target)
      mode_used: "host" or "ip"
    """
    if NMAP_MODE == "host":
        return "host", host
    if NMAP_MODE == "ip":
        return ("ip", a_records[0]) if a_records else ("host", host)

    # auto
    if cdn_hint and a_records:
        return "ip", a_records[0]
    return "host", host

def nmap_scan(scan_target: str, out_prefix: str) -> dict:
    out_xml = f"{out_prefix}.xml"
    out_txt = f"{out_prefix}.txt"

    cmd = [
        "nmap",
        "-sT",
        "-Pn",
        "-T3",
        "--top-ports", str(NMAP_TOP_PORTS),
        "-sV",
        "--version-light",
        "--open",
        "--max-retries", "2",
        "--host-timeout", "5m",
        "-oX", out_xml,
        "-oN", out_txt,
        scan_target,
    ]
    rc, out, err, status = run_cmd(cmd, timeout=NMAP_TIMEOUT)

    return {
        "scan_target": scan_target,
        "command": " ".join(cmd),
        "status": status,
        "return_code": rc,
        "stdout_tail": (out or "")[-1200:],
        "stderr_tail": (err or "")[-800:],
        "output_xml": out_xml,
        "output_txt": out_txt,
    }

def parse_nmap_open_ports(nmap_txt_path: str) -> list[int]:
    ports = []
    if not nmap_txt_path or not os.path.exists(nmap_txt_path):
        return ports
    try:
        with open(nmap_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # Example: 80/tcp open  http
                m = re.match(r"^(\d+)/tcp\s+open\b", line)
                if m:
                    ports.append(int(m.group(1)))
    except Exception:
        return ports
    return sorted(set(ports))

def nuclei_scan(url: str, out_jsonl: str) -> dict:
    cmd = [
        "nuclei",
        "-u", url,
        "-jsonl",
        "-follow-redirects",
        "-severity", "low,medium,high,critical",
        "-o", out_jsonl,
        "-no-color",
    ]
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

    # Collect up to 8 unique template ids for reporting
    for item in findings:
        sev = (item.get("info", {}) or {}).get("severity") or item.get("severity") or "info"
        sev = str(sev).lower().strip()
        by_sev[sev] = by_sev.get(sev, 0) + 1

        tid = item.get("template-id") or item.get("template") or ""
        matched = item.get("matched-at") or item.get("host") or item.get("url") or ""
        key = (tid, matched, sev)
        if tid and key not in seen:
            seen.add(key)
            top_items.append({"severity": sev, "template_id": tid, "matched": matched})
        if len(top_items) >= 8:
            break

    return {
        "count": len(findings),
        "by_severity": by_sev,
        "top": top_items,
        "raw": findings[:200],  # cap for combined json size
    }

def zap_baseline_scan(url: str, out_prefix: str) -> dict:
    """
    Runs ZAP baseline script.
    We keep it "safe": passive scan + light spider.
    """
    out_json = f"{out_prefix}.json"
    out_html = f"{out_prefix}.html"
    out_md = f"{out_prefix}.md"

    cmd = [
        "zap-baseline.py",
        "-t", url,
        "-J", out_json,
        "-r", out_html,
        "-w", out_md,
        "-I",
    ]
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
    """
    ZAP baseline json formats can vary slightly between versions.
    We'll try to extract:
      - total alerts count
      - counts by risk
      - top alerts names
    """
    if not zap_json_path or not os.path.exists(zap_json_path):
        return {"count": 0, "by_risk": {}, "top": [], "raw": {}}

    try:
        with open(zap_json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return {"count": 0, "by_risk": {}, "top": [], "raw": {}}

    alerts = []
    # Common location:
    # data["site"][0]["alerts"]
    try:
        if isinstance(data, dict) and "site" in data and data["site"]:
            site0 = data["site"][0]
            alerts = site0.get("alerts", []) or []
    except Exception:
        alerts = []

    by_risk = {}
    top = []
    seen = set()

    for a in alerts:
        risk = (a.get("risk") or a.get("riskdesc") or "Informational").strip()
        # Normalize: "Low", "Medium", "High", "Informational"
        risk_norm = risk.split(" ")[0].capitalize()
        by_risk[risk_norm] = by_risk.get(risk_norm, 0) + 1

        name = (a.get("name") or "").strip()
        if name and name not in seen:
            seen.add(name)
            top.append({"risk": risk_norm, "name": name})
        if len(top) >= 8:
            break

    return {
        "count": len(alerts),
        "by_risk": by_risk,
        "top": top,
        "raw": data,
    }

def compute_risk(missing_headers: list[str], nuclei_by_sev: dict, zap_by_risk: dict, open_ports: list[int]) -> str:
    # High if any high/critical from nuclei, or ZAP High
    if nuclei_by_sev.get("critical", 0) > 0 or nuclei_by_sev.get("high", 0) > 0:
        return "High"
    if zap_by_risk.get("High", 0) > 0:
        return "High"

    # Medium if any medium, or SSH/DB exposed, or many headers missing
    if nuclei_by_sev.get("medium", 0) > 0:
        return "Medium"
    if zap_by_risk.get("Medium", 0) > 0:
        return "Medium"

    for p in open_ports:
        if p in (22, 3389, 2375, 3306, 5432, 6379, 9200, 27017):
            return "Medium"

    if len(missing_headers) >= 4:
        return "Medium"

    return "Low"

def render_ports(open_ports: list[int]) -> str:
    if not open_ports:
        return "(none detected)"
    parts = []
    for p in open_ports:
        label = DANGEROUS_PORTS.get(p)
        if label:
            parts.append(f"{p}/tcp(!)")
        else:
            parts.append(f"{p}/tcp")
    return ", ".join(parts)

def render_notables(open_ports: list[int]) -> list[str]:
    notes = []
    for p in open_ports:
        if p in DANGEROUS_PORTS:
            notes.append(f"{DANGEROUS_PORTS[p]} — restrict/allowlist if not required.")
    return notes[:8]

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

    # Reachability
    if not combined.get("http_probe", {}).get("ok", False):
        lines.append(f"- Reachability: **DOWN / unreachable** ({combined.get('http_probe', {}).get('error','')})\n")
        lines.append("\n## Outputs\n\n")
        lines.append(f"- Combined JSON: `{combined.get('combined_json_path','')}`\n")
        lines.append(f"- Report: `{combined.get('report_path','')}`\n")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("".join(lines))
        return

    # Headers
    missing = combined.get("missing_security_headers") or []
    present = combined.get("present_security_headers") or []
    if missing:
        lines.append(f"- Missing security headers: {', '.join(missing)}\n")
    else:
        lines.append("- Missing security headers: (none from checked list)\n")
    if present:
        lines.append(f"- Present security headers: {', '.join(present)}\n")

    # Scanner summaries
    nuclei_sum = combined.get("nuclei_summary", {}) or {}
    zap_sum = combined.get("zap_summary", {}) or {}
    nmap_sum = combined.get("nmap_summary", {}) or {}

    lines.append(f"- Nuclei findings (count): {nuclei_sum.get('count', 0)}\n")
    if nuclei_sum.get("by_severity"):
        lines.append(f"  - By severity: {nuclei_sum.get('by_severity')}\n")

    lines.append(f"- ZAP alerts (count): {zap_sum.get('count', 0)}\n")
    if zap_sum.get("by_risk"):
        lines.append(f"  - By risk: {zap_sum.get('by_risk')}\n")

    open_ports = nmap_sum.get("open_ports", []) or []
    lines.append(f"- Nmap open ports: {render_ports(open_ports)}\n")

    # Notable items
    lines.append("\n## Notable Observations\n\n")
    if combined.get("cdn_hint"):
        lines.append("- CDN note: CDNs/WAFs may add/remove headers; validate at origin if you control it.\n")
        lines.append("- Nmap note: If the site is behind a CDN proxy, Nmap results may reflect edge infrastructure, not origin.\n")

    notables = []
    notables += render_notables(open_ports)

    if missing:
        notables.append("Missing browser security headers reduces defense-in-depth (especially CSP/HSTS/XFO/nosniff).")

    if not notables:
        notables.append("No major red flags from this limited automated scan. Validate results before changes.")

    for n in notables[:10]:
        lines.append(f"- {n}\n")

    # Top findings (actionable)
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

    # Fixes
    lines.append("\n## Suggested Fixes (starting points)\n\n")

    fix_lines = []
    for h in missing:
        fix_lines.append(f"- {HEADER_FIX_MAP.get(h, f'Add header: {h}')}")

    # Port fixes
    for p in open_ports:
        if p in DANGEROUS_PORTS:
            fix_lines.append(f"- {DANGEROUS_PORTS[p]}: restrict with firewall/VPN/allowlist; disable if not needed.")

    if nuclei_sum.get("count", 0) > 0 or zap_sum.get("count", 0) > 0:
        fix_lines.append("- Validate the automated findings (false positives happen), fix confirmed issues, then re-run scans.")

    if not fix_lines:
        fix_lines.append("- No specific remediations from this limited scan. Keep software patched and add monitoring.")

    for x in fix_lines[:14]:
        lines.append(x + "\n")

    lines.append("\n## Outputs\n\n")
    lines.append(f"- Combined JSON: `{combined.get('combined_json_path','')}`\n")
    lines.append(f"- Report: `{combined.get('report_path','')}`\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))

def main():
    ensure_dirs()

    # If arg given, use it; else prompt
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        target = normalize_input_url(sys.argv[1].strip())
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

    combined_json_path = os.path.join(OUTDIR, f"{safe}_{ts}_combined.json")
    report_path = os.path.join(REPORTDIR, f"{safe}_{ts}_site_check_report.md")

    # Basic dependencies check (non-fatal where possible)
    for t in ("dig", "nmap", "nuclei", "zap-baseline.py", "whois"):
        if not tool_exists(t) and t != "whois":
            print(f"[!] Missing tool: {t}")
    # Whois may not work on all TLDs; we handle timeouts.

    # DNS recon (best-effort)
    a = dig_record(host, "A")
    aaaa = dig_record(host, "AAAA")
    cname = dig_record(host, "CNAME")
    ns = dig_record(host, "NS")
    mx = dig_record(host, "MX")
    txt = dig_record(host, "TXT")

    # HTTP probe
    probe = http_probe(target)
    final_url = probe.get("final_url") if probe.get("ok") else ""

    cdn_hint = detect_cdn(ns, probe.get("headers") or {})

    # Security headers (from final response)
    headers = probe.get("headers") or {}
    missing_headers = [h for h in IMPORTANT_HEADERS if h not in headers]
    present_headers = [h for h in IMPORTANT_HEADERS if h in headers]

    # WHOIS (best-effort, never crash)
    whois_info = whois_lookup(host)

    combined = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "host": host,
        "final_url": final_url,
        "http_probe": probe,
        "cdn_hint": cdn_hint,
        "dns": {
            "A": a,
            "AAAA": aaaa,
            "CNAME": cname,
            "NS": ns,
            "MX": mx,
            "TXT": txt[:20],
        },
        "whois": whois_info,
        "missing_security_headers": missing_headers,
        "present_security_headers": present_headers,
        "combined_json_path": combined_json_path,
        "report_path": report_path,
        "notes": [
            "This is an automated health check (light scan).",
            "No credentialed testing, no brute forcing, no exploitation steps.",
            "Only scan targets you own or have explicit permission to test.",
        ],
    }

    # If DOWN, write report and stop
    if not probe.get("ok"):
        combined["risk_level"] = "Informational"
        # minimal outputs
        write_report(report_path, combined)
        with open(combined_json_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        print("\n[!] Target appears DOWN / unreachable. Wrote report and stopped before scans.")
        print(f"[+] Combined JSON: {combined_json_path}")
        print(f"[+] Combined report: {report_path}")
        print("[i] On the host, look in: ~/site-checker-runs/output and ~/site-checker-runs/reports")
        return

    # --- Nmap ---
    nmap_mode_used, scan_target = choose_nmap_target(host, a, cdn_hint)
    nmap_prefix = os.path.join(OUTDIR, f"{safe}_{ts}_nmap_{nmap_mode_used}")
    nmap_res = nmap_scan(scan_target, nmap_prefix)
    open_ports = parse_nmap_open_ports(nmap_res.get("output_txt"))

    combined["nmap"] = nmap_res
    combined["nmap_summary"] = {
        "mode": nmap_mode_used,
        "scan_target": scan_target,
        "open_ports": open_ports,
    }

    # --- Nuclei ---
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

    # --- ZAP baseline ---
    zap_prefix = os.path.join(OUTDIR, f"{safe}_{ts}_zap")
    zap_res = zap_baseline_scan(final_url or target, zap_prefix)
    zap_sum = parse_zap_json(zap_res.get("output_json"))

    combined["zap"] = zap_res
    combined["zap_summary"] = {
        "count": zap_sum["count"],
        "by_risk": zap_sum["by_risk"],
        "top": zap_sum["top"],
        "status": zap_res.get("status"),
    }

    # Risk
    combined["risk_level"] = compute_risk(
        missing_headers,
        combined["nuclei_summary"].get("by_severity", {}),
        combined["zap_summary"].get("by_risk", {}),
        open_ports,
    )

    # Write outputs
    write_report(report_path, combined)
    with open(combined_json_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print("\n[+] Done.")
    print(f"[+] Combined JSON: {combined_json_path}")
    print(f"[+] Combined report: {report_path}")
    print("[i] On the host, look in: ~/site-checker-runs/output and ~/site-checker-runs/reports")

if __name__ == "__main__":
    main()
