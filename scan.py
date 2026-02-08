import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
# Qwen is better for structured summaries than tinyllama (still works on Pi, just slower).
OLLAMA_MODEL = "qwen2.5-coder:3b"
# OLLAMA_MODEL = "tinyllama:latest"

IMPORTANT_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HEADER_FIX_MAP = {
    "content-security-policy": "Add a Content-Security-Policy (CSP). Start in report-only mode, tune it, then enforce.",
    "strict-transport-security": "Enable HSTS (Strict-Transport-Security) with a safe max-age; add includeSubDomains only if appropriate.",
    "x-frame-options": "Add X-Frame-Options (or use CSP frame-ancestors) to reduce clickjacking risk.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff to reduce MIME sniffing issues.",
    "referrer-policy": "Set Referrer-Policy to limit referrer leakage (e.g., strict-origin-when-cross-origin).",
    "permissions-policy": "Set Permissions-Policy to restrict browser features you don't need.",
}

def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target

def get_tls_expiry(host: str, port: int = 443, timeout: int = 10):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (dt - datetime.now(timezone.utc)).days
    return dt.isoformat(), days_left

def fetch_headers(url: str, timeout: int = 15):
    r = requests.get(url, timeout=timeout, allow_redirects=True)
    headers = {k.lower(): v for k, v in r.headers.items()}
    return {
        "final_url": r.url,
        "status_code": r.status_code,
        "server": headers.get("server", ""),
        "headers": headers,
    }

def run_nuclei(url: str, out_jsonl_path: str):
    os.makedirs(os.path.dirname(out_jsonl_path), exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.path.abspath(os.path.dirname(out_jsonl_path))}:/output",
        "projectdiscovery/nuclei:latest",
        "-u", url,
        "-jsonl",
        "-o", f"/output/{os.path.basename(out_jsonl_path)}",
        "-severity", "low,medium,high,critical",
        "--no-color",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

# Grok-style, calibrated risk logic
def compute_risk(missing_headers: list[str], vuln_count: int, tls_days_left: int | None) -> str:
    if vuln_count >= 3:
        return "High"

    # Any findings -> Medium
    if vuln_count >= 1:
        return "Medium"

    # TLS expiring soon -> Medium
    if tls_days_left is not None and tls_days_left <= 14:
        return "Medium"

    missing_count = len(missing_headers)

    # Many missing headers -> Medium
    if missing_count >= 4:
        return "Medium"

    # 0-2 missing headers or only CSP missing -> Low
    return "Low"

def build_fallback_summary(
    host: str,
    missing_headers: list[str],
    present_headers: list[str],
    tls_days_left: int | None,
    vuln_count: int,
    server_header: str,
    status_code: int
) -> str:
    lvl = compute_risk(missing_headers, vuln_count, tls_days_left)

    what = []
    what.append(f"Website responded with HTTP {status_code}.")

    if server_header:
        what.append(f"Server header observed: {server_header}.")

    if vuln_count == 0:
        what.append("No vulnerabilities detected in this automated scan.")
    else:
        what.append(f"{vuln_count} potential issue(s) detected by automated checks (needs validation).")

    if tls_days_left is not None:
        what.append(f"TLS certificate expires in {tls_days_left} day(s).")

    if missing_headers:
        what.append(f"Missing security headers: {', '.join(missing_headers)}.")
    else:
        what.append("All checked security headers appear present.")

    why = []
    # Nuanced wording (defense-in-depth)
    if "content-security-policy" in missing_headers:
        why.append("Missing CSP reduces defense-in-depth against XSS if an injection bug exists elsewhere.")
    if len(missing_headers) >= 3:
        why.append("Multiple missing browser security headers weaken protection against several common web attacks.")
    if tls_days_left is not None and tls_days_left <= 45:
        why.append(f"TLS expiry in {tls_days_left} days can cause outages or browser warnings if renewal is missed.")
    if not why:
        why.append("Overall posture looks reasonable based on this limited automated check.")

    fixes = []
    for h in missing_headers:
        if h in HEADER_FIX_MAP:
            fixes.append(HEADER_FIX_MAP[h])

    if tls_days_left is not None and tls_days_left <= 45:
        fixes.append("Enable auto-renewal and set an alert for TLS certificate expiry (e.g., notify at 30/14 days).")

    if vuln_count >= 1:
        fixes.append("Validate the automated findings, fix confirmed issues, then re-run the scan.")

    def bullets(items, max_n):
        if not items:
            return "  - Not enough information in this scan."
        return "\n".join([f"  - {x}" for x in items[:max_n]])

    return (
        "Summary:\n"
        f"- Risk level: {lvl}\n"
        "- What I found:\n"
        f"{bullets(what, 4)}\n"
        "- Why it matters:\n"
        f"{bullets(why, 3)}\n"
        "- How to fix:\n"
        f"{bullets(fixes, 6)}\n"
    )

def summarize_with_ollama(raw_findings: str) -> str:
    prompt = f"""You are a balanced, evidence-based cybersecurity analyst.

Rules you MUST follow strictly:
- Base EVERY statement ONLY on facts in RAW FINDINGS. Never assume or invent vulnerabilities, CVEs, or exploits.
- If "Vulnerability findings count: 0", you MUST state: "No vulnerabilities detected in this automated scan."
- Assess risk conservatively but accurately: consider compensating controls (e.g., if most headers are present, missing one is less severe).
- Risk level guidance:
  - Low: No vulns; 0-2 missing headers (or only CSP missing); TLS >30 days.
  - Medium: No vulns but 3+ missing headers, OR TLS ≤30 days, OR other moderate gaps.
  - High: Multiple confirmed findings (or critical/high findings).
- Be concise, factual, reassuring when appropriate.
- Output ONLY the filled TEMPLATE. No extra text, no RAW FINDINGS echo.

TEMPLATE:
Summary:
- Risk level: Low / Medium / High
- What I found:
  - ...
  - ...
- Why it matters:
  - ...
  - ...
- How to fix:
  - ...
  - ...

RAW FINDINGS:
{raw_findings}
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 260,
            "temperature": 0.05
        }
    }
    r = requests.post(OLLAMA_URL, json=payload, timeout=600)
    r.raise_for_status()
    return (r.json().get("response", "") or "").strip()

def looks_like_hallucination(ai_text: str, vuln_count: int) -> bool:
    t = ai_text.lower()
    bad_markers = ["cve-", "sql injection", "sqli", "xss", "session hijack", "rce", "remote code"]
    # If scan says 0 findings but AI claims classic vulns/CVEs, reject it.
    if vuln_count == 0 and any(m in t for m in bad_markers):
        return True
    # If it echoes prompt sections, reject.
    if "raw findings" in t:
        return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scan.py <domain-or-url>")
        sys.exit(1)

    target = normalize_url(sys.argv[1])
    u = urlparse(target)
    host = u.hostname
    if not host:
        print("Invalid target.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", host)
    nuclei_out = f"output/{safe_name}_{ts}_nuclei.jsonl"
    report_path = f"reports/{safe_name}_{ts}_report.md"

    http_info = fetch_headers(target)

    tls_info = None
    tls_days_left = None
    tls_note = ""
    if u.scheme == "https":
        try:
            tls_info = get_tls_expiry(host)
            if tls_info:
                _iso, tls_days_left = tls_info
        except Exception as e:
            tls_note = f"TLS check error: {e}"

    headers = http_info["headers"]
    missing = [h for h in IMPORTANT_HEADERS if h not in headers]
    present = [h for h in IMPORTANT_HEADERS if h in headers]

    rc, _out, _err = run_nuclei(http_info["final_url"], nuclei_out)

    nuclei_findings = []
    if os.path.exists(nuclei_out):
        with open(nuclei_out, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    nuclei_findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    vuln_count = len(nuclei_findings)

    # RAW findings: keep short, factual
    raw = []
    raw.append(f"Target: {target}")
    raw.append(f"Final URL: {http_info['final_url']}")
    raw.append(f"HTTP status: {http_info['status_code']}")
    if http_info["server"]:
        raw.append(f"Server header: {http_info['server']}")

    if tls_info:
        iso, days_left = tls_info
        raw.append(f"TLS certificate expires: {iso} ({days_left} days left)")
    if tls_note:
        raw.append(tls_note)

    if missing:
        raw.append(f"Missing security headers: {', '.join(missing)}")
    else:
        raw.append("Missing security headers: none from the checked list")

    if present:
        raw.append(f"Present security headers: {', '.join(present)}")

    raw.append("Vulnerability scan: completed" if rc == 0 else f"Vulnerability scan: completed with exit code {rc}")

    if vuln_count:
        raw.append(f"Vulnerability findings count: {vuln_count}")
        seen = set()
        count = 0
        for fnd in nuclei_findings:
            tid = fnd.get("template-id", "")
            sev = fnd.get("info", {}).get("severity", fnd.get("severity", ""))
            matched = fnd.get("matched-at", "")
            key = (tid, matched, sev)
            if key in seen:
                continue
            seen.add(key)
            raw.append(f"- [{sev}] {tid} :: {matched}")
            count += 1
            if count >= 8:
                break
    else:
        raw.append("Vulnerability findings count: 0")

    raw_text = "\n".join(raw)

    # AI summary with sanity guard + deterministic fallback
    ai_summary = ""
    try:
        ai_summary = summarize_with_ollama(raw_text)
    except Exception:
        ai_summary = ""

    if (not ai_summary.strip()) or looks_like_hallucination(ai_summary, vuln_count):
        ai_summary = build_fallback_summary(
            host=host,
            missing_headers=missing,
            present_headers=present,
            tls_days_left=tls_days_left,
            vuln_count=vuln_count,
            server_header=http_info.get("server", ""),
            status_code=http_info.get("status_code", 0),
        )

    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Website Security Health Check Report\n\n")
        f.write(f"- Date: {datetime.now().isoformat()}\n")
        f.write(f"- Target: {target}\n")
        f.write(f"- Final URL: {http_info['final_url']}\n\n")

        f.write("## Executive Summary (AI)\n\n")
        f.write(ai_summary + "\n\n")

        f.write("## Technical Findings (raw)\n\n")
        f.write("```\n" + raw_text + "\n```\n\n")

        f.write("## Notes / Scope\n\n")
        f.write("- This is an automated health check (light scan).\n")
        f.write("- No credentialed testing, no brute forcing, no exploitation steps.\n")
        f.write("- Findings should be validated before production changes.\n")

    print(f"[+] Report saved: {report_path}")
    print(f"[+] Nuclei output: {nuclei_out}")

if __name__ == "__main__":
    main()
