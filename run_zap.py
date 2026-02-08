#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

OUTDIR = os.path.join("output", "zap")
REPORTDIR = "reports"

# ---------------------------
# Plug your LLM call here
# ---------------------------
def llm_summarize(prompt: str) -> str:
    """
    Paste your existing LLM call here and return markdown text.
    Fallback summary returned if you haven't wired the LLM yet.
    """
    return (
        "## Executive Summary (AI)\n\n"
        "Summary:\n"
        "- Risk level: Informational\n"
        "- What I found:\n"
        "  - AI summarization not wired yet. Parsed ZAP findings are included below.\n"
        "- Why it matters:\n"
        "  - Review Medium issues first, then hardening headers/cookies.\n"
        "- How to fix:\n"
        "  - Wire llm_summarize() to your LLM function to generate a full summary.\n"
    )

# ---------------------------
# Helpers
# ---------------------------
def normalize_target(user_input: str) -> str:
    user_input = user_input.strip()
    if not user_input:
        raise ValueError("Empty target.")
    if not re.match(r"^https?://", user_input, re.I):
        user_input = "https://" + user_input
    parsed = urlparse(user_input)
    if not parsed.netloc:
        raise ValueError(f"Invalid target URL: {user_input}")
    return user_input

def safe_name_from_url(url: str) -> str:
    host = urlparse(url).netloc
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)

def run_cmd(cmd: list[str]) -> int:
    print("\n[*] Running command:\n  " + " ".join(cmd) + "\n")
    proc = subprocess.run(cmd, text=True)
    return proc.returncode

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)

def normalize_risk(r: str) -> str:
    r = (r or "").strip().lower()
    if r.startswith("high") or r == "3":
        return "High"
    if r.startswith("medium") or r == "2":
        return "Medium"
    if r.startswith("low") or r == "1":
        return "Low"
    return "Informational"

def risk_score(risk: str) -> int:
    return {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}.get(risk, 0)

def pick_first(d: dict, keys: list[str], default=""):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default

def extract_alerts(zap_json: dict) -> list[dict]:
    sites = zap_json.get("site") or zap_json.get("sites") or []
    out = []

    for site in sites:
        alerts = site.get("alerts") or []
        for a in alerts:
            name = pick_first(a, ["name", "alert", "alertName"], default="(no name)")
            risk = normalize_risk(pick_first(a, ["risk", "riskdesc", "riskDesc"], default="Informational"))
            confidence = pick_first(a, ["confidence", "confidencedesc", "confidenceDesc"], default="")
            desc = pick_first(a, ["desc", "description"], default="")
            solution = pick_first(a, ["solution"], default="")
            reference = pick_first(a, ["reference", "refs"], default="")
            cweid = str(pick_first(a, ["cweid", "cweId"], default="")).strip()
            wascid = str(pick_first(a, ["wascid", "wascId"], default="")).strip()

            instances = a.get("instances") or a.get("instance") or []
            sample_urls = []
            sample_evidence = []

            if isinstance(instances, list):
                for inst in instances[:10]:
                    if isinstance(inst, dict):
                        u = pick_first(inst, ["uri", "url"], default="")
                        ev = pick_first(inst, ["evidence"], default="")
                        if u:
                            sample_urls.append(u)
                        if ev:
                            sample_evidence.append(ev)

            sample_urls = list(dict.fromkeys(sample_urls))[:5]
            sample_evidence = sample_evidence[:3]

            out.append({
                "name": name,
                "risk": risk,
                "confidence": confidence,
                "cweid": cweid,
                "wascid": wascid,
                "instance_count": len(instances) if isinstance(instances, list) else 0,
                "desc": desc,
                "solution": solution,
                "reference": reference,
                "sample_urls": sample_urls,
                "sample_evidence": sample_evidence,
            })

    return out

def build_payload(alerts: list[dict]) -> dict:
    counts = Counter(a["risk"] for a in alerts)
    overall = "Informational"
    if alerts:
        overall = max((a["risk"] for a in alerts), key=risk_score)

    top = sorted(alerts, key=lambda x: (risk_score(x["risk"]), x["instance_count"]), reverse=True)[:10]

    return {
        "overall_risk": overall,
        "counts_by_risk": dict(counts),
        "total_unique_alerts": len(alerts),
        "top_alerts": top,
    }

def build_llm_prompt(target: str, payload: dict) -> str:
    return f"""
You are a cybersecurity assistant. Summarize a ZAP Baseline (passive) scan for a website.

Target: {target}

Data (JSON):
{json.dumps(payload, indent=2)}

Write the summary in Markdown with EXACTLY this structure:

## Executive Summary (AI)

Summary:
- Risk level: <High/Medium/Low/Informational> (use overall_risk)
- What I found:
  - 4-8 bullets describing the most important alerts (include counts, be specific).
- Why it matters:
  - 2-5 bullets about business/security impact in plain language.
- How to fix:
  - 6-12 bullets, prioritized from highest risk to lowest.
  - Avoid repetition by grouping related header/cookie issues.
""".strip()

def write_report(report_path: str, target: str, payload: dict, llm_summary_md: str):
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    counts = payload.get("counts_by_risk", {})
    total = payload.get("total_unique_alerts", 0)
    top_alerts = payload.get("top_alerts", [])

    lines = []
    lines.append("# Website Security Health Check Report (ZAP)\n")
    lines.append(f"- Date: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Target: {target}\n")

    lines.append(llm_summary_md.strip() + "\n")

    lines.append("## Technical Findings (raw)\n")
    lines.append("```")
    lines.append(f"Target: {target}")
    lines.append(f"ZAP unique alerts: {total}")
    lines.append(f"Counts by risk: {counts}")
    lines.append("Top alerts:")
    for a in top_alerts:
        ex_url = a["sample_urls"][0] if a.get("sample_urls") else ""
        lines.append(f"- {a['risk']}: {a['name']} (instances: {a['instance_count']}) {('- ' + ex_url) if ex_url else ''}")
    lines.append("```")
    lines.append("")

    lines.append("## Notes / Scope\n")
    lines.append("- This is a ZAP Baseline scan (primarily passive checks and light crawling).")
    lines.append("- No credentialed testing, no brute forcing, no exploitation steps.")
    lines.append("- Findings should be validated before production changes.\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def get_target_from_args_or_prompt() -> str:
    # Support:
    #   python3 run_zap.py https://example.com
    #   python3 run_zap.py example.com
    if len(sys.argv) >= 2:
        return sys.argv[1]
    return input("Enter target domain or URL (e.g., example.com or https://example.com): ")

def main():
    if shutil.which("docker") is None:
        print("[!] Docker not found. Install Docker first.")
        raise SystemExit(1)

    target_in = get_target_from_args_or_prompt()
    try:
        target = normalize_target(target_in)
    except ValueError as e:
        print(f"[!] {e}")
        raise SystemExit(1)

    os.makedirs(OUTDIR, exist_ok=True)
    os.makedirs(REPORTDIR, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = safe_name_from_url(target)

    json_name = f"{safe}_{ts}_zap.json"
    html_name = f"{safe}_{ts}_zap.html"
    md_name   = f"{safe}_{ts}_zap.md"

    json_path = os.path.join(OUTDIR, json_name)
    report_path = os.path.join(REPORTDIR, f"{safe}_{ts}_zap_report.md")

    mount = os.path.abspath(OUTDIR)

    print("\n[*] Target:", target)
    print("[*] Output:")
    print("   -", os.path.join(OUTDIR, json_name))
    print("   -", os.path.join(OUTDIR, html_name))
    print("   -", os.path.join(OUTDIR, md_name))
    print("[*] Report:")
    print("   -", report_path)

    cmd = [
        "docker", "run", "--rm", "-t",
        "--pull", "always",
        "-v", f"{mount}:/zap/wrk",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t", target,
        "-J", json_name,
        "-r", html_name,
        "-w", md_name,
        "-I"
    ]

    rc = run_cmd(cmd)

    if not os.path.exists(json_path):
        print("\n[!] ZAP did not produce JSON output.")
        print("[!] Check Docker volume mount path and permissions.")
        print(f"[*] Expected JSON path: {json_path}")
        print(f"[*] Exit code: {rc}")
        raise SystemExit(2)

    if os.path.getsize(json_path) == 0:
        print("\n[!] ZAP JSON file exists but is EMPTY.")
        print("[!] Likely write issue or baseline terminated early.")
        print(f"[*] JSON path: {json_path}")
        print(f"[*] Exit code: {rc}")
        raise SystemExit(3)

    zap_json = load_json(json_path)
    alerts = extract_alerts(zap_json)
    payload = build_payload(alerts)

    prompt = build_llm_prompt(target, payload)
    llm_md = llm_summarize(prompt)

    write_report(report_path, target, payload, llm_md)

    print("\n[+] Done.")
    print(f"[+] Exit code: {rc}")
    print(f"[+] ZAP report: {report_path}")

if __name__ == "__main__":
    main()
