#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlparse

# -----------------------
# Helpers
# -----------------------
def normalize_target(t: str) -> str:
    t = t.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t

def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def dig_record(name: str, record: str) -> list[str]:
    rc, out, _ = run_cmd(["dig", "+short", name, record], timeout=20)
    if rc != 0 or not out:
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]

def whois_lookup(domain: str) -> str:
    rc, out, err = run_cmd(["whois", domain], timeout=25)
    text = out if out else err
    return "\n".join(text.splitlines()[:120])

def likely_cdn(ns_records: list[str]) -> str:
    s = " ".join(ns_records).lower()
    if "akam.net" in s:
        return "Akamai"
    if "cloudflare" in s:
        return "Cloudflare"
    if "fastly" in s:
        return "Fastly"
    if "edgesuite" in s or "edgekey" in s:
        return "Akamai"
    return ""

def parse_nmap_summary(nmap_out: str) -> dict:
    """
    Pull a small human-friendly summary from Nmap stdout.
    """
    open_ports = []
    filtered_line = ""
    for line in (nmap_out or "").splitlines():
        line = line.strip()
        if line.startswith("Not shown:"):
            filtered_line = line
        m = re.match(r"^(\d+/\w+)\s+open\s+(\S+)", line)
        if m:
            open_ports.append({"port": m.group(1), "service": m.group(2)})
    return {"open_ports": open_ports, "not_shown": filtered_line}

# -----------------------
# Arg parsing
# -----------------------
def parse_args(argv: list[str]) -> dict:
    """
    Usage:
      python3 recon_nmap.py <domain-or-url> [--nmap] [--ports N] [--timeout 5m] [--host] [--ip] [--both]

    --nmap           run nmap after DNS/WHOIS
    --ports N        scan top N ports (default 1000)
    --timeout 5m     nmap host-timeout (default 5m)
    --ip             scan first A record IP (default behavior when --nmap is used)
    --host           scan hostname (SNI/virtualhost-friendly; can vary on CDN edges)
    --both           scan BOTH hostname and first A record IP (best for CDN comparison)
    """
    if len(argv) < 2:
        raise SystemExit(
            "Usage: python3 recon_nmap.py <domain-or-url> [--nmap] [--ports N] [--timeout 5m] [--host|--ip|--both]"
        )

    target = argv[1]
    do_nmap = "--nmap" in argv

    ports = 1000
    if "--ports" in argv:
        i = argv.index("--ports")
        if i + 1 >= len(argv):
            raise SystemExit("[!] --ports requires a value, e.g. --ports 1000")
        try:
            ports = int(argv[i + 1])
        except ValueError:
            raise SystemExit("[!] --ports must be an integer, e.g. --ports 1000")

    host_timeout = "5m"
    if "--timeout" in argv:
        i = argv.index("--timeout")
        if i + 1 >= len(argv):
            raise SystemExit("[!] --timeout requires a value, e.g. --timeout 5m")
        host_timeout = argv[i + 1].strip()

    mode = "ip"  # NEW DEFAULT: IP scan is more consistent for CDN-backed sites
    if "--both" in argv:
        mode = "both"
    elif "--host" in argv:
        mode = "host"
    elif "--ip" in argv:
        mode = "ip"

    return {"target": target, "do_nmap": do_nmap, "ports": ports, "host_timeout": host_timeout, "mode": mode}

def build_nmap_cmd(scan_target: str, ports: int, host_timeout: str, out_xml: str, out_txt: str) -> list[str]:
    return [
        "nmap",
        "-sT",
        "-Pn",
        "-T3",
        "--top-ports", str(ports),
        "-sV",
        "--version-light",
        "--open",
        "--max-retries", "2",
        "--host-timeout", host_timeout,
        "-oX", out_xml,
        "-oN", out_txt,
        scan_target
    ]

def run_nmap(scan_target: str, ports: int, host_timeout: str, out_prefix: str) -> dict:
    out_xml = f"{out_prefix}.xml"
    out_txt = f"{out_prefix}.txt"
    cmd = build_nmap_cmd(scan_target, ports, host_timeout, out_xml, out_txt)
    rc, out, err = run_cmd(cmd, timeout=420)
    return {
        "scan_target": scan_target,
        "command": " ".join(cmd),
        "return_code": rc,
        "stdout_tail": out[-1200:],
        "stderr_tail": err[-1200:],
        "output_xml": out_xml,
        "output_txt": out_txt,
        "summary": parse_nmap_summary(out),
    }

def main():
    args = parse_args(sys.argv)

    for tool, pkg in [("dig", "dnsutils"), ("whois", "whois")]:
        if not tool_exists(tool):
            print(f"[!] '{tool}' not found. Install: sudo apt-get install {pkg}")
            sys.exit(2)

    target = normalize_target(args["target"])
    do_nmap = args["do_nmap"]
    ports = args["ports"]
    host_timeout = args["host_timeout"]
    mode = args["mode"]

    u = urlparse(target)
    domain = u.hostname
    if not domain:
        print("[!] Invalid domain/url.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain)
    out_json = f"output/{safe}_{ts}_recon.json"

    # DNS recon
    a = dig_record(domain, "A")
    aaaa = dig_record(domain, "AAAA")
    cname = dig_record(domain, "CNAME")
    ns = dig_record(domain, "NS")
    mx = dig_record(domain, "MX")
    txt = dig_record(domain, "TXT")

    whois_text = whois_lookup(domain)
    cdn = likely_cdn(ns)

    result = {
        "target": target,
        "domain": domain,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "dns": {"A": a, "AAAA": aaaa, "CNAME": cname, "NS": ns, "MX": mx, "TXT": txt[:20]},
        "whois_head": whois_text,
        "cdn_hint": cdn,
        "notes": [
            "If the site is behind a CDN (Akamai/Cloudflare/Fastly/Netlify), Nmap results reflect the CDN edge, not the origin server.",
            "Only run Nmap when you have explicit written permission."
        ]
    }

    if do_nmap:
        if not tool_exists("nmap"):
            print("[!] 'nmap' not found. Install: sudo apt-get install nmap")
            sys.exit(2)

        # Choose targets based on mode
        targets = []
        ip_target = a[0] if a else ""
        host_target = domain

        if mode == "both":
            if ip_target:
                targets.append(("ip", ip_target))
            targets.append(("host", host_target))
        elif mode == "host":
            targets.append(("host", host_target))
        else:  # mode == "ip" (default)
            if ip_target:
                targets.append(("ip", ip_target))
            else:
                # No A record; fall back to hostname scan
                targets.append(("host", host_target))

        nmap_results = {}
        for label, scan_target in targets:
            out_prefix = f"output/{safe}_{ts}_nmap_{label}"
            nmap_results[label] = run_nmap(scan_target, ports, host_timeout, out_prefix)

        result["nmap"] = nmap_results
        result["nmap_mode"] = mode

    os.makedirs("output", exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Recon saved: {out_json}")

    print("\n--- Recon Summary ---")
    print(f"Domain: {domain}")
    print(f"A: {', '.join(a) if a else '(none)'}")
    print(f"AAAA: {', '.join(aaaa) if aaaa else '(none)'}")
    print(f"CNAME: {', '.join(cname) if cname else '(none)'}")
    print(f"NS: {', '.join(ns) if ns else '(none)'}")
    print(f"MX: {', '.join(mx) if mx else '(none)'}")
    if cdn:
        print(f"CDN hint: {cdn}")

    if do_nmap:
        print(f"Nmap mode: {result.get('nmap_mode')}")
        for label, n in (result.get("nmap") or {}).items():
            s = (n.get("summary") or {})
            open_ports = s.get("open_ports") or []
            print(f"\nNmap ({label}) target: {n.get('scan_target')}")
            if open_ports:
                pretty = ", ".join([f"{p['port']}({p['service']})" for p in open_ports])
                print(f"Open ports: {pretty}")
            else:
                print("Open ports: (none found in scanned range)")
            if s.get("not_shown"):
                print(s["not_shown"])
            print(f"Outputs: {n.get('output_txt')} , {n.get('output_xml')}")
            print(f"RC: {n.get('return_code')}")

if __name__ == "__main__":
    main()
