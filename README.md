# Site-Checker (Docker) — Nmap + Nuclei + ZAP Baseline (Combined Report)

This project runs **three automated security checks** against a target website and produces:
- a **combined JSON** file (raw results)
- a **Markdown report** (human-readable)

It is intended for **lab/testing websites** (dev/staging), internal apps you own, or systems you have explicit permission to test.

---

## What it does (high level)

1) **Input + validation**
- Prompts for a target URL
- Accepts: `https://example.com` OR `http://example.com`
- If you type only `example.com` or `www.example.com` it will re-prompt and tell you the expected format

2) **Reachability check**
- Confirms the target is reachable before scanning
- If unreachable, it writes a short report and stops (so you know it’s “DOWN/unreachable” from *this machine/network*)

3) **Recon + Nmap**
- DNS records (A/AAAA/CNAME/NS/MX/TXT)
- WHOIS (best-effort; can timeout on some TLDs)
- Nmap scan (note: if behind a CDN/WAF, the scan may reflect edge/CDN, not origin)

4) **Nuclei**
- Runs nuclei with JSONL output
- Follows redirects
- Saves results even if there are 0 findings

5) **ZAP Baseline**
- Runs ZAP baseline scan (lightweight)
- Produces alert counts (and top alerts if your script includes them)

6) **Combined Report**
- Writes a combined JSON + a Markdown report in one run

---

## Requirements (host machine)

You only need:
- **Docker**
- **Docker Compose v2** (the `docker compose` command)

You do **NOT** need Python installed on the host if you run via Docker.

---

## Quick start (run a scan)

From the repo directory:

```bash
cd ~/site-checker-docker
docker compose build
docker compose run --rm site-checker


3) **Recon + Nmap**
- DNS records (A/AAAA/CNAME/NS/MX/TXT)
- WHOIS (**best-effort**; can timeout on some TLDs/registries)
- Nmap scan (results may show **CDN/edge**, not the origin server)

4) **Nuclei**
- Runs Nuclei against the final URL
- Writes findings to **JSONL** (even when there are 0 matches)

5) **ZAP Baseline**
- Runs ZAP baseline scan (quick passive checks)
- Records alert counts (and top alerts if available)

6) **Combined report**
- Saves:
  - `*_combined.json` (all raw results together)
  - `*_site_check_report.md` (human readable report)

---

## Requirements (Host)

You only need:
- **Docker**
- **Docker Compose v2**

You do **NOT** need Python on your host if you run via Docker.

---

## Quick Start

From the repo folder:

```bash
cd site-checker-docker
docker compose build
docker compose run --rm site-checker


---

## Requirements (Host)

You only need:
- **Docker**
- **Docker Compose v2**

You do **NOT** need Python on your host if you run via Docker.

---

## Quick Start

From the repo folder:

```bash
docker compose build
docker compose run --rm site-checker

It will prompt you:

Enter target URL (format: https://example.com OR http://example.com):

Where results are saved (IMPORTANT)

All results are saved on your host machine inside the runs/ folder in this project directory:

Reports (Markdown): ./runs/reports/

Raw outputs + combined JSON: ./runs/output/

Examples:

./runs/reports/<target>_<timestamp>_site_check_report.md

./runs/output/<target>_<timestamp>_combined.json

List results:

ls -la ./runs/output
ls -la ./runs/reports


View the latest report:

ls -t ./runs/reports/*_site_check_report.md | head -n 1
cat "$(ls -t ./runs/reports/*_site_check_report.md | head -n 1)"

First-time Nuclei templates (only if needed)

If Nuclei complains templates are missing, run:

docker compose run --rm --entrypoint nuclei site-checker -update-templates

Try from the host:

getent hosts example.com
curl -Ivs --max-time 12 https://example.com/ 2>&1 | head -n 30
EOT
