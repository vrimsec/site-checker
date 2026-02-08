# Website Security Health Check Report (Combined)
- Date: 2026-02-08T23:16:26
- Target: https://swag.golf
- Final URL: https://swag.golf/

## Security Profile (no LLM)

- Risk level: **Low**
- CDN hint: Cloudflare
- Missing security headers: referrer-policy, permissions-policy
- Present security headers: content-security-policy, strict-transport-security, x-frame-options, x-content-type-options
- Nuclei findings (count): 0
- ZAP alerts (count): 0
- Nmap open ports: 80/tcp, 443/tcp, 8080/tcp(!), 8443/tcp(!)

## Notable Observations

- CDN note: CDNs/WAFs may add/remove headers; validate at origin if you control it.
- Nmap note: If the site is behind a CDN proxy, Nmap results may reflect edge infrastructure, not origin.
- Alt HTTP exposed (verify admin panels) — restrict/allowlist if not required.
- Alt HTTPS exposed (verify admin panels) — restrict/allowlist if not required.
- Missing browser security headers reduces defense-in-depth (especially CSP/HSTS/XFO/nosniff).

## Top Automated Findings

### Nuclei (top)

- No matches found (or scan timed out).

### ZAP (top)

- No alerts found (or scan not run / timed out).

## Suggested Fixes (starting points)

- Set Referrer-Policy to limit referrer leakage (e.g., strict-origin-when-cross-origin).
- Set Permissions-Policy to restrict browser features you don't need.
- Alt HTTP exposed (verify admin panels): restrict with firewall/VPN/allowlist; disable if not needed.
- Alt HTTPS exposed (verify admin panels): restrict with firewall/VPN/allowlist; disable if not needed.

## Outputs

- Combined JSON: `/runs/output/swag.golf_20260208_231626_combined.json`
- Report: `/runs/reports/swag.golf_20260208_231626_site_check_report.md`
