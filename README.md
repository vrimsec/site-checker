# Site-Checker (v1.0.1)

Run a quick website security health check (Nmap + Nuclei + ZAP baseline) and get:
- `runs/output/` (raw outputs + combined JSON)
- `runs/reports/` (Markdown report)

## Run (Ubuntu)

```bash
# 1) Install Docker + Compose plugin
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 2) Allow your user to run docker without sudo (log out/in after this)
sudo usermod -aG docker $USER
newgrp docker

# 3) Clone repo
git clone https://github.com/vrimsec/site-checker.git
cd site-checker

# 4) Build + run (it will prompt you for the target URL)
docker compose build
docker compose run --rm site-checker

Results

After the scan, results are saved here:

ls -la runs/output
ls -la runs/reports


Report file format:

runs/reports/<target>_<timestamp>_site_check_report.md
