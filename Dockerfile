# syntax=docker/dockerfile:1

# ---- Stage 1: grab nuclei binary from official image ----
FROM projectdiscovery/nuclei:latest AS nuclei

# ---- Stage 2: main image based on official ZAP (includes zap-* scripts) ----
FROM ghcr.io/zaproxy/zaproxy:stable

USER root
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Tools needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    python3-requests \
    ca-certificates curl jq unzip \
    nmap dnsutils whois netcat-openbsd openssl \
    \
  && rm -rf /var/lib/apt/lists/*

# Put nuclei in PATH
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN chmod +x /usr/local/bin/nuclei && nuclei -version || true

# Python venv for recon tools (sublist3r + theHarvester)
RUN python3 -m venv /opt/recon-venv && \
    /opt/recon-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/recon-venv/bin/pip install --no-cache-dir theHarvester sublist3r

# Make CLI tools available
RUN ln -sf /opt/recon-venv/bin/theHarvester /usr/local/bin/theHarvester && \
    ln -sf /opt/recon-venv/bin/sublist3r /usr/local/bin/sublist3r

# Copy project
COPY . /app

# Default dirs
RUN mkdir -p /app/runs/output /app/runs/reports

CMD ["bash"]

# ---- UI deps (Flask) ----
RUN python3 -m pip install --no-cache-dir flask==3.0.2 || true
COPY ui /app/ui


# ---- Go + subdomain tools (ARM-friendly) ----
# Force install location so we don't depend on GOPATH paths like /root/go/bin.
ENV GOBIN=/usr/local/bin

RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
 && rm -rf /var/lib/apt/lists/* \
 && go env \
 && go install github.com/owasp-amass/amass/v4/...@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && chmod +x /usr/local/bin/amass /usr/local/bin/assetfinder || true


# ---- Python deps for UI/runtime (PEP668-safe) ----
RUN python3 -m venv /opt/ui-venv \
 && /opt/ui-venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/ui-venv/bin/pip install --no-cache-dir flask requests

# ---- Go + subdomain tools (ARM-friendly) ----
USER root
ENV GOPATH=/tmp/go
ENV GOBIN=/usr/local/bin

RUN apt-get update \
 && apt-get install -y --no-install-recommends golang-go git \
 && rm -rf /var/lib/apt/lists/* \
 && go install github.com/owasp-amass/amass/v4/...@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && chmod +x /usr/local/bin/amass /usr/local/bin/assetfinder

# optional cleanup (smaller image)
RUN apt-get purge -y golang-go git || true \
 && apt-get autoremove -y || true \
 && rm -rf /var/lib/apt/lists/* /tmp/go

USER zap
