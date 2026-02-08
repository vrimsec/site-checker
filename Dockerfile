# syntax=docker/dockerfile:1

# ---- Stage 1: grab nuclei binary from official image ----
FROM projectdiscovery/nuclei:latest AS nuclei

# ---- Stage 2: main image based on official ZAP (includes zap-baseline.py) ----
FROM ghcr.io/zaproxy/zaproxy:stable

USER root
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Tools your scripts need (recon + python runtime)
# NOTE: Use apt packages for python libs to avoid PEP-668 pip block.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    python3-requests \
    ca-certificates curl jq unzip \
    nmap dnsutils whois \
  && rm -rf /var/lib/apt/lists/*

# Put nuclei in PATH
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN chmod +x /usr/local/bin/nuclei && nuclei -version || true

# Copy your project files
COPY . /app

# Default dirs (you can bind-mount these in compose later)
RUN mkdir -p /app/output /app/reports

# Ollama defaults (override in docker-compose)
ENV OLLAMA_URL="http://127.0.0.1:11434/api/generate"
ENV OLLAMA_MODEL="qwen2.5-coder:3b"

CMD ["bash"]
