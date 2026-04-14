FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/root/go \
    PATH=/app/.venv/bin:/root/go/bin:/usr/local/go/bin:/root/.local/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.25.1
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install recon tools used by current milestones
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Build massdns from source (no apt package available)
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make \
    && cp bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Fetch wordlist and resolvers for active subdomain enumeration
RUN mkdir -p /opt/wotd/wordlists \
    && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt \
        -o /opt/wotd/wordlists/dns.txt \
    && curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o /opt/wotd/resolvers.txt

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY pyproject.toml uv.lock README.md ./
COPY wotd/ ./wotd/

RUN uv sync --frozen

ENTRYPOINT ["/app/.venv/bin/python", "-m", "wotd"]
