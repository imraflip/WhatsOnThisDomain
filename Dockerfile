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
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && mv /root/go/bin/httpx /root/go/bin/httpx-pd \
    && go install github.com/projectdiscovery/notify/cmd/notify@latest

# Passive URL crawl tools
RUN go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest

RUN pip install --no-cache-dir waymore

# Active crawl tools
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/jaeles-project/gospider@latest \
    && go install github.com/hakluke/hakrawler@latest

# JS discovery tools
# subjs/getjs: find .js URLs linked from pages (stdin: URLs, stdout: JS URLs)
# jsluice: extract endpoints and secrets from JS content (JSON output)
RUN go install github.com/lc/subjs@latest \
    && go install github.com/003random/getjs@latest \
    && go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# gf pattern matching — install binary + community patterns into ~/.gf
RUN go install github.com/tomnomnom/gf@latest \
    && mkdir -p /root/.gf \
    && git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf-src \
    && cp /tmp/gf-src/examples/*.json /root/.gf/ \
    && rm -rf /tmp/gf-src \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json /root/.gf/ \
    && rm -rf /tmp/gf-patterns

# Build massdns from source (no apt package available)
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make \
    && cp bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Fetch wordlists and resolvers for active subdomain enumeration.
# Medium is the default (faster than huge, good coverage). Tiny is used by tests.
RUN mkdir -p /opt/wotd/wordlists \
    && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt \
        -o /opt/wotd/wordlists/dns.txt \
    && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt \
        -o /opt/wotd/wordlists/dns_tiny.txt \
    && curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o /opt/wotd/resolvers.txt

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY pyproject.toml uv.lock README.md ./
COPY wotd/ ./wotd/

RUN uv sync --frozen

ENTRYPOINT ["/app/.venv/bin/python", "-m", "wotd"]
