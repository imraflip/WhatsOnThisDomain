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
        jq \
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

# Directory bruteforcing
RUN go install github.com/ffuf/ffuf/v2@latest

# gf pattern matching — install binary + community patterns + custom wotd patterns into ~/.gf
RUN go install github.com/tomnomnom/gf@latest \
    && mkdir -p /root/.gf \
    && git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf-src \
    && cp /tmp/gf-src/examples/*.json /root/.gf/ \
    && rm -rf /tmp/gf-src \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json /root/.gf/ \
    && rm -rf /tmp/gf-patterns \
    && echo '{"flags":"-iE","pattern":"(dev|develop|development|staging|stage|stg|uat|test|testing|qa|sandbox|admin|administrator|portal|dashboard|console|management|api|internal|intranet|corp|corporate|vpn|backup|bak|old|legacy|deprecated|beta|demo|jenkins|ci|cd|jira|confluence|wiki|kibana|grafana|prometheus|monitoring|gitlab|drone|mail|smtp|ftp|sftp|db|database|redis|mongo|elastic|preprod|pre-prod)"}' \
        > /root/.gf/wotd-subdomains.json

# Build massdns from source (no apt package available)
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make \
    && cp bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Fetch DNS wordlists, resolvers, and raft fallback for dirbust.
# Medium is the default (faster than huge, good coverage). Tiny is used by tests.
RUN mkdir -p /opt/wotd/wordlists \
    && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt \
        -o /opt/wotd/wordlists/dns.txt \
    && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt \
        -o /opt/wotd/wordlists/dns_tiny.txt \
    && curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o /opt/wotd/resolvers.txt \
    && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt \
        -o /opt/wotd/wordlists/raft-large-directories.txt

# Fetch Assetnote wordlists into /opt/wotd/wordlists/ under stable normalized names.
# Automated lists have dated filenames — we query the JSON index once with jq to resolve
# the current filename, then download and store under a fixed name so module code is stable.
# Manual lists have stable filenames and are fetched directly.
# set -e ensures any failed download aborts the build loudly.
RUN set -e; \
    CDN="https://wordlists-cdn.assetnote.io/data"; \
    curl -fsSL "${CDN}/automated.json" -o /tmp/assetnote_automated.json; \
    for entry in \
        "httparchive_subdomains_:httparchive_subdomains.txt" \
        "httparchive_directories_1m_:httparchive_directories.txt" \
        "httparchive_js_2:httparchive_js.txt" \
        "httparchive_php_:httparchive_php.txt" \
        "httparchive_aspx_asp_cfm_svc_ashx_asmx_:httparchive_aspx.txt" \
        "httparchive_jsp_jspa_do_action_:httparchive_jsp.txt" \
    ; do \
        prefix="${entry%%:*}"; \
        dest="${entry##*:}"; \
        fname=$(jq -r --arg p "$prefix" \
            '.data[] | select(.Filename | startswith($p)) | .Filename' \
            /tmp/assetnote_automated.json | head -1); \
        echo "Downloading ${fname} -> ${dest}"; \
        curl -fsSL "${CDN}/automated/${fname}" -o "/opt/wotd/wordlists/${dest}"; \
    done; \
    curl -fsSL "${CDN}/manual/bak.txt" -o /opt/wotd/wordlists/bak.txt; \
    curl -fsSL "${CDN}/manual/dot_filenames.txt" -o /opt/wotd/wordlists/dot_filenames.txt; \
    cat /opt/wotd/wordlists/bak.txt /opt/wotd/wordlists/dot_filenames.txt \
        > /opt/wotd/wordlists/sensitive_files.txt; \
    rm /tmp/assetnote_automated.json

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY pyproject.toml uv.lock README.md ./
COPY wotd/ ./wotd/

RUN uv sync --frozen

ENTRYPOINT ["/app/.venv/bin/python", "-m", "wotd"]
