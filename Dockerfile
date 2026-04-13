FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/root/go \
    PATH=/root/go/bin:/usr/local/go/bin:/root/.local/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.23.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install recon tools used by current milestones
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/tomnomnom/assetfinder@latest

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY pyproject.toml uv.lock README.md ./
COPY wotd/ ./wotd/

RUN uv sync --frozen

ENTRYPOINT ["/app/.venv/bin/python", "-m", "wotd"]
