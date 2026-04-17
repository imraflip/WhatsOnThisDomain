# Tech Stack — WhatsOnThisDomain

## Language and runtime

Python 3.11 or newer. We get better async semantics, improved error messages, and the ecosystem is comfortably on 3.11+ at this point. No reason to support older versions.

## Package and environment management

**uv** for dependency management, lockfile, and Python version pinning. It's fast, modern, handles everything poetry does with less friction, and generates a proper lockfile.

## Core Python libraries

| Library | Purpose |
|---------|---------|
| `typer` | CLI framework |
| `rich` | Pretty CLI output — tables, progress bars, spinners |
| `sqlalchemy` (2.x, async) | ORM and query builder. Using async mode with an eye toward future postgres migration |
| `aiosqlite` | Async SQLite driver for SQLAlchemy |
| `alembic` | Database schema migrations |
| `pyyaml` | Config file parsing |
| `python-dotenv` | `.env` file loading |
| `httpx` (Python library) | HTTP client for internal Python-side HTTP calls (crt.sh queries, webhook dispatch, etc.) |
| `aiodns` | Async DNS resolution if needed on the Python side |
| `pydantic` | Data models and config validation |

> **Important disambiguation:** The Python `httpx` library and ProjectDiscovery's `httpx` Go binary are completely different tools that happen to share a name. Throughout this codebase, the Go binary is referred to as **`httpx-pd`** or "ProjectDiscovery httpx" to avoid confusion. When you see `httpx` in Python imports, that's the HTTP client library. When you see `httpx-pd` in subprocess calls or docs, that's the Go-based HTTP prober.

## Dev tooling

- **pytest** + **pytest-asyncio** — test runner. Async-first since most of the codebase is async.
- **ruff** — linting and formatting in one tool.
- **mypy** (strict mode) — static type checking.
- **pre-commit** — git hooks for lint/format on commit so nothing unformatted lands in the repo.

## External Go binaries (shelled out to)

These are best-in-class tools written in Go. We shell out to them as subprocesses rather than reimplementing their logic.

| Tool | Description | Install |
|------|-------------|---------|
| `subfinder` (ProjectDiscovery) | Passive subdomain enumeration from dozens of sources | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `assetfinder` (tomnomnom) | Passive subdomain enumeration from a handful of free sources | `go install -v github.com/tomnomnom/assetfinder@latest` |
| `shuffledns` (ProjectDiscovery) | Active DNS bruteforce with wildcard filtering. Requires massdns as a backend | `go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |
| `massdns` | High-performance DNS stub resolver, used as the backend for shuffledns | Built from source: `git clone https://github.com/blechschmidt/massdns && cd massdns && make` |
| `dnsx` (ProjectDiscovery) | Fast DNS resolver and record query tool | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx` (ProjectDiscovery) | HTTP probing, tech detection, WAF detection. **Referred to as `httpx-pd` in docs and code** | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` (ProjectDiscovery) | Web crawler with headless browser support | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| `waymore` | Historical URL fetcher from multiple archive sources | `pip install waymore` (Python, not Go, but same usage pattern) |
| `xnlinkfinder` | Endpoint extraction from JavaScript files and HTTP responses | `pip install xnlinkfinder` |
| `hakrawler` | Simple fast web crawler | `go install -v github.com/hakluke/hakrawler@latest` |
| `waybackurls` | Fetch URLs from the Wayback Machine | `go install -v github.com/tomnomnom/waybackurls@latest` |
| `gospider` | Web spider with multiple source support | `go install -v github.com/jauntyjocularjay/gospider@latest` |
| `notify` (ProjectDiscovery) | Notification dispatcher. May use this or dispatch directly from Python — TBD | `go install -v github.com/projectdiscovery/notify/cmd/notify@latest` |

## Storage

**SQLite** via SQLAlchemy + aiosqlite for v0.1. The database lives at `~/.local/share/wotd/wotd.db` (or the OS-appropriate path via `platformdirs`).

The schema is swappable to postgres later because SQLAlchemy abstracts the backend. This is a documented future migration path, not a current feature — don't over-engineer for it now, just don't do anything SQLite-specific that would make migration painful.

## Config

- **`~/.config/wotd/config.yaml`** — structured settings: tool binary paths, wordlist paths, default scan options, resolver lists, notification channel definitions.
- **`.env`** or real environment variables — secrets: API keys for subfinder sources, webhook URLs for notifications.
- **Precedence:** env vars > `.env` > `config.yaml`. An env var always wins.

## Containerization

Dockerfile based on a Python slim image. Installs Go, installs all Go tools via `go install`, copies the project, sets `wotd` as the entrypoint. A `docker-compose.yml` provides ergonomic local runs with mounted config (`~/.config/wotd`) and data (`~/.local/share/wotd`) volumes.

## Licensing

MIT.
