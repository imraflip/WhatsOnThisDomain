# Quickstart

WhatsOnThisDomain (`wotd`) runs inside Docker. There is no host install — everything goes through `docker compose`.

## Prerequisites

- Docker and Docker Compose
- A target you are authorized to test (bug bounty scope, your own infra, CTF/lab)

## Services

The compose file defines two services backed by the same image:

| Service | Purpose |
|---|---|
| `wotd` | Runs the `wotd` CLI. Entry point is `python -m wotd`, so everything after the service name is passed straight to Typer. |
| `wotd-dev` | Same image with no entrypoint. Used for pytest, shells, sqlite, and anything else that is not the CLI itself. |

Both services bind-mount `./wotd` and `./tests`, so Python edits take effect on the next `run` with no rebuild.

## Build the image

```bash
docker compose build wotd
```

First build takes a few minutes (pulls Go, installs subfinder / assetfinder / shuffledns / massdns / dnsx / httpx-pd, downloads the medium and tiny n0kovo wordlists and the trickest resolvers). Subsequent builds are cached unless `Dockerfile`, `pyproject.toml`, or `uv.lock` change.

Rebuild only when:

- the `Dockerfile` changes
- dependencies change (`pyproject.toml` / `uv.lock`)
- wordlists or resolvers should be refreshed

Everyday Python edits do **not** need a rebuild.

## Run the tool

### Full subdomain pipeline

Passive → active → resolve → probe, all in one run:

```bash
docker compose run --rm wotd subdomains hackerone.com
```

Output is stored in a persistent SQLite database inside the `wotd-data` volume. Re-running against the same target merges with previous findings rather than starting fresh, so running on a schedule naturally accumulates history.

### Inspect stored results

Show probed (live) subdomains for a target:

```bash
docker compose run --rm wotd show subdomains hackerone.com
```

Show the latest live subdomains across every target you've scanned:

```bash
docker compose run --rm wotd show subdomains
```

Useful flags on `show subdomains`:

| Flag | Effect |
|---|---|
| `--since 24h` | only rows first seen within the window (`24h`, `7d`, `2w`) |
| `--source subfinder` | filter by discovery source |
| `--include-unprobed` | include hosts that did not respond to HTTP |
| `--limit 100` | change the row cap (default 25, `0` = no limit) |
| `--all` | ignore `--since` and `--limit` |
| `--json` | raw JSON instead of a table |

### Poke at the database directly

```bash
docker compose run --rm wotd-dev sqlite3 /root/.local/share/wotd/wotd.db
```

## Running the tests

The test suite has two tiers:

- **`tests/unit/`** — hermetic unit tests. No network, no external binaries. Fast. Run these constantly.
- **`tests/modules/`** — real-tool integration tests. Each one shells out to the actual Go binary (subfinder, shuffledns, dnsx, httpx-pd) and hits the live internet against `hackerone.com`. Slow, can be flaky, network-dependent. Run these when touching a module.

### The whole suite

```bash
docker compose run --rm wotd-dev pytest
```

### Unit tests only (fast, offline, safe default)

```bash
docker compose run --rm wotd-dev pytest tests/unit
```

### Real-tool module tests (slow, needs network)

```bash
docker compose run --rm wotd-dev pytest tests/modules
```

### A single module

```bash
docker compose run --rm wotd-dev pytest tests/modules/test_subdomains_active.py
docker compose run --rm wotd-dev pytest tests/modules/test_subdomains_passive.py
docker compose run --rm wotd-dev pytest tests/modules/test_subdomains_resolve.py
docker compose run --rm wotd-dev pytest tests/modules/test_subdomains_probe.py
```

### A single test function

```bash
docker compose run --rm wotd-dev pytest tests/modules/test_subdomains_active.py::test_active_enum
```

### Useful pytest flags

| Flag | Effect |
|---|---|
| `-v` | verbose, show each test name |
| `-x` | stop on first failure |
| `-k <pattern>` | only tests whose name matches the pattern |
| `--lf` | re-run only the tests that failed last time |
| `-s` | do not capture stdout (handy for debugging real-tool output) |

### Lint and type check

```bash
docker compose run --rm wotd-dev ruff check wotd tests
docker compose run --rm wotd-dev mypy wotd
```

## Troubleshooting

- **`no matching subdomains`** — the default view only shows probed hosts. Pass `--include-unprobed` to see everything the enumeration stage found, or re-run `wotd subdomains <target>` to populate probe data.
- **Active phase feels slow** — the default wordlist is `n0kovo_subdomains_medium.txt`. For quick smoke tests, point at the tiny wordlist: modify the module call site, or wait for the `--wordlist` override flag (planned).
- **Stale `running` scan runs in the db** — previous runs that were Ctrl-C'd before completing. Harmless; they do not block new runs.
