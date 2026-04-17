# PLAN.md — WhatsOnThisDomain

This is the source of truth for the project. If reality diverges from this document, stop and ask whether to update the plan or change the code.

---

## Project overview

WhatsOnThisDomain (`wotd`) is a recon and attack surface monitoring pipeline for bug bounty hunting and authorized penetration testing. It automates the tedious parts of reconnaissance — subdomain enumeration, endpoint crawling, liveness checking, diffing against previous scans — so that new assets and changes surface automatically instead of requiring manual re-runs and eyeballing.

The user is an experienced Python developer. The tool is built for personal use in bug bounty programs and authorized pentesting engagements.

The high-level shape: a modular async Python pipeline where each module handles one recon concern, shells out to best-in-class Go tools where they exist, and writes structured results into a shared SQLite store. Modules can run independently or be chained. Diffing against previous runs is built in, so you get notified when something new appears on a target's attack surface.

The CLI command is `wotd`, with `whatsonthisdomain` registered as a second alias pointing to the same entry point.

---

## Scope rules and safety

This tool is for authorized testing only:

- Bug bounty programs with a defined scope.
- The user's own infrastructure.
- CTF and lab environments.

That's it. No exceptions.

Every module must filter its outputs through a `Scope` object before writing anything to the store. Out-of-scope assets are rejected at the boundary — they never land in the database. The scope object supports exact domain matches, wildcard patterns, and regex rules, with both include and exclude lists. Exclude rules take precedence over include rules.

This isn't just a policy statement. It's an architectural constraint: the scope check is part of the module contract, not an optional step.

---

## Terminology

- **Module** — an internal component that performs one category of recon (subdomain enumeration, crawling, etc.). Not called a stage, phase, or task. Code lives in `wotd/modules/`.
- **Scan run** — one invocation of one or more modules against a target. Tracked in the database with timestamps so we can diff between runs.
- **Store** — the SQLite database shared across all modules. Single source of truth for discovered assets.

---

## Planned modules

Modules are listed in priority order. The MVP (v0.1) is **subdomain enumeration** and **crawl/endpoint discovery**. Everything else is future work — documented here so the shape is visible, but not built yet.

### `subdomains` — MVP

Passive + active subdomain enumeration, resolution, and liveness probing in a single pipeline.

**What it does:**

1. **Passive enumeration.** Pulls subdomains from subfinder, crt.sh (via API), and other free passive sources. No traffic hits the target directly at this stage.
2. **Active bruteforce.** Runs shuffledns with a wordlist against the target, using massdns as the resolver backend. Includes wildcard detection and filtering — if a domain has a catch-all DNS record, shuffledns handles it, but we verify and log the wildcard status.
3. **Merge and normalize.** Deduplicates results from all sources, normalizes domain names (lowercase, strip trailing dots, remove wildcards like `*.`), tags each result with its source.
4. **DNS resolution.** Runs dnsx against the merged subdomain list to get A, AAAA, CNAME records.
5. **HTTP liveness probing.** Runs httpx-pd (ProjectDiscovery's Go binary, not the Python library) to check which resolved hosts actually serve HTTP/HTTPS. Captures status codes, titles, tech fingerprints if available.
6. **Diff and notify.** Compares against the previous scan run for the same target. Reports separate counts: new subdomains discovered vs. newly-live HTTP services.

**External tools:** subfinder, shuffledns, massdns, dnsx, httpx-pd.

**DB tables (reads/writes):**
- Writes: `subdomains`, `dns_records`, `http_services`
- Reads: `targets`, `scan_runs` (for diffing)

**Input:** Single domain (`acme.com`), multiple domains (`acme.com,foo.org`), wildcard (`*.acme.com`), or multiple wildcards. The scope object determines what's in bounds regardless of input format.

### `crawl` — MVP

Web crawling and endpoint discovery from multiple sources.

**What it does:**

1. Runs katana, waymore, xnlinkfinder, hakrawler, waybackurls, and gospider against the target URLs.
2. Merges all discovered endpoints, deduplicates, normalizes URL formats.
3. Writes to the `endpoints` table with source tagging.
4. Diffs against previous scan runs, notifies on new endpoints.

**External tools:** katana, waymore, xnlinkfinder, hakrawler, waybackurls, gospider.

**DB tables:**
- Writes: `endpoints`
- Reads: `targets`, `scan_runs`

**Input:** Full URL(s) with scheme — `https://acme.com`, not just `acme.com`. If the user passes a bare domain without a scheme, the CLI warns and refuses. This is deliberate: crawlers need to know whether to hit HTTP or HTTPS, and guessing leads to missed coverage or wasted time.

### `js-discovery` — future

JavaScript file discovery and analysis. Parses JS files for hidden API endpoints, secrets, internal paths, and other interesting strings. Builds on the endpoints discovered by the crawl module.

### `port-scan` — future

Wrapper around naabu and/or masscan. **Off by default.** Must be explicitly enabled per scan because many bug bounty programs explicitly forbid port scanning. The CLI should make this opt-in friction obvious, not hide it behind a flag.

### `dir-bruteforce` — future

Wrapper around ffuf and/or feroxbuster for directory and file bruteforcing.

### `tech-detect`, `waf-detect` — future

Enrichment layer that runs on top of liveness data. Identifies technologies, frameworks, CDNs, and WAFs. Some of this data may come for free from httpx-pd's output; these modules would add deeper analysis.

### Further future modules (not planned in detail)

- `takeover-check` — subdomain takeover detection (CNAME pointing to unclaimed resources).
- `nuclei-scan` — vulnerability scanning with nuclei templates. Careful scoping needed.
- `favicon-pivot` — favicon hash lookup for Shodan/Censys correlation.
- `asn-lookup` — ASN and IP range enumeration.
- `reverse-whois` — discover related domains via WHOIS data.
- `github-recon` — search GitHub for leaked secrets, internal paths, config files related to the target.

---

## Database schema (initial)

All timestamps are UTC. Tables for discoverable entities include `first_seen` and `last_seen` columns so diffing between scan runs is a cheap query rather than a full comparison.

### `targets`

The root objects. A target is a domain or set of domains being monitored.

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `name` | text | Human-readable label |
| `root_domains` | text | Comma-separated or JSON list of root domains |
| `scope_config` | text | JSON blob — include/exclude rules |
| `created_at` | datetime | |
| `updated_at` | datetime | |

### `scan_runs`

One row per invocation. Links modules to targets with timing info.

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `target_id` | integer FK → targets | |
| `module` | text | Which module ran (`subdomains`, `crawl`, etc.) |
| `started_at` | datetime | |
| `finished_at` | datetime | Null if still running or crashed |
| `status` | text | `running`, `completed`, `failed` |
| `summary` | text | JSON blob — counts, stats, whatever the module wants to record |

### `subdomains`

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `target_id` | integer FK → targets | |
| `fqdn` | text | Fully qualified domain name, normalized |
| `source` | text | How it was found (`subfinder`, `crtsh`, `shuffledns`, etc.) |
| `is_wildcard` | boolean | Whether this resolves due to a wildcard record |
| `first_seen` | datetime | First scan run that found this |
| `last_seen` | datetime | Most recent scan run that found this |
| `scan_run_id` | integer FK → scan_runs | The run that first discovered it |

Unique constraint on `(target_id, fqdn)`.

### `dns_records`

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `subdomain_id` | integer FK → subdomains | |
| `record_type` | text | `A`, `AAAA`, `CNAME`, etc. |
| `value` | text | The resolved value |
| `first_seen` | datetime | |
| `last_seen` | datetime | |
| `scan_run_id` | integer FK → scan_runs | |

### `http_services`

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `subdomain_id` | integer FK → subdomains | |
| `url` | text | Full URL including scheme and port |
| `status_code` | integer | |
| `title` | text | Page title if available |
| `content_length` | integer | |
| `tech` | text | JSON list of detected technologies |
| `first_seen` | datetime | |
| `last_seen` | datetime | |
| `scan_run_id` | integer FK → scan_runs | |

### `endpoints`

| Column | Type | Notes |
|--------|------|-------|
| `id` | integer PK | |
| `target_id` | integer FK → targets | |
| `url` | text | Full URL |
| `method` | text | HTTP method if known, null otherwise |
| `source` | text | Which crawler/tool found it |
| `content_type` | text | If known |
| `first_seen` | datetime | |
| `last_seen` | datetime | |
| `scan_run_id` | integer FK → scan_runs | |

Unique constraint on `(target_id, url, method)`.

---

## How work is done on this project

Read this section carefully. It governs every future session.

**Work is done milestone by milestone.** Each milestone is a logical chunk of work. After finishing one milestone, stop and wait for the user to review before starting the next. Do not chain milestones.

**If you hit anything unexpected — an ambiguity, a design decision not covered by this document, a tool that behaves differently than expected, a schema question — stop and ask the user. Do not improvise. Do not make architectural decisions unilaterally.** The cost of asking is low. The cost of unwinding a bad assumption is high.

**PLAN.md is the source of truth.** If the code diverges from this plan, or if you think the plan should change, stop and surface it. Don't silently deviate.

**Everything goes straight to `main`.** Solo project, no branches or PRs. Just commit and push.

**Commit messages:** plain lowercase imperative. One or two sentences. Examples:
- `add scope class with include and exclude rule matching`
- `implement subfinder wrapper with async subprocess`
- `fix wildcard detection when root domain has catch-all dns`
- `add tests for scope regex rule evaluation`

---

## Roadmap

Listed in order. Each milestone is a logical chunk of work. Check the box when done.

- [x] **M1** — Project scaffold. Initial commit on main.
- [x] **M2** — Dev tooling. Ruff, type checker, pytest, pre-commit, smoke test.
- [x] **M3** — Config and scope. Config loader, Scope class, HackerOne/Bugcrowd importers, tests.
- [x] **M4** — Store foundation. SQLAlchemy async engine, targets and scan_runs tables, Alembic.
- [x] **M5** — CLI skeleton. Typer CLI with both entry points, command stubs.
- [x] **M6** — Module base and tool wrappers. Abstract module base class, async subprocess wrapper, output parsers.
- [x] **M7** — Docker setup. Dockerfile with all Go tools, docker-compose.yml. Moved up from M13 so every later milestone can be tested end-to-end in a reproducible environment.
- [x] **M8** — Subdomains (passive). Passive enumeration, subdomains table.
- [x] **M9** — Normalize helpers refactor. Extract shared domain normalization utils.
- [x] **M10** — Subdomains (active). shuffledns integration with wildcard filtering.
- [x] **M11** — Subdomains (resolve + liveness). dnsx, httpx-pd, dns_records and http_services tables, end-to-end wiring.
- [x] **M12** — Show command. `wotd show subdomains [target]` for reading what's stored in the db, with filtering (--source, --since, --include-unprobed, --limit, --all, --json).
- [ ] **M13** — Diff and notify. Diff logic, Discord/Telegram/Slack webhook dispatchers.
- [ ] **M14** — CLI help and guide polish. The current help tree makes users drill through `wotd → show → subdomains --help` just to see what flags exist. Fix discoverability: richer top-level `--help` with examples, command summaries that hint at usage, a `wotd examples` or similar cheat-sheet command, and consistent help text across every command. Also consider shorter aliases (e.g. `wotd ls` for `wotd show subdomains`) if they pull their weight.
- [ ] **M15** — Docs. README with install, config, and usage examples.
- [ ] **M16** — Crawl module. All crawlers, endpoints table, diff+notify.

---

### M1 — Project scaffold (done)

Bare project skeleton committed directly to main.

Files: `pyproject.toml`, `.gitignore`, `LICENSE`, `README.md`, `wotd/__init__.py`, `wotd/modules/__init__.py`.

### M2 — Dev tooling

Linting, formatting, type checking, test runner. A trivial smoke test proves the package imports.

Commits:
1. `configure ruff, type checker, and pytest with pre-commit hooks`
2. `add smoke test that imports the wotd package`

### M3 — Config and scope

Config loading and the scope system. This is a medium chunk because scope is foundational — everything downstream depends on it being right.

Commits:
1. `add config loader with yaml and dotenv support`
2. `add scope class with exact, wildcard, and regex rule matching`
3. `add scope exclude rules with precedence over includes`
4. `add hackerone and bugcrowd scope importers`
5. `add tests for config loading and scope evaluation`

### M4 — Store foundation

Database setup. Only the `targets` and `scan_runs` tables — module-specific tables come with their modules.

Commits:
1. `set up sqlalchemy async engine with aiosqlite`
2. `add targets and scan_runs models with initial alembic migration`
3. `add store helper for creating scan runs and updating status`

### M5 — CLI skeleton

The CLI exists and responds to `--help`. Commands for future modules are stubs.

Commits:
1. `add typer cli with wotd and whatsonthisdomain entry points`
2. `add command stubs for subdomains and crawl modules`

### M6 — Module base and tool wrappers

The abstract module contract and the async subprocess utility. Bundled because you can't meaningfully test one without the other.

Commits:
1. `add abstract module base class with run and scope filtering contract`
2. `add async subprocess wrapper with timeout and binary-existence check`
3. `add output parsing utilities for line-delimited and json tool output`
4. `add tests for subprocess wrapper and output parsers`

### M7 — Docker setup

Containerization so every real-tool test from here on can run in a reproducible environment without polluting the host with Go binaries. Moved ahead of the subdomain work because M8+ all need live external tools.

Dockerfile based on a Python slim image, installs Go, installs all the Go tools (subfinder, assetfinder, shuffledns + massdns, dnsx, httpx-pd, katana, hakrawler, waybackurls, gospider, notify), copies the project, sets `wotd` as entrypoint. `docker-compose.yml` mounts the host config and data dirs so runs persist.

Commits:
1. `add dockerfile with python, go, and all external tool installations`
2. `add docker-compose.yml with config and data volume mounts`

### M8 — Subdomains (passive)

Passive subdomain enumeration. The `subdomains` table lands here.

Commits:
1. `add subdomains table with alembic migration`
2. `implement subfinder wrapper`
3. `add crt.sh passive source via http client`
4. `add one or two more passive sources`
5. `wire passive sources into subdomains module with dedup and normalization`

### M9 — Normalize helpers refactor

Small cleanup. Domain normalization logic got duplicated between the scope class and the subdomain module during M3 and M8. Extract it into a shared utility.

Commits:
1. `extract domain normalization helpers into shared utils`
2. `update scope and subdomains module to use shared normalization`

### M10 — Subdomains (active)

Active DNS bruteforce with shuffledns. Wildcard detection and filtering.

Commits:
1. `implement shuffledns wrapper with wordlist and resolver configuration`
2. `add wildcard detection and filtering logic`
3. `integrate active bruteforce into subdomains module pipeline`

### M11 — Subdomains (resolve + liveness)

DNS resolution and HTTP liveness probing. This is a bigger chunk because the pieces are tightly coupled — dnsx feeds httpx-pd, both need new tables, and the whole thing needs to wire into the existing subdomain module so one `wotd subdomains acme.com` does passive → active → resolve → liveness end to end.

Commits:
1. `add dns_records and http_services tables with alembic migration`
2. `implement dnsx wrapper for dns resolution`
3. `implement httpx-pd wrapper for http liveness probing`
4. `wire resolution and liveness into subdomains module pipeline`
5. `add end-to-end test for subdomains module with mocked tool output`
6. `handle edge cases: timeouts, partial failures, empty results`

### M12 — Diff and notify

Diffing between scan runs and notification dispatch.

Commits:
1. `add diff logic comparing current scan run against previous for same target`
2. `add discord webhook notification dispatcher`
3. `add telegram and slack webhook dispatchers`
4. `wire diff and notify into subdomains module with separate counts for new subdomains vs new services`

### M13 — Docs

Flesh out the README. Sometimes you write docs in the middle of a project, not at the end.

Commits:
1. `write readme with installation, configuration, and usage examples for subdomain module`

### M14 — Crawl module

The crawl module. Bigger chunk because the crawlers follow a similar pattern and splitting each out would be noise.

Commits:
1. `add endpoints table with alembic migration`
2. `scaffold crawl module with base wiring and input validation`
3. `implement katana, waybackurls, and gau wrappers`
4. `implement waymore and gospider wrappers`
5. `implement xnlinkfinder and hakrawler wrappers`
6. `add endpoint deduplication and normalization`
7. `wire all crawlers into crawl module with source tagging`
8. `integrate diff and notify for new endpoints`

### Beyond PR 14

Future modules (js-discovery, port-scan, dir-bruteforce, tech-detect, nuclei-scan, etc.) will get their own PR sequences planned when we get there. The module list above shows the direction, but detailed commit plans for work that far out would be fiction. We'll plan those PRs when the MVP is solid and we know what patterns emerged from building it.

---

## Out of scope for v0.1

To be explicit about what v0.1 does **not** include:

- Web dashboard or any kind of UI beyond the CLI.
- Postgres backend (SQLite only, migration path documented but not built).
- JavaScript discovery and analysis module.
- Port scanning.
- Directory bruteforcing.
- Nuclei or any vulnerability scanning.
- Subdomain takeover checks.
- Any form of exploitation or active vulnerability probing.

These are all future work. Some are in the module list above, some aren't. None are in v0.1.

---

## Open questions

Things to revisit later. Not blocking v0.1, but worth thinking about:

- **Postgres migration trigger.** When does it make sense to switch from SQLite to postgres? At what data volume or concurrency level? Or just when a web dashboard needs it?
- **Web dashboard timing.** Build one eventually? Use an existing tool like Nuclei's reporting? Ship scan results to something like Planka or Notion?
- **Plugin system.** Should third-party modules be possible? A plugin interface adds complexity. Might not be worth it if it's just for personal use.
- **Automatic scope re-fetch.** Should the HackerOne/Bugcrowd scope importers re-fetch automatically on each scan, or only when explicitly asked? Programs change scope — stale scope config could mean scanning out-of-bounds assets.
- **Notification batching.** For large targets with hundreds of new findings, should notifications be batched/summarized or sent individually?
