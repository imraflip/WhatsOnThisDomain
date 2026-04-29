"""Phase 16 — Scope-aware orchestrator that chains recon tools into execution waves."""
from __future__ import annotations
import asyncio
import enum
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse
from rich.console import Console
logger = logging.getLogger(__name__)
console = Console()
# ---------------------------------------------------------------------------
# Input classification
# ---------------------------------------------------------------------------
_API_PATH_PREFIXES = (
    "/api", "/v1", "/v2", "/v3", "/v4", "/graphql", "/gql", "/rest",
    "/rpc", "/trpc", "/swagger", "/openapi",
)
class ScopeType(str, enum.Enum):
    """The four scope categories from the Execution Matrix."""
    WILDCARD = "wildcard"
    HOSTNAME = "hostname"
    PATH = "path"
    API = "api"
@dataclass(frozen=True)
class RoutedInput:
    """Result of classifying user input."""
    scope_type: ScopeType
    root_domain: str
    base_url: str | None = None      # scheme://host (for hostname/path/api)
    path_prefix: str | None = None   # e.g. /admin or /v1
class InputRouter:
    """Classify a user-supplied string into one of the four scope types."""
    @staticmethod
    def classify(raw: str) -> RoutedInput:
        parsed = urlparse(raw)
        # No scheme → treat as bare domain (wildcard)
        if not parsed.scheme:
            return RoutedInput(
                scope_type=ScopeType.WILDCARD,
                root_domain=raw.strip().lower(),
            )
        host = (parsed.hostname or "").lower()
        root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/") or ""
        if path:
            # Check if path looks like an API prefix
            path_lower = path.lower()
            is_api = any(path_lower.startswith(p) for p in _API_PATH_PREFIXES)
            if is_api:
                return RoutedInput(
                    scope_type=ScopeType.API,
                    root_domain=root,
                    base_url=base_url,
                    path_prefix=path,
                )
            return RoutedInput(
                scope_type=ScopeType.PATH,
                root_domain=root,
                base_url=base_url,
                path_prefix=path,
            )
        # URL with scheme but no meaningful path → hostname scope
        return RoutedInput(
            scope_type=ScopeType.HOSTNAME,
            root_domain=root,
            base_url=base_url,
        )
def is_under_prefix(url: str, base_path: str) -> bool:
    """Path guard: return True if *url*'s path starts with *base_path*."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not base_path.endswith("/"):
        return path == base_path or path.startswith(base_path + "/")
    return path.startswith(base_path)
# ---------------------------------------------------------------------------
# Wave definitions
# ---------------------------------------------------------------------------
@dataclass
class WaveResult:
    tool: str
    ok: bool
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
@dataclass
class PipelineReport:
    scope_type: ScopeType
    input_raw: str
    results: list[WaveResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    @property
    def failed(self) -> list[WaveResult]:
        return [r for r in self.results if not r.ok]
# ---------------------------------------------------------------------------
# ReconPipeline
# ---------------------------------------------------------------------------
# Per-module timeout in seconds (smart timeouts per PLAN.md)
_MODULE_TIMEOUTS: dict[str, int] = {
    "sub-enum": 600,
    "sub-permute": 1800,
    "sub-resolve": 600,
    "sub-probe": 600,
    "vhost-enum": 600,
    "tech-detect": 300,
    "web-fingerprint": 300,
    "web-screenshot": 300,
    "web-crawl": 600,
    "dir-brute": 900,
    "api-discover": 900,
    "js-discover": 600,
}
class ReconPipeline:
    """Scope-aware orchestrator that runs tools in dependency-ordered waves.
    Concurrency is bounded by an ``asyncio.Semaphore(3)`` so that no more than
    three heavy tool processes are active at any time.
    """
    def __init__(self, routed: RoutedInput, *, notify: bool = False) -> None:
        self.routed = routed
        self.notify = notify
        self._sem = asyncio.Semaphore(3)
        self.report = PipelineReport(
            scope_type=routed.scope_type,
            input_raw=routed.base_url or routed.root_domain,
        )
    # -- helpers -------------------------------------------------------------
    async def _run_tool(self, name: str, coro: object) -> WaveResult:
        """Run a single tool coroutine under the semaphore with a timeout."""
        wr = WaveResult(tool=name, ok=False)
        timeout = _MODULE_TIMEOUTS.get(name, 600)
        async with self._sem:
            try:
                await asyncio.wait_for(coro, timeout=timeout)  # type: ignore[arg-type]
                wr.ok = True
            except asyncio.TimeoutError:
                wr.error = f"timed out after {timeout}s"
                console.print(f"[yellow]{name} timed out after {timeout}s[/yellow]")
            except Exception as exc:  # noqa: BLE001
                wr.error = str(exc)
                console.print(f"[red]{name} failed: {exc}[/red]")
            finally:
                wr.finished_at = datetime.now(UTC)
        self.report.results.append(wr)
        return wr
    async def _run_wave(self, tasks: list[tuple[str, object]]) -> list[WaveResult]:
        """Run a list of (name, coroutine) pairs concurrently."""
        if not tasks:
            return []
        return list(
            await asyncio.gather(*(self._run_tool(n, c) for n, c in tasks))
        )
    # -- wave builders -------------------------------------------------------
    def _get_url(self) -> str:
        """Return the base URL (with scheme) for URL-accepting tools."""
        return self.routed.base_url or f"https://{self.routed.root_domain}"
    def _get_scoped_url(self) -> str:
        """Return URL including path prefix for path/api scoped tools."""
        base = self._get_url()
        if self.routed.path_prefix:
            return base + self.routed.path_prefix
        return base
    async def run(self) -> PipelineReport:
        """Execute the full pipeline according to the scope type."""
        from wotd.cli import (
            _run_api_discover,
            _run_crawl,
            _run_dirbust,
            _run_discover_js,
            _run_subdomains,
            _run_subdomains_permute,
            _run_tech_detect,
            _run_vhost_enum_url,
            _run_visual_surface,
            _run_web_profile,
        )
        st = self.routed.scope_type
        root = self.routed.root_domain
        url = self._get_url()
        scoped_url = self._get_scoped_url()
        # ── Wave A (Discovery) ──────────────────────────────────────────
        if st == ScopeType.WILDCARD:
            console.print("[bold cyan]Wave A — Discovery[/bold cyan]")
            await self._run_wave([
                ("sub-enum", _run_subdomains(root, notify=False)),
                ("sub-permute", _run_subdomains_permute(root, mode="balanced",
                                                        max_candidates=20000,
                                                        budget_minutes=30,
                                                        notify=False)),
            ])
        # ── Wave B (DNS) ────────────────────────────────────────────────
        # sub-resolve is already part of _run_subdomains pipeline, so Wave B
        # is only needed if we ran Wave A.  _run_subdomains already chains
        # passive → active → resolve → probe internally, so we skip
        # explicit resolve here.
        # ── Wave C (HTTP / sub-probe) ───────────────────────────────────
        # For hostname/path/api scopes we still need sub-probe + metadata.
        if st in (ScopeType.HOSTNAME, ScopeType.PATH, ScopeType.API):
            console.print("[bold cyan]Wave C — Probe[/bold cyan]")
            # sub-probe is embedded in _run_subdomains; for single-host we
            # just ensure the host is probed via tech-detect (Wave D).
        # ── Wave D (Profiling) ──────────────────────────────────────────
        console.print("[bold cyan]Wave D — Profiling[/bold cyan]")
        wave_d: list[tuple[str, object]] = [
            ("tech-detect", _run_tech_detect(url, notify=False)),
            ("web-fingerprint", _run_web_profile(url, notify=False)),
        ]
        if st != ScopeType.API:
            wave_d.append(
                ("web-screenshot", _run_visual_surface(url, notify=False))
            )
        await self._run_wave(wave_d)
        # ── Wave E (Mapping) ────────────────────────────────────────────
        console.print("[bold cyan]Wave E — Mapping[/bold cyan]")
        wave_e: list[tuple[str, object]] = []
        if st == ScopeType.WILDCARD:
            wave_e.append(("web-crawl", _run_crawl(url, notify=False)))
            wave_e.append(("dir-brute", _run_dirbust(url, notify=False)))
            wave_e.append(("api-discover", _run_api_discover(
                url, notify=False,
                active_methods={"passive", "active", "gql", "spec"},
            )))
            wave_e.append(("js-discover", _run_discover_js(url, notify=False)))
            wave_e.append(("vhost-enum", _run_vhost_enum_url(url, notify=False)))
        elif st == ScopeType.HOSTNAME:
            wave_e.append(("web-crawl", _run_crawl(url, notify=False)))
            wave_e.append(("dir-brute", _run_dirbust(url, notify=False)))
            wave_e.append(("api-discover", _run_api_discover(
                url, notify=False,
                active_methods={"passive", "active", "gql", "spec"},
            )))
            wave_e.append(("js-discover", _run_discover_js(url, notify=False)))
            wave_e.append(("vhost-enum", _run_vhost_enum_url(url, notify=False)))
        elif st == ScopeType.PATH:
            wave_e.append(("web-crawl", _run_crawl(scoped_url, notify=False)))
            wave_e.append(("dir-brute", _run_dirbust(scoped_url, notify=False)))
            wave_e.append(("js-discover", _run_discover_js(scoped_url, notify=False)))
        elif st == ScopeType.API:
            wave_e.append(("api-discover", _run_api_discover(
                scoped_url, notify=False,
                active_methods={"passive", "active", "gql", "spec"},
            )))
            wave_e.append(("js-discover", _run_discover_js(scoped_url, notify=False)))
            wave_e.append(("web-crawl", _run_crawl(scoped_url, notify=False)))
        await self._run_wave(wave_e)
        # ── Finalise ────────────────────────────────────────────────────
        self.report.finished_at = datetime.now(UTC)
        # Notify summary
        if self.notify:
            await self._send_summary()
        return self.report
    async def _send_summary(self) -> None:
        from wotd.notify import dispatch
        ok = [r for r in self.report.results if r.ok]
        failed = self.report.failed
        parts = [f"[wotd] scan {self.report.input_raw} complete"]
        parts.append(f"  ✅ {len(ok)} tools succeeded")
        if failed:
            parts.append(f"  ❌ {len(failed)} tools failed: {', '.join(r.tool for r in failed)}")
        message = "\n".join(parts)
        try:
            await dispatch(message)
        except Exception:  # noqa: BLE001
            pass
