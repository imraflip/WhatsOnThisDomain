"""Virtual host enumeration via ffuf Host-header fuzzing."""

from __future__ import annotations

import json
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import normalize_hosts
from wotd.scope import Scope
from wotd.store import get_subdomain_hosts, upsert_vhost_services
from wotd.tools import ToolNotFoundError, run_tool

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")
_META_PREFIX = "WOTD_META:"
_MAX_BODY_CAPTURE = 120_000


def _normalize_title(title: str | None) -> str | None:
    if title is None:
        return None
    cleaned = _WHITESPACE_RE.sub(" ", title).strip()
    return cleaned.lower() if cleaned else None


def _extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    return _normalize_title(match.group(1))


def _extract_ffuf_vhost(entry: dict[str, object]) -> str | None:
    input_obj = entry.get("input")
    if isinstance(input_obj, dict):
        fuzz = input_obj.get("FUZZ")
        if isinstance(fuzz, str) and fuzz.strip():
            return fuzz.strip().lower().rstrip(".")
    host = entry.get("host")
    if isinstance(host, str) and host.strip():
        return host.strip().lower().rstrip(".")
    return None


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _build_vhost_url(base_url: str, vhost: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.scheme:
        return f"https://{vhost}"
    netloc = vhost
    if parsed.port:
        netloc = f"{vhost}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", "", ""))


def _load_wordlist_candidates(wordlist: Path, root_domain: str) -> list[str]:
    candidates: list[str] = []
    for line in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if "://" in value:
            parsed = urlparse(value)
            value = (parsed.hostname or "").lower().rstrip(".")
            if not value:
                continue
        if "." not in value:
            value = f"{value}.{root_domain}"
        candidates.append(value)
    return normalize_hosts(candidates)


@dataclass(frozen=True)
class _ResponseFingerprint:
    status_code: int | None
    title: str | None
    content_length: int | None


def _length_is_similar(current: int | None, baseline: int | None) -> bool:
    if current is None or baseline is None:
        return False
    threshold = max(48, int(baseline * 0.04))
    return abs(current - baseline) <= threshold


def _is_baseline_like(
    hit_status: int | None,
    hit_title: str | None,
    hit_content_length: int | None,
    baseline: list[_ResponseFingerprint],
) -> bool:
    normalized_title = _normalize_title(hit_title)
    for fp in baseline:
        if hit_status != fp.status_code:
            continue
        if _length_is_similar(hit_content_length, fp.content_length):
            return True
        if normalized_title and fp.title and normalized_title == fp.title:
            return True
    return False


class VhostEnumModule(Module):
    name = "vhost_enum"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        base_urls: list[str],
        candidate_wordlist: Path | None = None,
        max_candidates: int = 20000,
    ) -> None:
        super().__init__(session, target, scope)
        self.base_urls = sorted({u.rstrip("/") for u in base_urls if u.strip()})
        self.candidate_wordlist = candidate_wordlist
        self.max_candidates = max_candidates

    async def _baseline_for_service(self, base_url: str) -> list[_ResponseFingerprint]:
        probes = [
            f"wotd-{secrets.token_hex(8)}.{self.target.name}",
            f"wotd-{secrets.token_hex(8)}.{self.target.name}",
        ]
        out: list[_ResponseFingerprint] = []
        for host in probes:
            result = await run_tool(
                "curl",
                [
                    "-k",
                    "-sS",
                    "-L",
                    "--max-time",
                    "12",
                    "-H",
                    f"Host: {host}",
                    base_url,
                    "-w",
                    f"\n{_META_PREFIX}%{{http_code}}:%{{size_download}}\n",
                ],
                timeout=30.0,
            )
            status_code: int | None = None
            content_length: int | None = None
            body = result.stdout
            for line in reversed(result.stdout.splitlines()):
                if line.startswith(_META_PREFIX):
                    body = result.stdout.rsplit(line, 1)[0]
                    parts = line[len(_META_PREFIX) :].split(":", 1)
                    if len(parts) == 2:
                        try:
                            status_code = int(parts[0])
                        except ValueError:
                            status_code = None
                        try:
                            content_length = int(parts[1])
                        except ValueError:
                            content_length = None
                    break
            out.append(
                _ResponseFingerprint(
                    status_code=status_code,
                    title=_extract_title(body[:_MAX_BODY_CAPTURE]),
                    content_length=content_length,
                )
            )
        return out

    async def _ffuf_service(
        self,
        base_url: str,
        candidates_file: Path,
    ) -> list[dict[str, object]]:
        result = await run_tool(
            "ffuf",
            [
                "-u",
                base_url,
                "-w",
                str(candidates_file),
                "-H",
                "Host: FUZZ",
                "-rate",
                "100",
                "-t",
                "40",
                "-timeout",
                "10",
                "-ac",
                "-mc",
                "200,201,204,301,302,307,308,401,403,405",
                "-json",
            ],
            timeout=None,
        )
        hits: list[dict[str, object]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            vhost = _extract_ffuf_vhost(entry)
            if not vhost:
                continue
            hits.append(
                {
                    "base_url": base_url,
                    "vhost": vhost,
                    "url": _build_vhost_url(base_url, vhost),
                    "status_code": _int_or_none(entry.get("status")),
                    "title": entry.get("title") if isinstance(entry.get("title"), str) else None,
                    "content_length": _int_or_none(entry.get("length")),
                }
            )
        return hits

    async def run(self) -> ModuleResult:
        known_subdomains = await get_subdomain_hosts(self.session, self.target.id)
        candidate_hosts = normalize_hosts(known_subdomains)

        if self.candidate_wordlist is not None and self.candidate_wordlist.exists():
            candidate_hosts = normalize_hosts(
                candidate_hosts
                + _load_wordlist_candidates(self.candidate_wordlist, self.target.name)
            )

        truncated = False
        if len(candidate_hosts) > self.max_candidates:
            candidate_hosts = candidate_hosts[: self.max_candidates]
            truncated = True

        if not candidate_hosts:
            return ModuleResult(
                module=self.name,
                stats={
                    "base_services": len(self.base_urls),
                    "candidates": 0,
                    "truncated": truncated,
                    "hits": 0,
                    "baseline_filtered": 0,
                    "out_of_scope_filtered": 0,
                    "new": 0,
                    "existing": 0,
                    "errors": {},
                },
            )

        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                prefix="wotd-vhost-",
                suffix=".txt",
            ) as tmp:
                tmp_path = Path(tmp.name)
                tmp.write("\n".join(candidate_hosts))
                tmp.write("\n")

            errors: dict[str, str] = {}
            all_hits: list[dict[str, object]] = []
            baseline_filtered = 0
            out_of_scope_filtered = 0

            for base_url in self.base_urls:
                try:
                    baseline = await self._baseline_for_service(base_url)
                    service_hits = await self._ffuf_service(base_url, tmp_path)
                except ToolNotFoundError as e:
                    errors[base_url] = str(e)
                    continue
                except Exception as e:
                    errors[base_url] = str(e)
                    continue

                for hit in service_hits:
                    vhost = str(hit["vhost"])
                    if not self.scope.is_in_scope(vhost):
                        out_of_scope_filtered += 1
                        continue
                    if _is_baseline_like(
                        hit_status=hit.get("status_code")
                        if isinstance(hit.get("status_code"), int)
                        else None,
                        hit_title=hit.get("title") if isinstance(hit.get("title"), str) else None,
                        hit_content_length=hit.get("content_length")
                        if isinstance(hit.get("content_length"), int)
                        else None,
                        baseline=baseline,
                    ):
                        baseline_filtered += 1
                        continue
                    all_hits.append(hit)

            new_count, existing_count, new_urls = await upsert_vhost_services(
                self.session, self.target.id, all_hits
            )
            return ModuleResult(
                module=self.name,
                stats={
                    "base_services": len(self.base_urls),
                    "candidates": len(candidate_hosts),
                    "truncated": truncated,
                    "hits": len(all_hits),
                    "baseline_filtered": baseline_filtered,
                    "out_of_scope_filtered": out_of_scope_filtered,
                    "new": new_count,
                    "existing": existing_count,
                    "new_urls": new_urls,
                    "errors": errors,
                },
            )
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink()
