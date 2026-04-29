"""Web profile module — captures HTTP metadata posture and content fingerprints."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.scope import Scope
from wotd.store import (
    get_http_service_urls,
    list_web_profiles,
    upsert_service_fingerprints,
    upsert_web_profiles,
)
from wotd.tools import run_tool


class WebProfileModule(Module):
    """Probe HTTP services and extract metadata posture + content fingerprints.

    Captures headers (Server, CSP, HSTS, CORS), cookie flags (Secure, HttpOnly, SameSite),
    response title, and computes hashes for favicon and body content. Stores profiles and
    fingerprints, detects changes vs prior scans, and evaluates security posture.
    """

    name = "web_profile"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        single_url: str | None = None,
    ) -> None:
        super().__init__(session, target, scope)
        self.single_url = single_url

    async def _compute_favicon_hash(self, favicon_path: str | None) -> str | None:
        """Compute hash of favicon if available.
        Placeholder for future icon fetching.
        """
        return None

    async def _compute_body_hash(self, body: str) -> str:
        """Compute SHA256 hash of response body."""
        return hashlib.sha256(body.encode()).hexdigest()

    async def _compute_title_hash(self, title: str | None) -> str | None:
        """Compute hash of page title for fingerprinting."""
        if not title:
            return None
        return hashlib.sha256(title.encode()).hexdigest()

    async def _extract_headers(
        self, headers_json: str | None
    ) -> tuple[str | None, str | None, str | None, str | None]:
        """Extract Server, CSP, HSTS, CORS headers from httpx output.

        Returns (server, csp, hsts, cors).
        """
        if not headers_json:
            return None, None, None, None

        try:
            headers = json.loads(headers_json)
            if not isinstance(headers, dict):
                return None, None, None, None

            # Normalize header names (case-insensitive lookup)
            headers_lower = {k.lower(): v for k, v in headers.items()}

            server = headers_lower.get("server")
            csp = headers_lower.get("content-security-policy")
            hsts = headers_lower.get("strict-transport-security")
            cors = headers_lower.get("access-control-allow-origin")

            return server, csp, hsts, cors
        except (json.JSONDecodeError, ValueError):
            return None, None, None, None

    async def _extract_cookie_flags(self, set_cookie_raw: str | None) -> str | None:
        """Parse Set-Cookie header and extract individual cookie flags (JSON).

        Returns JSON string like {"secure": true, "httponly": true, "samesite": "Strict"} or None.
        """
        if not set_cookie_raw:
            return None

        flags: dict[str, Any] = {}
        parts = set_cookie_raw.split(";")

        for part in parts[1:]:  # Skip the first part (name=value)
            part_lower = part.strip().lower()
            if part_lower == "secure":
                flags["secure"] = True
            elif part_lower == "httponly":
                flags["httponly"] = True
            elif part_lower.startswith("samesite="):
                flags["samesite"] = part_lower.split("=", 1)[1]

        return json.dumps(flags) if flags else None

    async def _probe_services(self, urls: list[str]) -> dict[str, dict[str, Any]]:
        """Probe HTTP services via httpx-pd and extract metadata.

        Returns dict mapping URL to probe result dict with status, headers, body, etc.
        """
        if not urls:
            return {}

        result = await run_tool(
            "httpx-pd",
            [
                "-json",
                "-silent",
                "-timeout",
                "10",
            ],
            stdin_data="\n".join(urls),
            timeout=None,
        )

        probes: dict[str, dict[str, Any]] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url")
            if not url:
                continue

            body = obj.get("body", "")
            body_hash = await self._compute_body_hash(body) if body else None
            title = obj.get("title")
            title_hash = await self._compute_title_hash(title)

            # Extract metadata headers
            headers_json = json.dumps(obj.get("headers", {})) if obj.get("headers") else None
            server, csp, hsts, cors = await self._extract_headers(headers_json)

            set_cookie_raw = obj.get("set_cookie_raw")
            cookie_flags_json = await self._extract_cookie_flags(set_cookie_raw)

            probes[url] = {
                "status_code": obj.get("status_code"),
                "title": title,
                "server": server,
                "csp": csp,
                "hsts": hsts,
                "cors": cors,
                "set_cookie_raw": set_cookie_raw,
                "cookie_flags_json": cookie_flags_json,
                "headers_json": headers_json,
                "body_hash": body_hash,
                "title_hash": title_hash,
            }

        return probes

    async def _evaluate_posture(self, profiles: list[dict[str, Any]]) -> list[str]:
        """Evaluate security posture of profiles and return findings.

        Checks for:
        - Missing HSTS
        - Missing or weak CSP
        - Missing CORS restrictions
        - Cookies without Secure flag (auth-related)

        Returns list of finding strings.
        """
        findings: list[str] = []

        for profile in profiles:
            url = profile.get("url", "")
            hsts = profile.get("hsts")
            csp = profile.get("csp")
            set_cookie = profile.get("set_cookie_raw")
            cookie_flags_json = profile.get("cookie_flags_json")

            # Check HSTS
            if not hsts:
                findings.append(f"{url}: missing HSTS header")

            # Check CSP
            if not csp:
                findings.append(f"{url}: missing Content-Security-Policy header")
            elif "unsafe" in csp.lower():
                findings.append(f"{url}: weak CSP (contains 'unsafe')")

            # Check cookie flags
            if set_cookie and cookie_flags_json:
                try:
                    flags = json.loads(cookie_flags_json)
                    if not flags.get("secure"):
                        findings.append(f"{url}: cookie missing Secure flag")
                    if not flags.get("httponly"):
                        findings.append(f"{url}: cookie missing HttpOnly flag")
                except (json.JSONDecodeError, ValueError):
                    pass

        return findings

    async def run(self) -> ModuleResult:
        """Execute the web profile module.

        1. Determine URLs to probe (single URL or all from DB).
        2. Re-probe them via httpx-pd with header extraction.
        3. Store web profiles (metadata) and service fingerprints (hashes).
        4. Evaluate security posture.
        5. Compare against prior profiles for drift detection.
        6. Return stats for the scan run.
        """
        if self.single_url:
            service_urls = [self.single_url]
        else:
            # Read all http_services URLs for this target
            service_urls = await get_http_service_urls(self.session, self.target.id)

        if not service_urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "total_services": 0,
                    "profiles_stored": 0,
                    "fingerprints_stored": 0,
                    "posture_findings": 0,
                    "profile_changes": 0,
                },
            )

        # Re-probe all services
        probes = await self._probe_services(service_urls)

        # Build profile and fingerprint lists from probes
        profiles: list[dict[str, Any]] = []
        fingerprints: list[dict[str, Any]] = []

        for url, probe in probes.items():
            # Scope-check host before writes
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                if not host or not self.scope.is_in_scope(host):
                    continue
            except Exception:
                continue

            # Build web profile record
            profiles.append(
                {
                    "url": url,
                    "status_code": probe.get("status_code"),
                    "title": probe.get("title"),
                    "server": probe.get("server"),
                    "csp": probe.get("csp"),
                    "hsts": probe.get("hsts"),
                    "cors": probe.get("cors"),
                    "set_cookie_raw": probe.get("set_cookie_raw"),
                    "cookie_flags_json": probe.get("cookie_flags_json"),
                    "headers_json": probe.get("headers_json"),
                }
            )

            # Build service fingerprint record
            fingerprints.append(
                {
                    "url": url,
                    "favicon_hash": probe.get("favicon_hash"),
                    "body_hash": probe.get("body_hash"),
                    "title_hash": probe.get("title_hash"),
                }
            )

        # Store profiles and fingerprints
        profiles_stored = await upsert_web_profiles(self.session, self.target.id, profiles)
        fingerprints_stored = await upsert_service_fingerprints(
            self.session, self.target.id, fingerprints
        )

        # Evaluate posture
        posture_findings = await self._evaluate_posture(profiles)

        # Compare against prior profiles for drift detection
        prior_profiles = await list_web_profiles(self.session, target_id=self.target.id, limit=None)

        # Count changes: URLs with different server, CSP/HSTS, or fingerprint hashes
        profile_changes = 0
        for profile in profiles:
            url = profile["url"]
            # Find prior profile for this URL
            for prior in prior_profiles:
                if prior.url == url:
                    # Check for meaningful drift
                    if (
                        prior.server != profile.get("server")
                        or prior.csp != profile.get("csp")
                        or prior.hsts != profile.get("hsts")
                    ):
                        profile_changes += 1
                    break

        return ModuleResult(
            module=self.name,
            stats={
                "total_services": len(service_urls),
                "profiles_stored": profiles_stored,
                "fingerprints_stored": fingerprints_stored,
                "posture_findings": len(posture_findings),
                "profile_changes": profile_changes,
            },
        )
