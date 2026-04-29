"""Visual surface module - captures screenshots and tracks visual drift."""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from urllib.parse import urlparse

from PIL import Image
from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.scope import Scope
from wotd.store import (
    get_http_service_urls,
    get_latest_service_screenshot,
    upsert_service_screenshots,
)
from wotd.tools import ToolNotFoundError, run_tool
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.tasks import ScreenshotTag, Task, UrlTask

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}
_SCREENSHOT_DIR = Path.home() / ".local" / "share" / "wotd" / "screenshots"


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip().lower())
    return cleaned.strip("._-") or "item"


def _hash_url(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]


def _normalize_phash(phash: str) -> str:
    value = phash.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return value.zfill(16)[:16]


def _phash_distance(left: str, right: str) -> int:
    return (int(_normalize_phash(left), 16) ^ int(_normalize_phash(right), 16)).bit_count()


def _image_dimensions(path: Path) -> tuple[int, int]:
    with Image.open(path) as image:
        return image.width, image.height


def _phash_from_image(path: Path) -> str:
    with Image.open(path) as image:
        image = image.convert("L").resize((32, 32), Image.Resampling.LANCZOS)
        pixels = [float(v) for v in image.tobytes()]

    rows = [pixels[i * 32 : (i + 1) * 32] for i in range(32)]
    coeffs: list[float] = []
    scale = 0.25
    norm = math.pi / 32.0

    for u in range(8):
        cu = 1.0 / math.sqrt(2.0) if u == 0 else 1.0
        for v in range(8):
            cv = 1.0 / math.sqrt(2.0) if v == 0 else 1.0
            total = 0.0
            for x in range(32):
                cos_x = math.cos((2 * x + 1) * u * norm)
                row = rows[x]
                for y in range(32):
                    total += row[y] * cos_x * math.cos((2 * y + 1) * v * norm)
            coeffs.append(scale * cu * cv * total)

    threshold = median(coeffs[1:]) if len(coeffs) > 1 else coeffs[0]
    bits = ["1" if coeff > threshold else "0" for coeff in coeffs]
    return f"{int(''.join(bits), 2):016x}"


def _collect_image_candidates(roots: list[Path]) -> list[Path]:
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in _IMAGE_SUFFIXES:
                candidates.append(path)
    candidates.sort(
        key=lambda path: (
            path.stat().st_mtime,
            path.stat().st_size,
        ),
        reverse=True,
    )
    return candidates


@dataclass(frozen=True)
class _ScreenshotCapture:
    host: str
    url: str
    screenshot_path: Path
    phash: str
    width: int
    height: int


class VisualSurfaceModule(Module):
    name = "visual_surface"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        single_url: str | None = None,
        phash_distance_threshold: int = 10,
        urls: list[str] | None = None,
        task: object | None = None,
    ) -> None:
        super().__init__(session, target, scope, task=task)
        self.single_url = single_url
        self.phash_distance_threshold = phash_distance_threshold
        self.urls = urls

    async def _capture_with_tool(
        self,
        binary: str,
        args: list[str],
        workdir: Path,
    ) -> tuple[Path, str]:
        result = await run_tool(binary, args, timeout=240.0, cwd=str(workdir))
        del result
        search_roots = [
            workdir,
            Path.home() / ".config" / "gowitness" / "screenshots",
            Path.home() / ".config" / "httpx" / "screenshots",
            Path.home() / ".config" / "httpx-pd" / "screenshots",
        ]
        image_candidates = _collect_image_candidates(search_roots)
        if not image_candidates:
            raise RuntimeError(f"{binary} completed without producing a screenshot")
        return image_candidates[0], binary

    async def _capture_url(self, url: str, host: str) -> _ScreenshotCapture:
        with tempfile.TemporaryDirectory(prefix="wotd-visual-") as tmpdir:
            workdir = Path(tmpdir)
            attempts = [
                ("gowitness", ["single", "--url", url, "--screenshot-path", str(workdir)]),
                ("gowitness", ["single", url, "--screenshot-path", str(workdir)]),
                ("httpx-pd", ["-silent", "-json", "-ss"],),
            ]

            last_error: Exception | None = None
            for binary, args in attempts:
                try:
                    if binary == "httpx-pd":
                        result = await run_tool(
                            binary,
                            args,
                            stdin_data=f"{url}\n",
                            timeout=240.0,
                            cwd=str(workdir),
                        )
                        del result
                        image_candidates = _collect_image_candidates(
                            [
                                workdir,
                                Path.home() / ".config" / "httpx" / "screenshots",
                                Path.home() / ".config" / "httpx-pd" / "screenshots",
                            ]
                        )
                        if not image_candidates:
                            raise RuntimeError(
                                "httpx-pd completed without producing a screenshot"
                            )
                        source_image = image_candidates[0]
                    else:
                        source_image, _ = await self._capture_with_tool(binary, args, workdir)
                    width, height = _image_dimensions(source_image)
                    phash = _phash_from_image(source_image)
                    persistent_dir = (
                        _SCREENSHOT_DIR
                        / _slugify(self.target.name)
                        / _slugify(host)
                    )
                    persistent_dir.mkdir(parents=True, exist_ok=True)
                    suffix = source_image.suffix.lower()
                    dest = persistent_dir / f"{_slugify(host)}-{_hash_url(url)}-{phash}{suffix}"
                    shutil.copy2(source_image, dest)
                    return _ScreenshotCapture(
                        host=host,
                        url=url,
                        screenshot_path=dest,
                        phash=phash,
                        width=width,
                        height=height,
                    )
                except ToolNotFoundError as e:
                    last_error = e
                    continue
                except Exception as e:
                    last_error = e
                    continue

            raise RuntimeError(f"unable to capture screenshot for {url}: {last_error}")

    async def run(self) -> ModuleResult:
        if self.urls:
            service_urls = self.urls
        elif self.single_url:
            service_urls = [self.single_url]
        else:
            service_urls = await get_http_service_urls(self.session, self.target.id)

        if not service_urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "total_services": 0,
                    "captured": 0,
                    "new_services_screenshoted": 0,
                    "visual_changes_detected": 0,
                    "new_urls": [],
                    "changed_urls": [],
                    "errors": {},
                },
            )

        captures: list[dict[str, object]] = []
        errors: dict[str, str] = {}
        new_urls: list[str] = []
        changed_urls: list[str] = []
        visual_changes_detected = 0

        for url in service_urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").strip().lower()
            if not host or not self.scope.is_in_scope(host):
                continue

            try:
                previous = await get_latest_service_screenshot(self.session, self.target.id, url)
                capture = await self._capture_url(url, host)
            except Exception as e:
                errors[url] = str(e)
                continue

            if previous is not None:
                distance = _phash_distance(previous.phash, capture.phash)
                if distance > self.phash_distance_threshold:
                    visual_changes_detected += 1
                    changed_urls.append(url)
            else:
                new_urls.append(url)

            captures.append(
                {
                    "host": capture.host,
                    "url": capture.url,
                    "screenshot_path": str(capture.screenshot_path),
                    "phash": capture.phash,
                    "width": capture.width,
                    "height": capture.height,
                }
            )

        new_count, existing_count = await upsert_service_screenshots(
            self.session, self.target.id, captures
        )

        return ModuleResult(
            module=self.name,
            stats={
                "total_services": len(service_urls),
                "captured": len(captures),
                "new_services_screenshoted": new_count,
                "visual_changes_detected": visual_changes_detected,
                "new_urls": new_urls,
                "changed_urls": changed_urls,
                "existing": existing_count,
                "captures": captures,
                "errors": errors,
            },
        )


@dispatcher.register(UrlTask, module_name=VisualSurfaceModule.name)
async def handle_url_screenshot(task: UrlTask, ctx: ModuleContext) -> list[Task]:
    module = VisualSurfaceModule(ctx.session, ctx.target, ctx.scope, urls=[task.url], task=task)
    result = await ctx.run_module(module)
    captures = result.stats.get("captures", [])
    output: list[Task] = []
    for capture in captures:
        url = capture.get("url")
        path = capture.get("screenshot_path")
        if not isinstance(url, str) or not isinstance(path, str):
            continue
        output.append(
            ScreenshotTag(
                url=url,
                path=path,
                phash=capture.get("phash") if isinstance(capture.get("phash"), str) else None,
                parent_task_id=task.id,
                source_module=module.name,
            )
        )
    return output

