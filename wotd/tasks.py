from __future__ import annotations

import hashlib
import json
from enum import IntEnum
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wotd.parsers import normalize_url


class Priority(IntEnum):
    DISCOVERY = 1
    PROFILING = 2
    MAPPING = 3


def _extract_host(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return (parsed.hostname or "").strip().lower()


class Task(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    task_hash: str = ""
    parent_task_id: UUID | None = None
    source_module: str | None = None
    priority: Priority = Priority.MAPPING
    retry_count: int = 0
    max_retries: int = 2
    cooldown_until: float | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.task_hash:
            object.__setattr__(self, "task_hash", self.compute_task_hash())

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(
            exclude={
                "id",
                "task_hash",
                "parent_task_id",
                "source_module",
                "priority",
                "retry_count",
                "max_retries",
                "cooldown_until",
            }
        )

    def compute_task_hash(self) -> str:
        payload = self.hash_payload()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def scope_target(self) -> str | None:
        return None

    def merge(self, other: "Task") -> bool:
        return False


class DomainTask(Task):
    domain: str
    priority: Priority = Priority.DISCOVERY

    def hash_payload(self) -> dict[str, Any]:
        return {"domain": self.domain.strip().lower()}

    def scope_target(self) -> str | None:
        return self.domain.strip().lower()


class HostnameTask(Task):
    fqdn: str
    priority: Priority = Priority.DISCOVERY

    def hash_payload(self) -> dict[str, Any]:
        return {"fqdn": self.fqdn.strip().lower()}

    def scope_target(self) -> str | None:
        return self.fqdn.strip().lower()


class ResolvedHostTask(Task):
    fqdn: str
    ips: list[str]
    priority: Priority = Priority.DISCOVERY

    def hash_payload(self) -> dict[str, Any]:
        return {"fqdn": self.fqdn.strip().lower(), "ips": sorted(self.ips)}

    def scope_target(self) -> str | None:
        return self.fqdn.strip().lower()


class UrlTask(Task):
    url: str
    host: str | None = None
    priority: Priority = Priority.PROFILING

    @model_validator(mode="after")
    def _fill_host(self) -> "UrlTask":
        if not self.host:
            host = _extract_host(self.url)
            if host:
                object.__setattr__(self, "host", host)
        return self

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {"url": normalized}

    def scope_target(self) -> str | None:
        return self.host or _extract_host(self.url)


class EndpointTask(Task):
    url: str
    method: str | None = None
    content_type: str | None = None
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {
            "url": normalized,
            "method": self.method or "",
            "content_type": self.content_type or "",
        }

    def scope_target(self) -> str | None:
        return _extract_host(self.url)


class JsFileTask(Task):
    url: str
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {"url": normalized}

    def scope_target(self) -> str | None:
        return _extract_host(self.url)


class SecretTask(Task):
    kind: str
    data: str
    source_js_url: str
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "data": self.data,
            "source_js_url": self.source_js_url,
        }

    def scope_target(self) -> str | None:
        return _extract_host(self.source_js_url)


class ApiRouteTask(Task):
    url: str
    method: str
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {"url": normalized, "method": self.method.upper()}

    def scope_target(self) -> str | None:
        return _extract_host(self.url)


class ApiSpecTask(Task):
    spec_url: str
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.spec_url) or self.spec_url.strip()
        return {"spec_url": normalized}

    def scope_target(self) -> str | None:
        return _extract_host(self.spec_url)


class TechTag(Task):
    url: str
    techs: list[str]
    priority: Priority = Priority.PROFILING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {"url": normalized, "techs": sorted({t.strip() for t in self.techs if t})}

    def merge(self, other: "Task") -> bool:
        if not isinstance(other, TechTag):
            return False
        merged = sorted({t.strip() for t in (self.techs + other.techs) if t})
        object.__setattr__(self, "techs", merged)
        return True

    def scope_target(self) -> str | None:
        return _extract_host(self.url)


class FingerprintTag(Task):
    url: str
    headers: dict[str, str]
    server: str | None = None
    priority: Priority = Priority.PROFILING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {
            "url": normalized,
            "headers": self.headers,
            "server": self.server or "",
        }

    def merge(self, other: "Task") -> bool:
        if not isinstance(other, FingerprintTag):
            return False
        merged_headers = {**self.headers, **other.headers}
        object.__setattr__(self, "headers", merged_headers)
        if not self.server and other.server:
            object.__setattr__(self, "server", other.server)
        return True

    def scope_target(self) -> str | None:
        return _extract_host(self.url)


class ScreenshotTag(Task):
    url: str
    path: str
    phash: str | None = None
    priority: Priority = Priority.MAPPING

    def hash_payload(self) -> dict[str, Any]:
        normalized = normalize_url(self.url) or self.url.strip()
        return {"url": normalized, "path": self.path, "phash": self.phash or ""}

    def scope_target(self) -> str | None:
        return _extract_host(self.url)

