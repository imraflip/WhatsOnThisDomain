"""Phase 17 — Reactive dispatcher for task-driven recon orchestration."""

from __future__ import annotations

import asyncio
import enum
import itertools
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

from wotd.modules.base import Module
from wotd.store import finish_scan_run, log_task_run, start_scan_run
from wotd.tasks import EndpointTask, Priority, Task

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


logger = logging.getLogger(__name__)

# Per-module timeout in seconds (smart timeouts per PLAN.md)
_MODULE_TIMEOUTS: dict[str, int] = {
    "subdomains_passive": 600,
    "subdomains_active": 1800,
    "subdomains_permute": 1800,
    "subdomains_resolve": 600,
    "subdomains_probe": 600,
    "vhost_enum": 600,
    "tech_detect": 300,
    "web_profile": 300,
    "visual_surface": 300,
    "crawl": 600,
    "dirbust": 900,
    "api_passive": 900,
    "api_kiterunner": 900,
    "api_graphql": 900,
    "api_openapi": 900,
    "js_discovery": 600,
}


@dataclass
class ModuleContext:
    session: Any
    target: Any
    scope: Any

    async def run_module(self, module: Module) -> Any:
        scan_run = await start_scan_run(self.session, self.target.id, module.name)
        try:
            result = await module.run()
            await finish_scan_run(self.session, scan_run, "completed", summary=result.stats)
            return result
        except Exception as exc:  # noqa: BLE001
            await finish_scan_run(
                self.session,
                scan_run,
                "failed",
                summary={"error": str(exc)},
            )
            raise


@dataclass(frozen=True)
class HandlerSpec:
    task_type: type[Task]
    handler: Callable[[Task, ModuleContext], Any]
    module_name: str
    batch: bool = False
    buffer_size: int = 50
    buffer_seconds: float = 5.0


@dataclass
class BatchItem:
    handler: HandlerSpec
    tasks: list[Task]
    priority: Priority


@dataclass
class QueueItem:
    payload: Task | BatchItem
    priority: Priority


class Dispatcher:
    def __init__(
        self,
        *,
        scope: Any,
        session_factory: Any,
        target: Any,
        path_prefix: str | None = None,
        max_workers: int = 3,
    ) -> None:
        self.scope = scope
        self.session_factory = session_factory
        self.target = target
        self.path_prefix = path_prefix
        self.max_workers = max_workers
        self.queue: asyncio.PriorityQueue[tuple[int, int, QueueItem]] = asyncio.PriorityQueue()
        self.handlers: dict[type[Task], list[HandlerSpec]] = {}
        self.batch_handlers: dict[type[Task], HandlerSpec] = {}
        self.buffers: dict[type[Task], list[Task]] = {}
        self.buffer_timers: dict[type[Task], asyncio.Task[None]] = {}
        self.seen_tasks: set[str] = set()
        self.task_cache: dict[str, Task] = {}
        self.active_workers = 0
        self.pending_delayed = 0
        self._counter = itertools.count()
        self._sem = asyncio.Semaphore(max_workers)

    def configure(
        self,
        *,
        scope: Any,
        session_factory: Any,
        target: Any,
        path_prefix: str | None = None,
        max_workers: int | None = None,
    ) -> "Dispatcher":
        self.scope = scope
        self.session_factory = session_factory
        self.target = target
        self.path_prefix = path_prefix
        if max_workers is not None:
            self.max_workers = max_workers
            self._sem = asyncio.Semaphore(max_workers)
        self.queue = asyncio.PriorityQueue()
        self.seen_tasks.clear()
        self.task_cache.clear()
        self.active_workers = 0
        self.pending_delayed = 0
        self._counter = itertools.count()
        for timer in self.buffer_timers.values():
            timer.cancel()
        self.buffer_timers.clear()
        self.buffers.clear()
        return self

    def register(
        self,
        task_type: type[Task],
        *,
        module_name: str,
        batch: bool = False,
        buffer_size: int = 50,
        buffer_seconds: float = 5.0,
    ) -> Callable[[Callable[[Task, ModuleContext], Any]], Callable[[Task, ModuleContext], Any]]:
        def decorator(func: Callable[[Task, ModuleContext], Any]) -> Callable[[Task, ModuleContext], Any]:
            spec = HandlerSpec(
                task_type=task_type,
                handler=func,
                module_name=module_name,
                batch=batch,
                buffer_size=buffer_size,
                buffer_seconds=buffer_seconds,
            )
            if batch:
                if task_type in self.batch_handlers:
                    raise RuntimeError(f"batch handler already registered for {task_type}")
                self.batch_handlers[task_type] = spec
            self.handlers.setdefault(task_type, []).append(spec)
            return func

        return decorator

    async def enqueue(self, task: Task, *, bypass_dedup: bool = False) -> None:
        if not self._in_scope(task):
            logger.info("dropping out-of-scope task %s", task.task_hash)
            return

        existing = self.task_cache.get(task.task_hash)
        if existing and existing.merge(task):
            return

        if not bypass_dedup:
            if task.task_hash in self.seen_tasks:
                return
            self.seen_tasks.add(task.task_hash)
            self.task_cache[task.task_hash] = task

        batch_spec = self.batch_handlers.get(type(task))
        if batch_spec:
            await self._buffer_task(batch_spec, task)
            return

        await self._queue_task(task)

    async def run_until_quiescent(self) -> None:
        workers = [asyncio.create_task(self._worker_loop()) for _ in range(self.max_workers)]
        while True:
            await asyncio.sleep(0.1)
            if self._is_quiescent():
                if await self._force_flush_all_buffers():
                    continue
                break
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _worker_loop(self) -> None:
        while True:
            try:
                _, _, item = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.1)
                continue

            self.active_workers += 1
            try:
                if isinstance(item.payload, BatchItem):
                    await self._handle_batch(item.payload)
                else:
                    await self._handle_task(item.payload)
            finally:
                self.active_workers -= 1
                self.queue.task_done()

    async def _handle_task(self, task: Task) -> None:
        handlers = self.handlers.get(type(task), [])
        if not handlers:
            return

        results: list[Task] = []
        failed = False
        for spec in handlers:
            if spec.batch:
                continue
            tasks, errored = await self._run_handler(spec, task)
            results.extend(tasks)
            failed = failed or errored

        await self._enqueue_children(task, results)
        if failed:
            await self._retry_task(task)

    async def _handle_batch(self, batch: BatchItem) -> None:
        tasks, errored = await self._run_batch_handler(batch.handler, batch.tasks)
        for parent in batch.tasks:
            children = [t for t in tasks if t.parent_task_id == parent.id]
            await self._enqueue_children(parent, children)
        if errored:
            for task in batch.tasks:
                await self._retry_task(task)

    async def _run_handler(self, spec: HandlerSpec, task: Task) -> tuple[list[Task], bool]:
        return await self._run_with_context(spec, [task])

    async def _run_batch_handler(
        self, spec: HandlerSpec, tasks: list[Task]
    ) -> tuple[list[Task], bool]:
        return await self._run_with_context(spec, tasks)

    async def _run_with_context(self, spec: HandlerSpec, tasks: list[Task]) -> tuple[list[Task], bool]:
        started_at = datetime.now(UTC)
        errored = False
        output_tasks: list[Task] = []
        async with self._sem:
            async with self.session_factory() as session:
                ctx = ModuleContext(session=session, target=self.target, scope=self.scope)
                try:
                    if spec.batch:
                        result = await asyncio.wait_for(
                            spec.handler(tasks, ctx),
                            timeout=_MODULE_TIMEOUTS.get(spec.module_name, 600),
                        )
                    elif len(tasks) == 1:
                        result = await asyncio.wait_for(
                            spec.handler(tasks[0], ctx),
                            timeout=_MODULE_TIMEOUTS.get(spec.module_name, 600),
                        )
                    else:
                        result = await asyncio.wait_for(
                            spec.handler(tasks, ctx),
                            timeout=_MODULE_TIMEOUTS.get(spec.module_name, 600),
                        )
                    output_tasks = list(result or [])
                    for out_task in output_tasks:
                        if out_task.source_module is None:
                            out_task.source_module = spec.module_name
                except Exception as exc:  # noqa: BLE001
                    errored = True
                    logger.error("handler %s failed: %s", spec.module_name, exc)

                finished_at = datetime.now(UTC)
                if spec.batch:
                    await self._log_batch_runs(
                        tasks,
                        spec,
                        output_tasks,
                        started_at,
                        finished_at,
                        errored,
                    )
                elif len(tasks) == 1:
                    await self._log_task_run(tasks[0], spec, output_tasks, started_at, finished_at, errored)
                else:
                    await self._log_batch_runs(tasks, spec, output_tasks, started_at, finished_at, errored)

        return output_tasks, errored

    async def _log_task_run(
        self,
        task: Task,
        spec: HandlerSpec,
        output_tasks: list[Task],
        started_at: datetime,
        finished_at: datetime,
        errored: bool,
    ) -> None:
        async with self.session_factory() as session:
            await log_task_run(
                session,
                task_id=str(task.id),
                parent_task_id=str(task.parent_task_id) if task.parent_task_id else None,
                source_module=spec.module_name,
                input_hash=task.task_hash,
                output_count=len(output_tasks),
                status="failed" if errored else "completed",
                started_at=started_at,
                finished_at=finished_at,
            )

    async def _log_batch_runs(
        self,
        tasks: list[Task],
        spec: HandlerSpec,
        output_tasks: list[Task],
        started_at: datetime,
        finished_at: datetime,
        errored: bool,
    ) -> None:
        output_counts: dict[str, int] = {}
        for task in output_tasks:
            if task.parent_task_id:
                output_counts[str(task.parent_task_id)] = output_counts.get(
                    str(task.parent_task_id), 0
                ) + 1
        async with self.session_factory() as session:
            for task in tasks:
                await log_task_run(
                    session,
                    task_id=str(task.id),
                    parent_task_id=str(task.parent_task_id) if task.parent_task_id else None,
                    source_module=spec.module_name,
                    input_hash=task.task_hash,
                    output_count=output_counts.get(str(task.id), 0),
                    status="failed" if errored else "completed",
                    started_at=started_at,
                    finished_at=finished_at,
                )

    async def _enqueue_children(
        self,
        parent: Task,
        tasks: Iterable[Task],
    ) -> None:
        for task in tasks:
            if task.parent_task_id is None:
                task.parent_task_id = parent.id
            await self.enqueue(task)

    async def _queue_task(self, task: Task) -> None:
        item = QueueItem(payload=task, priority=task.priority)
        await self.queue.put((task.priority.value, next(self._counter), item))

    async def _buffer_task(self, spec: HandlerSpec, task: Task) -> None:
        buffer = self.buffers.setdefault(spec.task_type, [])
        buffer.append(task)
        if len(buffer) >= spec.buffer_size:
            await self._flush_buffer(spec.task_type)
            return
        if spec.task_type not in self.buffer_timers:
            self.buffer_timers[spec.task_type] = asyncio.create_task(
                self._flush_after_delay(spec.task_type, spec.buffer_seconds)
            )

    async def _flush_after_delay(self, task_type: type[Task], delay: float) -> None:
        await asyncio.sleep(delay)
        await self._flush_buffer(task_type)

    async def _flush_buffer(self, task_type: type[Task]) -> None:
        tasks = self.buffers.get(task_type, [])
        if not tasks:
            return
        spec = self.batch_handlers.get(task_type)
        if spec is None:
            return
        if timer := self.buffer_timers.pop(task_type, None):
            timer.cancel()
        priority = min(t.priority for t in tasks)
        batch_item = BatchItem(handler=spec, tasks=tasks[:], priority=priority)
        self.buffers[task_type] = []
        await self.queue.put((priority.value, next(self._counter), QueueItem(batch_item, priority)))

    async def _force_flush_all_buffers(self) -> bool:
        flushed = False
        for task_type in list(self.buffers.keys()):
            if self.buffers.get(task_type):
                await self._flush_buffer(task_type)
                flushed = True
        return flushed

    async def _retry_task(self, task: Task) -> None:
        if task.retry_count >= task.max_retries:
            return
        task.retry_count += 1
        task.priority = Priority.MAPPING
        cooldown = 2 ** task.retry_count
        task.cooldown_until = time.time() + cooldown
        delay = max(0.0, task.cooldown_until - time.time())
        self.pending_delayed += 1
        asyncio.create_task(self._enqueue_after_delay(task, delay))

    async def _enqueue_after_delay(self, task: Task, delay: float) -> None:
        await asyncio.sleep(delay)
        self.pending_delayed -= 1
        await self.enqueue(task, bypass_dedup=True)

    def _is_quiescent(self) -> bool:
        return (
            self.queue.empty()
            and self.active_workers == 0
            and self.pending_delayed == 0
            and all(not v for v in self.buffers.values())
        )

    def _in_scope(self, task: Task) -> bool:
        if self.scope is None:
            return True
        target = task.scope_target()
        if target and not self.scope.is_in_scope(target):
            return False
        if self.path_prefix and isinstance(task, EndpointTask):
            return is_under_prefix(task.url, self.path_prefix)
        return True


dispatcher = Dispatcher(scope=None, session_factory=None, target=None)  # type: ignore[arg-type]


def load_handlers() -> None:
    """Import modules for decorator registration."""
    from wotd import modules as _modules  # noqa: F401

    _ = _modules

