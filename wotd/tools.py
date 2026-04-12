"""Async subprocess wrapper for shelling out to external Go tools."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass


class ToolNotFoundError(RuntimeError):
    """Raised when an external tool binary cannot be found on PATH."""


class ToolTimeoutError(RuntimeError):
    """Raised when an external tool exceeds its timeout."""


@dataclass
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def find_binary(name: str) -> str:
    """Resolve a binary name to an absolute path. Raises ToolNotFoundError if missing."""
    path = shutil.which(name)
    if path is None:
        raise ToolNotFoundError(
            f"required tool '{name}' not found on PATH. "
            f"see TECHSTACK.md for install instructions."
        )
    return path


async def run_tool(
    binary: str,
    args: list[str],
    stdin_data: str | None = None,
    timeout: float | None = 300.0,
    check_exists: bool = True,
) -> ToolResult:
    """Run an external tool and capture its output.

    If check_exists is True (default), verify the binary exists on PATH first.
    The timeout is in seconds; None disables it.
    """
    if check_exists:
        binary = find_binary(binary)

    command = [binary, *args]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
    except TimeoutError as e:
        process.kill()
        await process.wait()
        raise ToolTimeoutError(
            f"tool '{binary}' exceeded {timeout}s timeout"
        ) from e

    return ToolResult(
        command=command,
        returncode=process.returncode or 0,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
    )
