import pytest

from wotd.tools import ToolNotFoundError, ToolTimeoutError, find_binary, run_tool


def test_find_binary_exists() -> None:
    path = find_binary("sh")
    assert path.endswith("/sh")


def test_find_binary_missing() -> None:
    with pytest.raises(ToolNotFoundError):
        find_binary("definitely-not-a-real-binary-xyz-123")


async def test_run_tool_captures_stdout() -> None:
    result = await run_tool("echo", ["hello world"])
    assert result.ok
    assert result.stdout.strip() == "hello world"


async def test_run_tool_captures_nonzero_exit() -> None:
    result = await run_tool("sh", ["-c", "exit 7"])
    assert not result.ok
    assert result.returncode == 7


async def test_run_tool_stdin() -> None:
    result = await run_tool("cat", [], stdin_data="piped input\n")
    assert result.ok
    assert result.stdout.strip() == "piped input"


async def test_run_tool_missing_binary() -> None:
    with pytest.raises(ToolNotFoundError):
        await run_tool("definitely-not-a-real-binary-xyz-123", [])


async def test_run_tool_timeout() -> None:
    with pytest.raises(ToolTimeoutError):
        await run_tool("sleep", ["5"], timeout=0.2)
