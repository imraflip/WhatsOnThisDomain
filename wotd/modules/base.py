from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.scope import Scope


@dataclass
class ModuleResult:
    """What a module returns after running. Counts and stats land in the scan_run summary."""

    module: str
    stats: dict[str, Any] = field(default_factory=dict)


class Module(ABC):
    """Abstract base class for all recon modules.

    Every module takes a target, a scope, and a DB session, runs its work,
    filters outputs through the scope before writing to the store, and returns
    a ModuleResult with stats for the scan_run summary.
    """

    name: str

    def __init__(self, session: AsyncSession, target: Target, scope: Scope) -> None:
        self.session = session
        self.target = target
        self.scope = scope

    @abstractmethod
    async def run(self) -> ModuleResult:
        """Execute the module's recon work."""
        ...

    def filter_in_scope(self, values: list[str]) -> list[str]:
        """Drop anything the scope object rejects. Every module must use this
        before writing discovered assets to the store."""
        return [v for v in values if self.scope.is_in_scope(v)]
