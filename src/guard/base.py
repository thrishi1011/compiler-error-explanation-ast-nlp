from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from .models import Finding, InputKind


@dataclass
class GuardContext:
    kind: InputKind
    payload: str
    purpose: str = "analyze"
    meta: dict[str, Any] = field(default_factory=dict)


class GuardAgent(ABC):
    name: str
    handles: set[InputKind]

    @abstractmethod
    def quick_match(self, ctx: GuardContext) -> bool:
        """Cheap signal check. Invariant: must return True whenever analyze could return a finding."""
        pass

    @abstractmethod
    def analyze(self, ctx: GuardContext) -> list[Finding]:
        """Deep analysis returning a list of findings."""
        pass
