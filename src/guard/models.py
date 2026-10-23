from __future__ import annotations

from dataclasses import dataclass, asdict, field
from enum import Enum
import uuid


class InputKind(str, Enum):
    USER_SOURCE = "USER_SOURCE"
    COMPILER_OUTPUT = "COMPILER_OUTPUT"
    AI_RESPONSE = "AI_RESPONSE"
    USER_HINT = "USER_HINT"
    PATCH = "PATCH"
    HTTP_REQUEST = "HTTP_REQUEST"
    MODEL_FILE = "MODEL_FILE"
    DATASET_ENTRY = "DATASET_ENTRY"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    agents: list[str] = field(default_factory=list)
    origin: str = "attack"  # "attack" | "vulnerability"
    category: str = ""      # snake_case
    severity: str = "Medium" # "Critical" | "High" | "Medium" | "Low"
    title: str = ""
    description: str = ""
    recommendation: str = ""
    line: int | None = None
    column: int | None = None
    evidence: str = ""      # sanitised plain text
    action: str = "warn"    # "block" | "warn" | "allow"
    confidence: float = 1.0
    blocks_on: set[str] | None = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.blocks_on is not None:
            d["blocks_on"] = sorted(list(self.blocks_on))
        return d


@dataclass
class Verdict:
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_label: str = "Clean"
    action: str = "allow"   # overall "block" | "warn" | "allow"
    blocked: bool = False
    routing: list[dict[str, str]] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0
    kind: InputKind | str = InputKind.USER_SOURCE
    purpose: str = "analyze"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["kind"] = str(self.kind.value if isinstance(self.kind, InputKind) else self.kind)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data
