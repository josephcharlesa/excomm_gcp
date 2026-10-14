"""Normalized findings shared with the cloud audit reporting layer."""
from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = {"critical", "high", "medium", "low", "info"}

@dataclass
class FindingRecord:
    category: str
    severity: str
    resource_id: str
    current_monthly_cost: float | None
    estimated_monthly_savings: float | None
    recommendation: str
    evidence: str = ""
    source: str = "gcp"
    currency: str = "USD"
    confidence: str = "medium"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        for key in ("current_monthly_cost", "estimated_monthly_savings"):
            value = getattr(self, key)
            if value is not None and value < 0:
                raise ValueError(f"{key} cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
