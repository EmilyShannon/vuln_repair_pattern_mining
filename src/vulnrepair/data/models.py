"""Typed data-transfer objects used by the dataset interfaces."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VulnerabilityExample:
    cve_id: str | None = None
    cwe_id: Any = None
    vulnerable_code: str | None = None
    fixed_code: str | None = None
    patch: str | None = None
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityDataset:
    name: str
    examples: list[VulnerabilityExample] = field(default_factory=list)

    def to_frame(self):
        import pandas as pd

        from .loaders import dataset_to_records

        return pd.DataFrame(dataset_to_records(self))


@dataclass
class DatasetSplit:
    train: Any
    test: Any
