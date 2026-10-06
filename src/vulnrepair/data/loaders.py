"""Dataset loading adapters around the repository's established normalizer."""

from pathlib import Path
from typing import Any

import pandas as pd

from data.utils.dataset import load_dataset

from .models import VulnerabilityDataset, VulnerabilityExample


class DatasetLoader:
    """Load a CSV, JSONL, or SQLite dataset into normalized examples."""

    dataset_name = "custom"

    def load(self, path: str | Path, **options: Any) -> VulnerabilityDataset:
        frame = load_dataset(path, **options)
        examples = []
        known_columns = {
            "cve_id",
            "cve",
            "cwe",
            "cwe_id",
            "vul_func",
            "func",
            "func_before",
            "fixed_func",
            "func_after",
            "patch",
            "message",
        }
        for row in frame.to_dict(orient="records"):
            examples.append(
                VulnerabilityExample(
                    cve_id=_first_present(row, "cve_id", "cve"),
                    cwe_id=_first_present(row, "cwe", "cwe_id"),
                    vulnerable_code=_first_present(
                        row, "vul_func", "func", "func_before"
                    ),
                    fixed_code=_first_present(row, "fixed_func", "func_after"),
                    patch=row.get("patch"),
                    message=row.get("message"),
                    metadata={key: value for key, value in row.items() if key not in known_columns},
                )
            )
        return VulnerabilityDataset(name=self.dataset_name, examples=examples)


class CVEFixesLoader(DatasetLoader):
    dataset_name = "cvefixes"


class BigVulLoader(DatasetLoader):
    dataset_name = "bigvul"


class PrimeVulLoader(DatasetLoader):
    dataset_name = "primevul"


class TitanVulLoader(DatasetLoader):
    dataset_name = "titanvul"


def dataset_to_records(dataset: VulnerabilityDataset) -> list[dict[str, Any]]:
    """Convert examples to records without dropping their source metadata."""
    records = []
    for example in dataset.examples:
        record = dict(example.metadata)
        record.update(
            cve_id=example.cve_id,
            cwe=example.cwe_id,
            vul_func=example.vulnerable_code,
            fixed_func=example.fixed_code,
            patch=example.patch,
            message=example.message,
        )
        records.append(record)
    return records


def _first_present(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, dict)):
            return value
        if not pd.isna(value):
            return value
    return None
