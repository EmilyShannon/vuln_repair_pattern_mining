"""Dataset filtering helpers."""

from collections.abc import Iterable
from typing import Any

import pandas as pd

from data.utils.dataset import _cwe_labels


def filter_by_cwe(
    frame: pd.DataFrame, cwes: Iterable[str], cwe_column: str = "cwe"
) -> pd.DataFrame:
    """Return rows whose CWE column contains at least one requested CWE label."""
    if cwe_column not in frame.columns:
        raise ValueError(f"DataFrame is missing the CWE column {cwe_column!r}")
    wanted = {str(cwe).strip().lower() for cwe in cwes}

    def matches(value: Any) -> bool:
        return any(label.strip().lower() in wanted for label in _cwe_labels(value))

    return frame.loc[frame[cwe_column].map(matches)].copy()
