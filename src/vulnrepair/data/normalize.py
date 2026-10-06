"""Convenience functions for the existing dataset normalization pipeline."""

from pathlib import Path
from typing import Any

import pandas as pd

from data.utils.dataset import load_dataset


def normalize_dataset(path: str | Path, **options: Any) -> pd.DataFrame:
    """Read and normalize a dataset using the existing CSV/JSONL/SQLite rules."""
    return load_dataset(path, **options)

