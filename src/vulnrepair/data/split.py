"""Dataset splitting helpers."""

import pandas as pd

from data.utils.dataset import split_dataset as _split_dataset

from .models import DatasetSplit


def split_dataset(
    frame: pd.DataFrame,
    cwe_column: str = "cwe",
    test_size: float = 0.2,
    random_state: int = 42,
) -> DatasetSplit:
    """Use the established deterministic, CWE-grouped train/test split."""
    train, test = _split_dataset(
        frame,
        cwe_column=cwe_column,
        test_size=test_size,
        random_state=random_state,
    )
    return DatasetSplit(train=train, test=test)
