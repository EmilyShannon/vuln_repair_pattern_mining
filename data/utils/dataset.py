import ast
import difflib
import json
import sqlite3
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def infer_input_format(input_path, input_format="auto"):
    input_path = Path(input_path).expanduser()
    if input_format and input_format.lower() != "auto":
        normalized_format = input_format.lower()
        if normalized_format not in {"jsonl", "csv", "sqlite"}:
            raise ValueError(f"Unsupported input format: {input_format}")
        return normalized_format

    suffix = input_path.suffix.lower()
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix in {".db", ".sqlite", ".sqlite3"}:
        return "sqlite"
    raise ValueError(f"Unsupported input file extension: {suffix or 'no suffix'}")


def build_patch_from_diff(vul_func, fixed_func):
    before_lines = [] if _is_missing(vul_func) else str(vul_func).splitlines()
    after_lines = [] if _is_missing(fixed_func) else str(fixed_func).splitlines()
    diff_lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile="before",
        tofile="after",
        lineterm="",
    )
    return "\n".join(diff_lines)


def _is_missing(value):
    if value is None:
        return True
    if isinstance(value, (list, tuple, set, dict)):
        return False
    return bool(pd.isna(value))


def _read_jsonl(input_path):
    records = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {input_path}: {exc}"
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected a JSON object on line {line_number} of {input_path}"
                )
            records.append(record)
    return pd.DataFrame.from_records(records)


def _read_sqlite(input_path, table):
    if not table:
        raise ValueError("A table name is required when loading a SQLite database")

    with sqlite3.connect(input_path) as connection:
        available_tables = pd.read_sql_query(
            "SELECT name FROM sqlite_master WHERE type = 'table'", connection
        )["name"].tolist()
        if table not in available_tables:
            raise ValueError(
                f"Table {table!r} not found in {input_path}; "
                f"available tables: {available_tables}"
            )
        quoted_table = '"' + table.replace('"', '""') + '"'
        return pd.read_sql_query(f"SELECT * FROM {quoted_table}", connection)


def _copy_column(df, target, candidates):
    source = next((column for column in candidates if column in df.columns), None)
    if source is not None and source != target:
        df[target] = df[source]


def load_dataset(
    input_path,
    patch_column="patch",
    message_column="message",
    vul_func_column="vul_func",
    fixed_func_column="fixed_func",
    size_column="size",
    cwe_column="cwe",
    input_format="auto",
    table=None,
):
    input_path = Path(input_path).expanduser()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    source_format = infer_input_format(input_path, input_format)
    if source_format == "jsonl":
        df = _read_jsonl(input_path)
    elif source_format == "csv":
        df = pd.read_csv(input_path)
    else:
        df = _read_sqlite(input_path, table)

    _copy_column(df, "patch", (patch_column, "patch"))
    _copy_column(df, "message", (message_column, "message", "commit_message"))
    _copy_column(
        df,
        "vul_func",
        (vul_func_column, "vul_func", "func_before", "func"),
    )
    _copy_column(
        df,
        "fixed_func",
        (fixed_func_column, "fixed_func", "func_after"),
    )
    _copy_column(df, "size", (size_column, "size"))
    _copy_column(df, "cwe", (cwe_column, "cwe", "cwe_id"))

    for optional_column in ("message", "vul_func", "fixed_func"):
        if optional_column not in df.columns:
            df[optional_column] = pd.NA

    if "size" not in df.columns:
        if df["vul_func"].notna().any():
            df["size"] = df["vul_func"].map(
                lambda code: len(str(code).splitlines()) if not _is_missing(code) else pd.NA
            )
        else:
            df["size"] = pd.NA

    if "patch" not in df.columns:
        if not df["vul_func"].notna().any() or not df["fixed_func"].notna().any():
            raise ValueError(
                "Input must contain a patch column or both vulnerable and fixed "
                "function columns"
            )
        df["patch"] = df.apply(
            lambda row: build_patch_from_diff(row["vul_func"], row["fixed_func"]),
            axis=1,
        )

    if "cwe" not in df.columns:
        raise ValueError(
            f"Input file is missing the CWE column {cwe_column!r} "
            "(also checked for 'cwe' and 'cwe_id')"
        )

    return df


def _cwe_labels(value):
    if _is_missing(value):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(label).strip().strip("'\"") for label in value if str(label).strip()]

    value = str(value).strip()
    if not value or value.lower() in {"none", "nan", "null", "cwe-noinfo"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            parsed = value[1:-1].split(",")
        if isinstance(parsed, (list, tuple, set)):
            return [
                str(label).strip().strip("'\"")
                for label in parsed
                if str(label).strip()
            ]
        return []
    return [label.strip().strip("'\"") for label in value.split(",") if label.strip()]


def summarize_cwe_distribution(df, cwe_column="cwe"):
    if cwe_column not in df.columns:
        raise ValueError(f"DataFrame is missing the CWE column {cwe_column!r}")
    labels_by_row = df[cwe_column].map(_cwe_labels)
    counts = Counter(label for labels in labels_by_row for label in labels)
    filtered_df = df.loc[labels_by_row.map(bool)].copy()
    return filtered_df, dict(counts)


def save_cleaned_dataset(df, output_path):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Saved cleaned dataset to {output_path}")


def split_dataset(df, cwe_column="cwe", test_size=0.2, random_state=42):
    if not 0 < test_size < 1:
        raise ValueError("test_size must be greater than 0 and less than 1")
    if cwe_column not in df.columns:
        raise ValueError(f"DataFrame is missing the CWE column {cwe_column!r}")

    train_parts = []
    test_parts = []
    cwe_groups = df[cwe_column].map(lambda value: tuple(_cwe_labels(value)))
    for _, group in df.groupby(cwe_groups, dropna=False, sort=True):
        shuffled = group.sample(frac=1, random_state=random_state)
        if len(shuffled) == 1:
            train_parts.append(shuffled)
            continue
        test_count = min(len(shuffled) - 1, max(1, round(len(shuffled) * test_size)))
        test_parts.append(shuffled.iloc[:test_count])
        train_parts.append(shuffled.iloc[test_count:])

    train_df = pd.concat(train_parts) if train_parts else df.iloc[0:0]
    test_df = pd.concat(test_parts) if test_parts else df.iloc[0:0]
    train_df = train_df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    test_df = test_df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    return train_df, test_df


def plot_cwe_distribution(
    cwe_counts,
    output_path,
    title="CWE Distribution",
):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(12, 6))
    pd.Series(cwe_counts).sort_values(ascending=False).head(25).plot(kind="bar")
    plt.xlabel("CWE")
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Count")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_code_size_distribution(df, output_path, max_lines, size_column="size"):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    size_series = pd.to_numeric(df[size_column], errors="coerce").dropna()
    code_size_counts = size_series.value_counts().sort_index()
    code_size_counts = code_size_counts[code_size_counts.index <= max_lines]

    plt.figure(figsize=(10, 6))
    plt.bar(code_size_counts.index, code_size_counts.values, edgecolor="black")
    plt.xlabel("Code Size (Number of Lines)")
    plt.ylabel("Frequency")
    plt.title(f"Function Size Distribution (Sizes <= {max_lines})")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def analyze_dataset(
    input_path,
    output_path,
    plots_dir,
    patch_column="patch",
    message_column="message",
    vul_func_column="vul_func",
    fixed_func_column="fixed_func",
    size_column="size",
    cwe_column="cwe",
    input_format="auto",
    dataset_name=None,
    test_size=0.2,
    random_state=42,
    table=None,
):
    if not 0 < test_size < 1:
        raise ValueError("test_size must be greater than 0 and less than 1")
    dataset_name = dataset_name or Path(input_path).stem
    if Path(dataset_name).name != dataset_name or dataset_name in {".", ".."}:
        raise ValueError("dataset_name must be a file-name-safe name without directories")

    output_path = Path(output_path).expanduser()
    train_path = output_path.parent / f"{dataset_name}_train.csv"
    test_path = output_path.parent / f"{dataset_name}_test.csv"
    if output_path in {train_path, test_path}:
        raise ValueError("The cleaned output path must not overwrite a train/test split")

    df = load_dataset(
        input_path,
        patch_column=patch_column,
        message_column=message_column,
        vul_func_column=vul_func_column,
        fixed_func_column=fixed_func_column,
        size_column=size_column,
        cwe_column=cwe_column,
        input_format=input_format,
        table=table,
    )
    print(f"Loaded {len(df)} rows")
    df.info()
    print(f"Unique patches: {df['patch'].nunique()}")
    for column in ("message", "vul_func", "fixed_func", "size", "cwe"):
        print(f"Missing values in '{column}': {df[column].isna().sum()}")

    df, cwe_counts = summarize_cwe_distribution(df, cwe_column="cwe")
    print(f"Rows with usable CWE labels: {len(df)}")
    print("CWE counts:")
    print(pd.Series(cwe_counts).sort_values(ascending=False))
    save_cleaned_dataset(df, output_path)

    train_df, test_df = split_dataset(
        df,
        cwe_column="cwe",
        test_size=test_size,
        random_state=random_state,
    )
    save_cleaned_dataset(train_df, train_path)
    save_cleaned_dataset(test_df, test_path)
    print(f"Train rows: {len(train_df)}; test rows: {len(test_df)}")

    plots_dir = Path(plots_dir).expanduser()
    plots_dir.mkdir(parents=True, exist_ok=True)
    plot_cwe_distribution(
        cwe_counts,
        plots_dir / f"{dataset_name}_cwe_distribution.png",
        title=f"CWE Distribution for {dataset_name}",
    )
    plot_code_size_distribution(
        df,
        plots_dir / f"{dataset_name}_vul_func_size_distribution.png",
        max_lines=1000,
    )
    plot_code_size_distribution(
        df,
        plots_dir / f"{dataset_name}_vul_func_size_distribution_30.png",
        max_lines=30,
    )
    return df
