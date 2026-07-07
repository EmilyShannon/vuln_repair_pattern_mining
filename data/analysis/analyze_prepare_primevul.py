from pathlib import Path
import argparse
import json
import pandas as pd
import matplotlib.pyplot as plt


REQUIRED_COLUMNS = {"patch", "message", "vul_func", "fixed_func", "size", "cwe"}


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze PrimeVul-style datasets")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input JSONL file with the same structure as the PrimeVul training data.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to save the cleaned dataset.",
    )
    parser.add_argument(
        "--plots-dir",
        default="/home/emsha/projects/vuln_repair_pattern_mining/data/analysis/plots",
        help="Directory where analysis plots will be saved.",
    )
    return parser.parse_args()


def load_dataset(input_path):
    input_path = Path(input_path).expanduser()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if input_path.suffix.lower() != ".jsonl":
        raise ValueError(f"Expected a .jsonl input file, got {input_path.suffix or 'no suffix'}")

    records = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number} of {input_path}: {exc}") from exc
            records.append(record)

    df = pd.DataFrame(records)

    if "func" in df.columns and "vul_func" not in df.columns:
        df["vul_func"] = df["func"]
    if "func" in df.columns and "fixed_func" not in df.columns:
        df["fixed_func"] = df["func"]
    if "message" not in df.columns and "commit_message" in df.columns:
        df["message"] = df["commit_message"]
    if "size" not in df.columns:
        df["size"] = pd.NA
    if "patch" not in df.columns and "vul_func" in df.columns and "fixed_func" in df.columns:
        df["patch"] = df.apply(lambda row: f"---\n+++\n{row['vul_func']}\n{row['fixed_func']}", axis=1)

    missing_columns = REQUIRED_COLUMNS.difference(df.columns)
    if missing_columns:
        raise ValueError(f"Input file is missing required columns: {sorted(missing_columns)}")

    print(df.info())
    print(f"Number of unique values in 'patch' column: {df['patch'].nunique()}")
    print(f"Number of missing values in 'message' column: {df['message'].isna().sum()}")
    print(f"Number of missing values in 'vul_func' column: {df['vul_func'].isna().sum()}")
    print(f"Number of missing values in 'fixed_func' column: {df['fixed_func'].isna().sum()}")
    print(f"Number of missing values in 'size' column: {df['size'].isna().sum()}")
    return df


def summarize_cwe_distribution(df):
    cwe_counts_no_mod = df['cwe'].value_counts()
    print(cwe_counts_no_mod)
    missing_cwe_count = df['cwe'].isna().sum()
    print(f"Number of missing values in 'cwe' column: {missing_cwe_count}")
    print("Dropping rows with missing 'cwe' values")
    df = df.dropna(subset=['cwe']).copy()
    print(f"Number of rows after dropping missing 'cwe' values: {len(df)}")

    cwe_counts = {}
    for cwe in df['cwe']:
        if cwe is None:
            cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
            continue

        if isinstance(cwe, (list, tuple, set)):
            cwes_list = [str(entry).strip().strip("'").strip('"') for entry in cwe if str(entry).strip()]
            if not cwes_list:
                cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
                continue
            for entry in cwes_list:
                cwe_counts[entry] = cwe_counts.get(entry, 0) + 1
            continue

        if isinstance(cwe, str):
            if cwe.startswith('[') and cwe.endswith(']'):
                cwes_list = [entry.strip().strip("'").strip('"') for entry in cwe.replace('[', '').replace(']', '').split(', ') if entry.strip()]
                if not cwes_list:
                    cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
                    continue
                for entry in cwes_list:
                    cwe_counts[entry] = cwe_counts.get(entry, 0) + 1
            else:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        else:
            if pd.isna(cwe):
                cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
            else:
                cwe_counts[str(cwe)] = cwe_counts.get(str(cwe), 0) + 1

    print("Dropping rows with missing cwe values after counting cwe distribution from lists")
    df = df[df['cwe'] != 'CWE-NoInfo']
    print(f"Number of rows after dropping 'CWE-NoInfo' values: {len(df)}")
    return df, cwe_counts


def save_cleaned_dataset(df, output_path):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Saved cleaned dataset to {output_path}")


def plot_cwe_distribution(cwe_counts, output_path):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(12, 6))
    cwe_series = pd.Series(cwe_counts).sort_values(ascending=False)
    print(cwe_series)
    cwe_series.head(25).plot(kind='bar')
    plt.xlabel('CWE')
    plt.xticks(rotation=30, ha='right')
    plt.ylabel('Count')
    plt.title('Distribution of CWEs in PrimeVul Training Dataset')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_code_size_distribution(df, output_path, max_lines):
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    size_series = pd.to_numeric(df['size'], errors='coerce').dropna()
    code_size_counts = size_series.value_counts().sort_index()
    code_size_counts = code_size_counts[code_size_counts.index <= max_lines]

    plt.figure(figsize=(10, 6))
    plt.bar(code_size_counts.index, code_size_counts.values, edgecolor='black')
    plt.xlabel('Code Size (Number of Lines)')
    plt.ylabel('Frequency')
    plt.title(f'Distribution of Vulnerable Function Sizes (Sizes <= {max_lines})')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def analyze_dataset(input_path, output_path, plots_dir):
    df = load_dataset(input_path)
    df, cwe_counts = summarize_cwe_distribution(df)
    save_cleaned_dataset(df, output_path)

    plots_dir = Path(plots_dir).expanduser()
    plots_dir.mkdir(parents=True, exist_ok=True)

    plot_cwe_distribution(cwe_counts, plots_dir / 'primevul_train_cwe_distribution.png')
    plot_code_size_distribution(df, plots_dir / 'primevul_train_vul_func_size_distribution.png', max_lines=1000)
    plot_code_size_distribution(df, plots_dir / 'primevul_train_vul_func_size_distribution_30.png', max_lines=30)

    return df


def main():
    args = parse_args()
    analyze_dataset(args.input, args.output, args.plots_dir)


if __name__ == '__main__':
    main()

