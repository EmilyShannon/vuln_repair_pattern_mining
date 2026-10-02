import argparse
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from data.utils.dataset import analyze_dataset


def parse_args():
    parser = argparse.ArgumentParser(
        description="Load, prepare, split, and analyze a vulnerability dataset"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a CSV, JSONL, or SQLite dataset.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to save the complete cleaned dataset as CSV.",
    )
    parser.add_argument(
        "--plots-dir",
        help="Directory for analysis plots (defaults to a plots folder beside --output).",
    )
    parser.add_argument(
        "--input-format",
        default="auto",
        choices=["auto", "jsonl", "csv", "sqlite"],
        help="Explicitly set the input format when it cannot be inferred from the extension.",
    )
    parser.add_argument(
        "--table",
        help="Table to load when --input is a SQLite database.",
    )
    parser.add_argument(
        "--patch-column",
        default="patch",
        help="Column name containing the patch content.",
    )
    parser.add_argument(
        "--message-column",
        default="message",
        help="Column name containing the commit/message text.",
    )
    parser.add_argument(
        "--vul-func-column",
        default="vul_func",
        help="Column name containing the vulnerable function content.",
    )
    parser.add_argument(
        "--fixed-func-column",
        default="fixed_func",
        help="Column name containing the fixed function content.",
    )
    parser.add_argument(
        "--size-column",
        default="size",
        help="Column name containing the function size information.",
    )
    parser.add_argument(
        "--cwe-column",
        default="cwe",
        help="Column name containing CWE information.",
    )
    parser.add_argument(
        "--dataset-name",
        help="Name used for plot and train/test split files (defaults to the input filename).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction assigned to test within each CWE group (default: 0.2).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed used when shuffling train/test data (default: 42).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    plots_dir = args.plots_dir or str(Path(args.output).expanduser().parent / "plots")
    analyze_dataset(
        args.input,
        args.output,
        plots_dir,
        patch_column=args.patch_column,
        message_column=args.message_column,
        vul_func_column=args.vul_func_column,
        fixed_func_column=args.fixed_func_column,
        size_column=args.size_column,
        cwe_column=args.cwe_column,
        input_format=args.input_format,
        dataset_name=args.dataset_name,
        test_size=args.test_size,
        random_state=args.random_state,
        table=args.table,
    )


if __name__ == '__main__':
    main()
