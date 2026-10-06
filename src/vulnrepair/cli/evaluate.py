import argparse
import json
from pathlib import Path

import pandas as pd

from vulnrepair.evaluation import Evaluator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculate patch-repair metrics from an existing results CSV."
    )
    parser.add_argument("--input", required=True, help="Repair results CSV to evaluate.")
    parser.add_argument(
        "--output",
        help="Optional path to write the overall metrics as a JSON file.",
    )
    args = parser.parse_args()

    results = pd.read_csv(args.input)
    evaluation = Evaluator().evaluate(results)
    summary = json.dumps(evaluation.overall, indent=2)
    print(summary)

    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary + "\n", encoding="utf-8")

__all__ = ["main"]
