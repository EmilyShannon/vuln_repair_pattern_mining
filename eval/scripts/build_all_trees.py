#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]

TREE_INPUT_ROOT = ROOT_DIR / "eval" / "tree_building_inputs"
TREE_OUTPUT_ROOT = ROOT_DIR / "eval" / "tree_building_outputs"

BUILD_TREE_SCRIPT = (
    ROOT_DIR / "mining" / "trees" / "utils" / "build_tree.py"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build trees from the latest CWE-specific summary inputs"
    )

    parser.add_argument(
        "--provider",
        default="ollama",
        choices=["ollama", "openai"],
        help="Provider name",
    )

    parser.add_argument(
        "--model-name",
        default="qwen3-coder_480b-cloud",
        help="Model name",
    )

    parser.add_argument(
        "--prompt-mode",
        default="orig",
        choices=["orig", "hybrid", "semantic"],
        help="Prompt mode",
    )

    return parser.parse_args()


def find_latest_input_file(cwe_dir: Path) -> Path:
    """
    Find the newest input_<timestamp>.jsonl file in a CWE directory.
    """
    candidate_files = [
        path
        for path in cwe_dir.iterdir()
        if (
            path.is_file()
            and path.name.startswith("input_")
            and path.suffix == ".jsonl"
        )
    ]

    if not candidate_files:
        raise FileNotFoundError(
            f"No input JSONL files found in {cwe_dir}"
        )

    # Use filename timestamp rather than filesystem timestamp
    # since the naming convention is controlled.
    return max(
        candidate_files,
        key=lambda path: int(path.stem.split("_")[1]),
    )


def run_build_tree(
    input_jsonl: Path,
    output_dir: Path,
    cwe_id: str,
    provider: str,
    model_name: str,
) -> None:
    """
    Run the tree building script on one CWE input file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(BUILD_TREE_SCRIPT),
        "--input",
        str(input_jsonl),
        "--cwe-id",
        cwe_id,
        "--output-dir",
        str(output_dir),
        "--provider",
        provider,
        "--model",
        model_name,
    ]

    print(f"Running: {' '.join(command)}")

    subprocess.run(
        command,
        check=True,
    )


def main() -> None:
    args = parse_args()
    safe_mode_name =  args.model_name.replace(":", "_").replace("/", "_")
    input_root = (
        TREE_INPUT_ROOT
        / args.provider
        / safe_mode_name
        / args.prompt_mode
    )

    output_root = (
        TREE_OUTPUT_ROOT
        / args.provider
        / safe_mode_name
        / args.prompt_mode
    )

    if not input_root.exists():
        raise FileNotFoundError(
            f"Input directory does not exist: {input_root}"
        )

    cwe_dirs = sorted(
        [
            path
            for path in input_root.iterdir()
            if path.is_dir()
        ]
    )

    if not cwe_dirs:
        raise FileNotFoundError(
            f"No CWE directories found in {input_root}"
        )

    print(f"Found {len(cwe_dirs)} CWE directories")
    print(f"Input root: {input_root}")
    print(f"Output root: {output_root}")


    # counter = 0
    # max_cnt = 3
    for cwe_dir in cwe_dirs:
        # if counter < max_cnt:
        cwe_id = cwe_dir.name
    
        input_file = find_latest_input_file(cwe_dir)

        output_dir = output_root / cwe_id

        if output_dir.exists():
            print(f"Output directory already exists: {output_dir}")
            continue

        print("\n" + "=" * 80)
        print(f"CWE: {cwe_id}")
        print(f"Input: {input_file}")
        print(f"Output: {output_dir}")
        print("=" * 80)

        run_build_tree(
            input_file,
            output_dir,
            cwe_id,
            args.provider,
            args.model_name
        )
        # counter += 1


    print("\nFinished building trees.")


if __name__ == "__main__":
    main()