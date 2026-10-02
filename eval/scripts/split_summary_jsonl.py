import argparse
import glob
import os
import pandas as pd
import time 

parser = argparse.ArgumentParser(
    description="Split the latest summaries JSONL into separate files by CWE."
)

parser.add_argument(
    "--provider",
    choices=["ollama", "openai"],
    required=True,
)

parser.add_argument(
    "--model-name",
    required=True,
)

parser.add_argument(
    "--prompt-mode",
    required=True,
    choices=["orig", "hybrid", "semantic"]
)

args = parser.parse_args()

# Directory containing the summaries
input_dir = (
    f"/home/emsha/projects/vuln_repair_pattern_mining/mining/summaries/"
    f"{args.provider}/{args.model_name}/{args.prompt_mode}"
)

# Find the newest JSONL file
jsonl_files = glob.glob(os.path.join(input_dir, "*.jsonl"))
if not jsonl_files:
    raise FileNotFoundError(f"No JSONL files found in {input_dir}")

input_file = max(jsonl_files, key=os.path.getmtime)
print(f"Using input file: {input_file}")


timestamp = int(time.time())
output_dir = (
    "/home/emsha/projects/vuln_repair_pattern_mining/eval/tree_building_inputs/"
    f"{args.provider}/{args.model_name}/{args.prompt_mode}"
)


df = pd.read_json(input_file, lines=True)
print(df.info())

# Remove rows without a CWE
df = df.dropna(subset=["cwe_id"])

# Handle rows with multiple CWEs
df["cwe_id"] = df["cwe_id"].astype(str).str.split(",")
df = df.explode("cwe_id")
df["cwe_id"] = df["cwe_id"].str.strip()

# Write one JSONL per CWE
for cwe_id, group in df.groupby("cwe_id"):
    cwe_output_dir = os.path.join(output_dir, cwe_id.lower())
    os.makedirs(cwe_output_dir, exist_ok=True)

    output_file = os.path.join(
        cwe_output_dir,
        f"input_{timestamp}.jsonl"
    )

    group.to_json(
        output_file,
        orient="records",
        lines=True,
        force_ascii=False,
    )

    print(f"Saved {len(group)} rows -> {output_file}")

print(f"\nCreated {df['cwe_id'].nunique()} files.")