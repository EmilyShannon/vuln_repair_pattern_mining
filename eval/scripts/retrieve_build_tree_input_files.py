import argparse
import os 
import pandas as pd
import shutil

parser = argparse.ArgumentParser(description="Retrieve summary files for a given configuration based o na predefined folder structure")
parser.add_argument("--provider", choices=["ollama", "openai"], type=str, required=True, help="The model provider name")
parser.add_argument("--model-name", choices=["qwen3-coder_480b-cloud", "gpt-5.1"], type=str, required=True, help="The model name")
parser.add_argument("--prompt-mode", type=str, choices=["orig", "hybrid", "semantic"], default="orig", help="The prompt mode")
parser.add_argument("--summary-type", type=str, choices=["vul", "fix"], default="vul", help="The summary type (if it's summarizing the vulnerability or the repair)")
parser.add_argument("--cwe-id", type=str, required=False, help="The CWE identifier. If not provided, all CWEs will be processed.")

args = parser.parse_args()

TARGET_DIR = "/home/emsha/projects/vuln_repair_pattern_mining/eval/tree_building_inputs"
os.makedirs(TARGET_DIR, exist_ok=True)
MAPPABLE_CWES_PATH = "/home/emsha/projects/vuln_repair_pattern_mining/data/analysis/mappable_cwes.csv"

mappable_cwes_df = pd.read_csv(MAPPABLE_CWES_PATH)
mappable_cwes = mappable_cwes_df[mappable_cwes_df['Mapping_Status'] == "Allowed"]['CWE_ID'].tolist()
# print(f"Mappable CWEs: {mappable_cwes}")
mappable_cwes = ["cwe-" + str(cwe) for cwe in mappable_cwes]
# print(f"Mappable CWEs: {mappable_cwes}")    

if args.cwe_id is not None:
    TARGET_DIR = os.path.join(TARGET_DIR, f"{args.cwe_id}")

if not os.path.exists(TARGET_DIR):
    os.makedirs(TARGET_DIR)

else: 
    # Clear the target directory if it already exists
    for f in os.listdir(TARGET_DIR):
        file_path = os.path.join(TARGET_DIR, f)
        if os.path.isfile(file_path):
            os.remove(file_path)

base_path = os.path.join("../../clusters", args.provider, args.model_name, args.prompt_mode, args.summary_type)
print(f"Base path: {base_path}")
if os.path.exists(base_path):
    print(f"Base path {base_path} exists.")
    if args.cwe_id is not None:
        print(f"Retrieving files for CWE {args.cwe_id}")
        # path = os.path.join(base_path, f"cluster_summaries_{args.cwe_id}_*.csv")
        # The file name will have the format cluster_summaries_<CWE-ID>_<timestamp>.csv, so we can filter the files based on that
        files = [f for f in os.listdir(base_path) if f.lower().startswith(f"cluster_summaries_{args.cwe_id}_") and f.endswith(".csv")]
        # Find the most recent one based on the last modified time
        if files:
            latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(base_path, f)))
            print(f"Latest file for CWE {args.cwe_id}: {latest_file}")
            # Copy them into /home/emsha/projects/vuln_repair_pattern_mining/eval/tree_building_inputs
            shutil.copy(os.path.join(base_path, latest_file), f"{TARGET_DIR}/{latest_file}")

    else:
        # List all CSV files in the base path
        csv_files = [f for f in os.listdir(base_path) if f.lower().startswith(f"cluster_summaries_cwe-") and f.endswith(".csv") and f.split("_")[2].lower() in mappable_cwes]

        # Go through each of the cwes and find the latest file for each
        latest_files = []
        for cwe in mappable_cwes:
            cwe_files = [f for f in csv_files if f.lower().startswith(f"cluster_summaries_{cwe}_")]
            if len(cwe_files) > 0:
                latest_file_for_cwe = max(cwe_files, key=lambda f: os.path.getmtime(os.path.join(base_path, f)))
                latest_files.append(latest_file_for_cwe)
                print(f"Latest file for {cwe}: {latest_file_for_cwe}")
                if not os.path.exists(f"{TARGET_DIR}/{cwe}"):
                    os.makedirs(f"{TARGET_DIR}/{cwe}")
                print(f"Copying {latest_file_for_cwe} to {TARGET_DIR}/{cwe}")
                shutil.copy(os.path.join(base_path, latest_file_for_cwe), f"{TARGET_DIR}/{cwe}")
            # else:
            #     print(f"No files found for {cwe}")
        print(f"Found CSV files: {csv_files}")

    
    
else:
    print(f"Base path {base_path} does not exist.")
    exit(1)