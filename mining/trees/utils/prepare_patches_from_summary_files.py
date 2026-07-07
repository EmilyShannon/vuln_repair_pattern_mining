# Take a csv file with columns cwe_id,cluster_label,summary,input_prompt,original_index, and create a json file with the same structure as the one used in build_tree.py, but with "patches" instead of "steps". The "patches" field should be a list of dictionaries, each containing the fields "summary", "input_prompt", and "original_index". The output json file should be saved to the same directory as the input csv file, with the same name but with a .json extension.

import csv
import json
import os
import argparse

def extract_patch_from_prompt(input_prompt):
    # Assuming the patch comes after "Patch" and is the last part of the prompt
    if "Patch" in input_prompt:
        return input_prompt.split("Patch")[-1].strip()
    return ""

def prepare_patches_from_summary_files(input_csv):
    patches = []
    
    with open(input_csv, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            patch = {
                "patch_id": row['original_index'],
                "cwe_id": row["cwe_id"],
                "summary": row["summary"],
                "patch": extract_patch_from_prompt(row["input_prompt"]),
            }
            patches.append(patch)
    
    output_data = {
        "patches": patches
    }
    
    output_json_path = os.path.splitext(input_csv)[0] + '.json'
    with open(output_json_path, mode='w') as json_file:
        json.dump(output_data, json_file, indent=4)
    
    print(f"Prepared patches saved to {output_json_path}")


# csv_path = "/home/emsha/projects/vuln_repair_pattern_mining/mining/cluster/clusters/ollama/qwen3-coder_480b-cloud/orig/fix/cluster_summaries_CWE-120_1778266389.csv"
csv_path = "/home/emsha/projects/vuln_repair_pattern_mining/mining/cluster/clusters/ollama/qwen3-coder_480b-cloud/orig/vul/cluster_summaries_CWE-125_1778265969.csv"
prepare_patches_from_summary_files(csv_path)