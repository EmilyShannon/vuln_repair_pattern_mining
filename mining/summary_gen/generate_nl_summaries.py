import json
import re
import os
import argparse
import pandas as pd
import traceback
from time import time
from time import sleep
from openai import OpenAI
from ollama import Client
from ollama._types import ResponseError as OllamaResponseError
from dotenv import load_dotenv

argparse = argparse.ArgumentParser(description="Generate natural language summaries of vulnerability-fixing commits using OpenAI's GPT-5.1")
argparse.add_argument(
    "--input",
    required=True,
    help="Input CSV file containing patches and metadata"
)
argparse.add_argument(
    "--num-variants",
    type=int,
    default=3,
    help="Number of summary variants to generate for each commit"
)

argparse.add_argument(
    "--patch_column",
    default="patch",
    help="Name of the column in the CSV that contains the patch content"
)

argparse.add_argument(
    "--cwe_column",
    default="cwe_id",
    help="Name of the column in the CSV that contains the CWE ID"
)   
argparse.add_argument(  
    "--cve_column",
    default="cve_id",
    help="Name of the column in the CSV that contains the CVE ID"
)   
argparse.add_argument(
    "--commit-message_column",
    default="commit_message",
    help="Name of the column in the CSV that contains the commit message"
)
# argparse.add_argument(
#     "--multi-file_column",
#     default="multi_file",
#     help="Name of the column in the CSV that indicates whether the commit modifies multiple files"
# )

argparse.add_argument(
    "--language_column",
    default="language",
    help="Name of the column in the CSV that indicates the programming language(s) of the patch"
)

argparse.add_argument(
    "--num-summaries",
    type=int,
    default=None,
    help="Total number of commits to generate summaries for (default: all)"
)

argparse.add_argument(
    "--provider-name",
    default="ollama",
    help="Name of the LLM provider to use (e.g., 'openai', 'ollama')"
)

argparse.add_argument(
    "--model-name",
    help="Name of the LLM model to use (e.g., 'gpt-5.1')"
)

argparse.add_argument(
    "--target_language",
    default=None,
    help="Programming language of the patches"
)

argparse.add_argument(
    "--prompt_mode",
    default="orig",
    help="Prompt mode to use for summary generation (e.g., 'orig', 'hybrid', 'semantic')"
)

argparse.add_argument(
    "--resume-from",
    default=None,
    help="Path to a JSONL file containing previously generated summaries to resume from. The script will skip any commits that already have summaries in this file."
)

args = argparse.parse_args()
load_dotenv()
print("OLLAMA_API_KEY exists:", os.environ.get("OLLAMA_API_KEY") is not None)
print("OPENAI_API_KEY exists:", os.environ.get("OPENAI_API_KEY") is not None)
provider = args.provider_name.lower()
if provider == "ollama":
    model_name = args.model_name if args.model_name else "qwen3-coder:30b-cloud"
    client = Client(
        host="https://ollama.com",
        headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
    )

elif provider == "openai":
    model_name = args.model_name if args.model_name else "gpt-5.1"
    client = OpenAI(
        api_key=os.environ.get('OPENAI_API_KEY')
    )

prompt_mode = args.prompt_mode.lower()
if prompt_mode == "orig":
    prompt_base = """Given the following information from a vulnerability-fixing commit, generate 1) a one-sentence summary of the vulnerability being fixed, and 2) a one-sentence summary of the strategy being used to repair the vulnerability.  Do NOT include the patch content in your summaries. Focus on decribing the vulnerabililty itself, and the repair strategy, respecively. Output the summariies like this: "VUL_SUMMARY: <vul_summary>" and "STRATEGY_SUMMARY: <strat_summary>"."""
    # vul_prompt_base = """Given the following information from a vulnerability-fixing commit, generate a one-sentence summary of the vulnerability being fixed.  Do NOT include the patch content in your summary. Focus on describing the vulnerability itself."""

if prompt_mode == "hybrid":
    prompt_base = """Given the following information from a vulnerability-fixing commit, generate 1) a one-sentence summary of the vulnerability being fixed, and 2) a one-sentence summary of the strategy being used to repair the vulnerability.  Do NOT include the patch content in your summaries. Focus on decribing the vulnerabililty itself, and the repair strategy, respecively. Omit implementation-specific details unless they are critical to the vulnerability or repair, e.g.,  if the vulnerability is due to a specific function call or library usage, or the repair is done by adding a function call from a security library. Output the summariies like this: "VUL_SUMMARY: <vul_summary>" and "STRATEGY_SUMMARY: <strat_summary>"."""
    # vul_prompt_base = """Given the following information from a vulnerability-fixing commit, generate a one-sentence summary of the vulnerability being fixed.  Do NOT include the patch content in your summary. Focus on describing the vulnerability itself. Omit implementation-specific details unless they are critical to understanding the vulnerability, e.g., if the vulnerability is due to a specific function call or library usage."""


if prompt_mode == "semantic":
    prompt_base = """
Given the following information from a vulnerability-fixing commit, generate 1) a one-sentence summary of the vulnerability being fixed, and 2) a one-sentence summary of the repair strategy being used to repair the vulnerability. 

Do NOT include the patch content in your summary. Do NOT include implementation details, library or parser names, or code-specific content.

For the vulnerability summary, focus on describing the nature of the vulnerability (e.g., "improper input validation leading to potential remote code execution", "use of unsafe deserialization", "buffer overflow due to unchecked array access").
The vulnerability summary should emphasize the underlying issue rather than specific code constructs, making them generalizable across different contexts.

For the repair summary, focus on the general approach or high-level strategy (e.g., "disabling unsafe features", "replacing with a secure parser", "validating input before processing"). 
The repair summary should emphasize how the vulnerability is addressed rather than what exact code was changed.

Make summaries generalizable so that semantically similar vulnerabilities can be phrased similarly to one another, and similar repair strategies can be phrased similarly to one another.

Output the summariies like this: "VUL_SUMMARY: <vul_summary>" and "STRATEGY_SUMMARY: <strat_summary>".
"""

# vul_summary_prompt_base_orig = """Given the following information from a vulnerability-fixing commit, generate a one-sentence summary of the vulnerability being fixed.  Do NOT include the patch content in your summary. Focus on describing the vulnerability itself."""
# vul_summary_prompt_base_hybrid = """Given the following information from a vulnerability-fixing commit, generate a one-sentence summary of the vulnerability being fixed.  Do NOT include the patch content in your summary. Focus on describing the vulnerability itself. Omit implementation-specific details unless they are critical to understanding the vulnerability, e.g., if the vulnerability is due to a specific function call or library usage."""
    # vul_prompt_base = """Given the following information from a vulnerability-fixing commit, generate a one-sentence summary of the vulnerability being fixed. Focus on describing the nature of the vulnerability (e.g., "improper input validation leading to potential remote code execution", "use of unsafe deserialization", "buffer overflow due to unchecked array access").
    # Do NOT include the patch content in your summary.
    # Do NOT include implementation details, library or parser names, or code-specific content.
    # Summaries should emphasize the underlying issue rather than specific code constructs, making them generalizable across different contexts.
    # """

def build_prompt(patch: str, cwe_id: str, commit_message: str) -> str:
    prompt = f"""{prompt_base} 
        CWE ID:
        {cwe_id}
        COMMIT MESSAGE:
        {commit_message}
        Patch:
        {patch}
    """
    return prompt

def generate_summaries_openai(patch: str, cwe_id: str, commit_message: str, empty_counter, k: int = 3):
    prompt = str(build_prompt(patch, cwe_id, commit_message))
    responses = []
    logs = []
    for i in range(k):
        response = client.responses.create(
            model=model_name,
            input=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        summary = response.output_text.strip()

        if summary == "":
            print(f"WARNING: Received empty summary for CWE ID {cwe_id} on variant {i}. Storing empty string as summary.")
            empty_counter += 1

        else:
            empty_counter = 0
        responses.append(summary)
        logs.append({
            "variant_id": i,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "input_prompt": prompt,
            "summary": summary
        })

        sleep(1)
    return responses, logs, empty_counter

def generate_summaries_ollama(patch: str, cwe_id: str, commit_message: str, empty_counter, k: int = 3):
    prompt = build_prompt(patch, cwe_id, commit_message)

    responses = []
    logs = []
    for i in range(k):
        response = client.generate(
            model=model_name,
            prompt=prompt,
            # temperature=0.0,  # deterministic
            # max_tokens=512
        )

        summary = response['response'].strip()

        if summary == "":
            print(f"WARNING: Received empty summary for CWE ID {cwe_id} on variant {i}. Storing empty string as summary.")
            empty_counter += 1
        else:
            empty_counter = 0

        responses.append(summary)
        logs.append({
            "variant_id": i,
            "input_prompt": prompt,
            "input_tokens": -1,  # Ollama does not provide input token count
            "output_tokens": -1,
            "summary": summary
        })
        sleep(1)
    return responses, logs, empty_counter

# Either the language column will have list of languages or a single language. We will filter the dataframe to only include rows where the language column contains the specified language (e.g., "Java").
def filter_by_language(df, language_column, target_language):
    def language_filter(languages):
        if pd.isna(languages):
            return False
        if isinstance(languages, str) and languages.startswith("[") and languages.endswith("]"):
            # print(f"Parsing languages list: {languages}")
            languages_list = languages.strip("[]").split(",")
            languages_list = [lang.strip().strip("'\"") for lang in languages_list]
            # print(f"Parsed languages: {languages_list}")
            # print("Target language in list? ", target_language in languages_list)
            return target_language in languages_list
        elif isinstance(languages, str):
            return languages.strip() == target_language
        return False

    return df[df[language_column].apply(language_filter)]

current_index = -1
if args.resume_from:
    print(f"Resuming from previously generated summaries in {args.resume_from}...")
    existing_summaries_df = pd.read_json(args.resume_from, lines=True)
    print(f"Loaded {len(existing_summaries_df)/args.num_variants:.2f} existing summaries.")
    print("Existing summaries info:")
    print(f"Found {len(existing_summaries_df)} existing summaries in {args.resume_from}")
    current_index = len(existing_summaries_df) // args.num_variants - 1  # Calculate the index of the last processed commit based on the number of variants
    print(f"Resuming from index {current_index} (skipping {len(existing_summaries_df)} summaries)")
examples_csv_file = args.input
dataset_name = os.path.basename(examples_csv_file).split(".")[0]
df = pd.read_csv(examples_csv_file)
# Every patch appears twice in the dataset, once with a commit message and once without. We will drop the duplicates based on the patch content, keeping the one with the commit message if it exists.
print(f"Number of rows before dropping duplicates: {len(df)}")
df = df.sort_values(by=args.commit_message_column, na_position='last').drop_duplicates(subset=args.patch_column, keep='first').reset_index(drop=True)
print(f"Number of rows after dropping duplicates: {len(df)}")
print(df.info())
# print(df.info())
if args.target_language:
    print(df[args.language_column].apply(lambda x: type(x)).value_counts())
    # Look at the instances of type float - these are likely NaN values. We can fill them with empty lists or empty strings before applying the filter.
    print(f"Number of NaN values in language column before filling: {df[args.language_column].isna().sum()}")
    df[args.language_column] = df[args.language_column].fillna("[]")  # Fill NaN with empty list representation
    df = filter_by_language(df, args.language_column, args.target_language)
    print("numbe rof rows after filtering by language: ", len(df))
    print(df[args.language_column].value_counts())

# if args.single_file_only:
#     df = df[df[args.multi_file_column] == False]
# if args.single_function_only:
#     df = df[df[args.single_function_column] == True]
    
# Sanitize model name for use in filename (replace invalid Windows filename characters)
safe_model_name = model_name.replace(":", "_").replace("/", "_").replace("\\", "_")

output_dir = f"../summaries/{provider}/{safe_model_name}/{prompt_mode}"
# Ensure the output directory exists (create any missing parent directories).
# os.makedirs with exist_ok=True handles the check and recursion in one call.
os.makedirs(output_dir, exist_ok=True)

if args.resume_from:
    output_file = args.resume_from
else:
    output_file = f"{output_dir}/nl_summaries_{int(time())}.jsonl"

start_time = time()
empty_counter = 0
with open(output_file, "a+") as f:
    processed_count = 0
    skipped_count = 0
    if current_index >= 0:
        print(f"Skipping the first {current_index} commits based on existing summaries...")
        df = df.iloc[current_index+1:].reset_index(drop=True)

    max_iters = args.num_summaries if args.num_summaries else len(df) 

    for index, row in df.iterrows():
        if processed_count >= max_iters:
            break
        if empty_counter >= 5:
            break
        patch = row[args.patch_column]
        cwe_id = row[args.cwe_column]
        # cve_id = row[args.cve_column]
        commit_message = row[args.commit_message_column]
        # multi = row[args.multi_file_column]
        
        try:
            if provider == "ollama":
                responses, logs, empty_counter = generate_summaries_ollama(patch, cwe_id, commit_message, empty_counter, k=args.num_variants)
            elif provider == "openai":
                responses, logs, empty_counter = generate_summaries_openai(patch, cwe_id, commit_message, empty_counter, k=args.num_variants)

            for i in range(len(responses)):
                record = {
                    # "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    # "multi_file": multi,
                    "variant_id": logs[i]["variant_id"],
                    "input_tokens": logs[i]["input_tokens"],
                    "output_tokens": logs[i]["output_tokens"],
                    "input_prompt": logs[i]["input_prompt"],
                    "summary": responses[i]
                }
                # print(f"Record's summary : {record.get('summary')}")
                f.write(json.dumps(record) + "\n")
            processed_count += 1
            print(f"Processed {processed_count}/{max_iters} ")
        except (OllamaResponseError, Exception) as e:
            skipped_count += 1
            print(f"ERROR: Skipping row {index}: {str(e)[:200]}")
            continue
        # except Exception as e:
            # print("FULL ERROR:")
            # traceback.print_exc()
            # continue
        sleep(1)  # Sleep between requests to avoid rate limits

        # Compute the running average time per processed example and print an estimate of the remaining time every 10 examples
        if processed_count % 10 == 0 and processed_count > 0:
            elapsed_time = time() - start_time
            avg_time_per_example = elapsed_time / processed_count
            remaining_examples = max_iters - processed_count
            estimated_remaining_time = remaining_examples * avg_time_per_example
            print(f"Elapsed time: {elapsed_time:.2f} seconds, average of {avg_time_per_example:.2f} seconds per processed example, estimated remaining time: {estimated_remaining_time/60:.2f} minutes")
end_time = time()
elapsed_time = end_time - start_time
print(f"\n{'='*60}")
print(f"Summary generation complete!")
print(f"Successfully processed: {processed_count}")
print(f"Skipped due to errors: {skipped_count}")
print(f"Output file: {output_file}")
print(f"Elapsed time: {elapsed_time:.2f} seconds, average of {elapsed_time/processed_count:.2f} seconds per processed example")
print(f"{'='*60}")
