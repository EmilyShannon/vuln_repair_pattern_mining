import sys
import csv
import time
from pathlib import Path

try:
    from ..retrieval.retrieve_guidance import retrieve_guidance, process_vulnerable_code
except ImportError:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from retrieval.retrieve_guidance import retrieve_guidance, process_vulnerable_code

from openai import OpenAI
from ollama import Client as OllamaClient
from argparse import ArgumentParser
from typing import List, Optional, Any
import pandas as pd
import json
import os
import random

# Keep repository and installed-package resource paths independent of the caller's cwd.
PATH_TO_PROMPT_TEMPLATES = Path(__file__).resolve().with_name("llm_based_repair_prompt_templates.json")
PATH_TO_ACCEPTED_CWES = Path(__file__).resolve().parents[1] / "data" / "analysis" / "allowed_mappable_cwes.txt"

with open(PATH_TO_PROMPT_TEMPLATES, "r") as f:
    prompt_templates = json.load(f).get("prompt_templates", []) 

with open(PATH_TO_ACCEPTED_CWES, "r") as f:
    allowed_cwes = [line.strip().lower() for line in f.readlines() if line.strip()]
# print("Prompt templates loaded: ", prompt_templates)

def load_client(provider: str, model: Optional[str] = None) -> Any:
    try:
        if provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY") or "test-key"
            return OpenAI(api_key=api_key)
        elif provider == "ollama":
            host = os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434"
            headers = None
            if os.environ.get("OLLAMA_API_KEY"):
                headers = {"Authorization": f"Bearer {os.environ.get('OLLAMA_API_KEY')}"}
            return OllamaClient(host=host, headers=headers)
        else:
            raise ValueError(f"Unsupported provider: {provider}. Supported providers are 'openai' and 'ollama'.")
    except Exception as e:
        raise RuntimeError(f"Failed to load model for provider '{provider}': {str(e)}")


def load_model(provider: str, model: Optional[str] = None) -> Any:
    return load_client(provider, model)


def extract_ollama_response(response: Any) -> str:
    if response is None:
        return ""
    if isinstance(response, str):
        return response.strip()
    if isinstance(response, dict):
        if "response" in response and isinstance(response["response"], str):
            return response["response"].strip()
        if "message" in response:
            return extract_ollama_response(response["message"])
        if "content" in response and isinstance(response["content"], str):
            return response["content"].strip()
        if "content" in response and isinstance(response["content"], list):
            parts = []
            for item in response["content"]:
                if isinstance(item, dict):
                    if isinstance(item.get("text"), str):
                        parts.append(item["text"])
                    elif isinstance(item.get("content"), str):
                        parts.append(item["content"])
            if parts:
                return "\n".join(parts).strip()
    if hasattr(response, "response"):
        return extract_ollama_response(getattr(response, "response"))
    if hasattr(response, "message"):
        return extract_ollama_response(getattr(response, "message"))
    if hasattr(response, "content"):
        return extract_ollama_response(getattr(response, "content"))
    return str(response).strip()


def get_response(provider: str, client: Any, model: str, prompt: str) -> str:
    if provider == "openai":
        response = client.responses.create(
            model=model,
            input=[{"role": "user", "content": prompt}],
        )
        return response.output_text.strip()
    if provider == "ollama":
        try:
            response = client.generate(model=model, prompt=prompt)
        except Exception as exc:
            return f"[ollama error: {exc}]"
        return extract_ollama_response(response)
    raise ValueError(f"Unsupported provider: {provider}")

def load_prompt_template(template_name, prompt_templates):
    try:
        if template_name not in [template.get("id") for template in prompt_templates]:
            raise KeyError(f"Template '{template_name}' not found in prompt templates.")
        else:
            return next((template for template in prompt_templates if template.get("id") == template_name), None)
    except KeyError:
        raise ValueError(f"Template '{template_name}' not found in prompt templates.")


def open_output_writer(output_dir: Path, base_name: str, chunk_idx: int):
    if chunk_idx == 0:
        output_path = output_dir / f"{base_name}.csv"
    else:
        output_path = output_dir / f"{base_name}_continued_{chunk_idx}.csv"

    output_file = open(output_path, "w", encoding="utf-8", newline="")
    writer = csv.writer(output_file)
    writer.writerow([
        "prompt_template",
        # "test_case_idx",
        "cwe_id",
        "commit_id",
        "formulated_prompt",
        "model_response",
        "ground_truth_patch",
        "extracted_patch",
        "patch_match",
        "guidance_used"
    ])
    return output_file, writer, output_path

# def extract_repaired_code(response):
#     pass

# TODO: use cosine similarity to find the most similar example in the guidance tree and return it as an example for few-shot evaluation
def extract_examples(code, tree, num_examples):
    leaves = [node.get("features").get("raw_patch").get("patch") for node in tree.get("nodes").values() if node.get("depth") == 0]
    return random.sample(leaves, min(num_examples, len(leaves)))

def extract_patch_from_response(response_text):
    # Assuming the model's response contains the repaired code in a specific format, e.g., between special markers
    # This function should be adapted based on how the model outputs the repaired code
    start_marker = "<repaired_code>"
    end_marker = "</repaired_code>"
    start_index = response_text.find(start_marker)
    end_index = response_text.rfind(end_marker)
    
    if start_index != -1 and end_index != -1 and start_index < end_index:
        return response_text[start_index + len(start_marker):end_index].strip()
    else:
        # If no markers are found, return the entire response as a fallback
        return response_text.strip()


# TODO implement fuzzy matching 
def eval_patch(model_patch, ground_truth_patch):
    return model_patch.strip() == ground_truth_patch.strip()

def formulate_prompt(template, code, examples: Optional[List[str]] = None, guidance: Optional[str] = None):
    if template is None:
        raise ValueError("Prompt template cannot be None.")
    if template.get("id") == "zero_shot" or template.get("id") == "zero_shot_cot" or template.get("id") == "plan_and_solve" or template.get("id") == "security_cot":
        prompt = template.get("template").format(code=code)
    elif template.get("id") == "few_shot":
        if examples is None or len(examples) == 0:
            raise ValueError("Examples must be provided for few-shot evaluation.")
        # TODO break examples into vul and fixed code and their explanations
        examples_str = "\n".join([f"Example {i+1}:\n{ex}" for i, ex in enumerate(examples)])
        prompt = template.get("template").format(code=code) + examples_str

    if guidance: 
        prompt += f"\n\nIMPORTANT: Use the following guidance derived from similar vulnerabilities:\n{guidance}"

    return prompt

def main():
    argparser = ArgumentParser(description="Evaluate the basic repair capability of the model.")
    argparser.add_argument("--dataset", type=str, choices=["titanvul", "primevul"], required=True, help="Name of the dataset being tested on.")

    # TODO implement it so it can run both
    argparser.add_argument("--test", action="store_true", help="Whether to use the test dataset.")
    argparser.add_argument("--train", action="store_true", help="Whether to use the train dataset.")

    argparser.add_argument("--num_tests", type=int, default=10, help="Number of test cases to evaluate. Default is 10.")
    argparser.add_argument("--provider", type=str, choices=["openai", "ollama"], required=True, help="The provider of the model to be evaluated.")
    argparser.add_argument("--model", type=str, required=True, help="The model to be evaluated.")
    argparser.add_argument("--prompt_template", type=str, required=True, help="The prompt template to be used for evaluation. This should be a key from the llm_based_repair_prompt_templates.json file.")
    argparser.add_argument("--num_examples", type=int, default=0, help="Number of examples to include in the prompt for few-shot evaluation. Default is 3.")
    argparser.add_argument("--tree_path", type=str, required=False, help="Path to the JSON file containing the guidance tree (only required for certain modes).")
    argparser.add_argument("--max_output_mb", type=int, default=10, help="Maximum output file size in megabytes before splitting into continued files.")
    argparser.add_argument(
        "--add_guidance",
        action="store_true",
        help="Whether to retrieve and add guidance"
    )
    argparser.add_argument("--cwe_filter", type=str, required=False, help="Optional filter to evaluate only test cases with a specific CWE ID.")
    args = argparser.parse_args()

    if args.cwe_filter and args.cwe_filter.lower() not in allowed_cwes:
        raise ValueError(f"Unsupported CWE: {args.cwe_filter}")

    client = load_client(args.provider, args.model)
    dataset = args.dataset

    if dataset == "primevul":
        TRAIN_PATH = "/home/emsha/projects/vuln_repair_pattern_mining/data/extracted/primevul_train_paired.jsonl"
        TEST_PATH = "/home/emsha/projects/vuln_repair_pattern_mining/data/extracted/primevul_valid_paired.jsonl"
        vul_func_col = "func"
        commit_id_col = "commit_id"
        # index_col = "idx"
        cwe_col = "cwe"
    elif dataset == "titanvul":
        TRAIN_PATH = "/home/emsha/projects/vuln_repair_pattern_mining/data/extracted/titanvul_train.csv"
        TEST_PATH = "/home/emsha/projects/vuln_repair_pattern_mining/data/extracted/titanvul_test.csv"
        vul_func_col = "func_before"
        cwe_col = "cwe_id"
        commit_id_col = "cve_id"
        # index_col = commit_id_col
    else:
        raise ValueError(f"Unsupported dataset: {dataset}")

    if args.test:
        input_path = TEST_PATH
    elif args.train:
        input_path = TRAIN_PATH
    else:
        raise ValueError("Either --test or --train must be specified.")

    if input_path.endswith("jsonl"):
        with open(input_path, "r") as f:
            test_cases = [json.loads(line) for line in f]

        fixed = [case for case in test_cases if "func" in case and case["func"].strip() != "" and "target" in case and case["target"] == 0]
        test_cases = [case for case in test_cases if "func" in case and case["func"].strip() != "" and "target" in case and case["target"] == 1]
    else:
        df = pd.read_csv(input_path)
        fixed = df.to_dict("records")
        test_cases = df.to_dict("records")

    print(f"Loaded {len(test_cases)} test cases from {input_path}")
    print(any(case.get(cwe_col, "") != "" for case in test_cases))
    print(f"{len([case for case in test_cases if case.get(cwe_col, '') != ''])} test cases have a non-empty CWE ID.")

    test_cases = [case for case in test_cases if (case.get(cwe_col, None) is not None and str(case.get(cwe_col, None)) != "[]" and str(case.get(cwe_col, None)) != "")]

    if args.cwe_filter:
        cwes_to_process = [args.cwe_filter.lower()]
    else:
        cwes_to_process = sorted({str(case[cwe_col]).strip().lower() for case in test_cases})

    if len(test_cases) == 0:
        print(f"No test cases for CWE ID: {args.cwe_filter}, skipping")
        sys.exit(1)

    prompt_templates_list = []
    if args.prompt_template and args.prompt_template.lower() == "all":
        prompt_templates_list = prompt_templates
    else:
        prompt_template = load_prompt_template(args.prompt_template, prompt_templates)
        prompt_templates_list.append(prompt_template)

    guidance_tree = None
    if args.tree_path:
        with open(args.tree_path, "r") as f:
            guidance_tree = json.load(f)

    set_label = "train" if args.train else "test"
    results_dir = Path(f"/home/emsha/projects/vuln_repair_pattern_mining/eval/results/{dataset}/{set_label}/{args.provider}/{args.model.replace(':', '_').replace('/', '_')}/")
    results_dir.mkdir(parents=True, exist_ok=True)

    guidance_label = "guidance" if args.add_guidance else "no_guidance"

    for cwe in cwes_to_process:
        cwe_cases = [case for case in test_cases if cwe in str(case.get(cwe_col, "")).lower()]
        if not cwe_cases:
            continue

        print(f"{cwe}: {len(cwe_cases)} test cases")
        if len(cwe_cases) > args.num_tests:
            random.seed(42)
            cwe_cases = random.sample(cwe_cases, args.num_tests)
        print(f"Reduced to {len(cwe_cases)} test cases")


        output_dir = results_dir / cwe.lower()
        output_dir.mkdir(parents=True, exist_ok=True)
        base_name = f"{guidance_label}_{int(time.time())}"
        chunk_idx = 0
        max_output_bytes = args.max_output_mb * 1024 * 1024
        
        output_file, writer, output_path = open_output_writer(output_dir, base_name, chunk_idx)

        for prompt_template in prompt_templates_list:
            print(f"Evaluating with prompt template: {prompt_template.get('id')}")
            for test_case in cwe_cases:
                time.sleep(1)  # To avoid hitting rate limits
                
                if cwe_col not in test_case:
                    print(f"Skipping test case without CWE: {test_case.get('idx', 'unknown idx')} | project={test_case.get('project')} | target={test_case.get('target')}")
                    continue

                cwe_id = test_case.get(cwe_col, "")
                code = test_case.get(vul_func_col, "")
                # index = test_case[index_col]
                commit_id = test_case.get(commit_id_col, "")
                guidance = None
                examples = None

                print(f"Evaluating test case: {commit_id}")
                
                if args.add_guidance:
                    summary = process_vulnerable_code(client=client, provider=args.provider, model=args.model, code=code, cwe_id=cwe_id, detail_level="high", description=None)
                    guidance = retrieve_guidance(client=client, provider=args.provider, model=args.model, vul_code=code, cwe_id=cwe_id, description=None, tree_json=guidance_tree, cache_path=f"/home/emsha/projects/vuln_repair_pattern_mining/retrieval/caches/retrieval_cache_{cwe_id}")
                if prompt_template.get("id") == "few_shot":
                    examples = extract_examples(code, guidance_tree, args.num_examples)
                formulated_prompt = formulate_prompt(prompt_template, code, examples=examples, guidance=guidance)
                response_text = get_response(args.provider, client, args.model, formulated_prompt)

                # print("======================================================")
                # print(f"Prompt:\n{formulated_prompt}\n")
                # print("======================================================")
                # print(f"Model Response:\n{response_text}\n")
                # print("======================================================")

                ground_truth_patch = next((item for item in fixed if item[commit_id_col] == commit_id), None)
                if ground_truth_patch is None:
                    print(f"No ground truth patch found for test case commit ID: {commit_id}")
                    continue

                patch = extract_patch_from_response(response_text)
                ground_truth_patch_code = ground_truth_patch.get(vul_func_col, "")

                writer.writerow([
                    prompt_template.get("id"),
                    # index,
                    cwe_id,
                    commit_id,
                    formulated_prompt,
                    response_text,
                    ground_truth_patch_code,
                    patch,
                    eval_patch(patch, ground_truth_patch_code),
                    args.add_guidance,
                ])
                output_file.flush()

                if output_file.tell() >= max_output_bytes:
                    print(f"Output file size exceeded {max_output_bytes} bytes, splitting into continued file.")
                    output_file.close()
                    chunk_idx += 1
                    output_file, writer, output_path = open_output_writer(output_dir, base_name, chunk_idx)

        output_file.close()
        print(f"{cwe} done. Saved results to {output_path}")


if __name__ == "__main__":
    main()
