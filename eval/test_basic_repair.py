print(__name__)
print(__package__)
from ..retrieval import retrieve_guidance
from openai import OpenAI
from ollama import Client
from argparse import ArgumentParser
from typing import List, Optional
import json
import os
import random

PATH_TO_PROMPT_TEMPLATES = "/home/emsha/projects/vuln_repair_pattern_mining/eval/llm_based_repair_prompt_templates.json"

with open(PATH_TO_PROMPT_TEMPLATES, "r") as f:
    prompt_templates = json.load(f).get("prompt_templates", []) 

# print("Prompt templates loaded: ", prompt_templates)

def load_model(provider, model):
    try:
        if provider == "openai":
            return OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
        elif provider == "ollama":
            return Client(
                    host="https://ollama.com",
                    headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
                )
        else:
            raise ValueError(f"Unsupported provider: {provider}. Supported providers are 'openai' and 'ollama'.")
    except Exception as e:
        raise RuntimeError(f"Failed to load model for provider '{provider}': {str(e)}")

def load_prompt_template(template_name, prompt_templates):
    try:
        if template_name not in [template.get("id") for template in prompt_templates]:
            raise KeyError(f"Template '{template_name}' not found in prompt templates.")
        else:
            return next((template for template in prompt_templates if template.get("id") == template_name), None)
    except KeyError:
        raise ValueError(f"Template '{template_name}' not found in prompt templates.")

# def extract_repaired_code(response):
#     pass

# TODO: use cosine similarity to find the most similar example in the guidance tree and return it as an example for few-shot evaluation
def extract_examples(code, tree, num_examples):
    leaves = [node for node in tree if node.get("depth") == 0]
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
        prompt = template.get("template").format(code=code, examples=examples_str)

    if guidance: 
        prompt += f"\n\nIMPORTANT: Use the following guidance derived from similar vulnerabilities:\n{guidance}"

    return prompt

argparser = ArgumentParser(description="Evaluate the basic repair capability of the model.")
argparser.add_argument("--input", type=str, required=True, default="/home/emsha/projects/vuln_repair_pattern_mining/data/extracted/primevul_test_paired.jsonl", help="Path to the input JSON file containing the test cases.")
argparser.add_argument("--num_tests", type=int, default=10, help="Number of test cases to evaluate. Default is 10.")
argparser.add_argument("--provider", type=str, choices=["openai", "ollama"], required=True, help="The provider of the model to be evaluated.")
argparser.add_argument("--model", type=str, required=True, help="The model to be evaluated.")
argparser.add_argument("--prompt_template", type=str, required=True, help="The prompt template to be used for evaluation. This should be a key from the llm_based_repair_prompt_templates.json file.")
argparser.add_argument("--num_examples", type=int, default=0, help="Number of examples to include in the prompt for few-shot evaluation. Default is 3.")
# argparser.add_argument("--output", type=str, required=True, help="Path to the output CSV file where the evaluation results will be saved.")
argparser.add_argument("--tree_path", type=str, required=False, help="Path to the JSON file containing the guidance tree (only required for certain modes).")
argparser.add_argument("--add_guidance", type=bool, required=False, default=False, help="Whether to retrieve and add guidance to the prompt. Accepts 'True' or 'False'. Default is 'False'.")
argparser.add_argument("--cwe_filter", type=str, required=False, help="Optional filter to evaluate only test cases with a specific CWE ID.")

args = argparser.parse_args()

client = load_model(args.provider, args.model)

with open(args.input, "r") as f:
    test_cases = [json.loads(line) for line in f]

# print(test_cases[0])

fixed = [case for case in test_cases if "func" in case and case["func"].strip() != "" and "target" in case and case["target"] == 0]
test_cases = [case for case in test_cases if "func" in case and case["func"].strip() != "" and "target" in case and case["target"] == 1]

print(f"Loaded {len(test_cases)} test cases from {args.input}")
print(any(case.get("cwe", "") != "" for case in test_cases))
print(f"{len([case for case in test_cases if case.get('cwe', '') != ''])} test cases have a non-empty CWE ID.")
# print(test_cases[0])
# Apply CWE filter if specified
if args.cwe_filter:
    # Sanity check that any of them have a cwe that isn't just an empty string
    fixed = [case for case in fixed if case.get("cwe", "") == args.cwe_filter]
    test_cases = [case for case in test_cases if case.get("cwe", "") == args.cwe_filter]

print(f"Filtered test cases to {len(test_cases)} cases with CWE ID: {args.cwe_filter}")
# Limit the number of test cases to evaluate - choose randomly if there are more than the specified number
if len(test_cases) > args.num_tests:
    random.seed(42)  # For reproducibility
    test_cases = random.sample(test_cases, args.num_tests)

prompt_templates_list = []

if args.prompt_template and args.prompt_template.lower() == "all":
    prompt_templates_list = prompt_templates
else:
    prompt_template = load_prompt_template(args.prompt_template, prompt_templates)
    prompt_templates_list.append(prompt_template)

if args.tree_path:
    with open(args.tree_path, "r") as f:
        guidance_tree = json.load(f)

for prompt_template in prompt_templates_list:
    print(f"Evaluating with prompt template: {prompt_template.get('id')}")
    for test_case in test_cases:
        print(f"Evaluating test case: {test_case.get('idx', 'unknown idx')}")
        if "cwe" not in test_case:
            print(f"Skipping test case without CWE: {test_case.get('idx', 'unknown idx')} | project={test_case.get('project')} | target={test_case.get('target')}")
            continue
        # TODO: is the index correct? 
        cwe_id = test_case.get("cwe", "")
        code = test_case.get("func", "")
        index = test_case["idx"]
        commit_id = test_case.get("commit_id", "")
        guidance = None
        examples = None

        # TODO need to load the guidance tree and retrieve guidance for the specific vulnerability
        if args.add_guidance:
            guidance = retrieve_guidance(code, guidance_tree)
            print(f"Retrieved guidance: {guidance}")
        if prompt_template.get("id") == "few_shot":
            examples = extract_examples(code, guidance_tree, args.num_examples)
            print(f"Extracted examples: {examples}")
        formulated_prompt = formulate_prompt(prompt_template, code, examples=examples, guidance=guidance)
        # print(f"Formulated prompt:\n{formulated_prompt}\n")
        if args.provider == "openai":
            client_response = client.responses.create(
                model=args.model,
                input=[
                    {
                        "role": "user",
                        "content": formulated_prompt
                    }
                ]
            )
            # client_response = ""

        elif args.provider == "ollama":
            client_response = client.generate(
                model=args.model,
                prompt=formulated_prompt,
                max_tokens=512,
                temperature=0.0)
        
        # print(f"Prompt Template: {prompt_template.get('id')}, Test Case Index: {index}, CWE ID: {cwe_id}")
        # print(f"Prompt:\n{formulated_prompt}\n")
        # print(f"Model Response:\n{client_response}\n")

        ground_truth_patch = next((item for item in fixed if item["commit_id"] == commit_id), None)
        if ground_truth_patch is None:
            print(f"No ground truth patch found for test case commit ID: {commit_id}")
            continue

        patch = extract_patch_from_response(client_response.output_text.strip())
        print(f"Extracted Patch:\n{patch}\n")
        ground_truth_patch_code = ground_truth_patch.get("func", "")
        print(f"Ground Truth Patch Code:\n{ground_truth_patch_code}\n")
        print("Patch matching ground truth patch code: ", eval_patch(patch, ground_truth_patch_code))