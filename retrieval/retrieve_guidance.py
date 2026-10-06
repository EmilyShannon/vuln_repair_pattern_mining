from openai import OpenAI
from ollama import Client as OllamaClient
from typing import Any, Optional
from dotenv import load_dotenv
from argparse import ArgumentParser
import json
import os
import pandas as pd

# load_dotenv()
# client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
# TODO makke llm calling and response extraction utilities for both files to use
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

def process_vulnerable_code(client, provider, model, code: str, cwe_id: str, detail_level: Optional[str], description: Optional[str]):
    # Generate a summary of the vulnerable code 
    prompt = f"""
        Generate a concise vulnerability summary for this vulnerable code, at the appropriate level of detail. Return ONLY the summary, without any additional explanation or formatting.

        DETAIL: {detail_level.upper()}
        - Describe the vulnerability at the appropriate level of abstraction.
        - Focus on the underlying weakness, conditions, and impact.
        - Avoid programming language constructs, specific API names, or overly procedural steps.

        VULNERABLE CODE:
        {code}

        CWE ID: {cwe_id}
        DESCRIPTION: {description}

        """
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
    # response = client.responses.create(
    #     model="gpt-5",
    #     input=[
    #         {
    #             "role": "user",
    #             "content": prompt
    #         }
    #     ],
    # )
    return response.output_text.strip()


def retrieve_most_similar_summary(client, provider, model, tree: str, vuln_code_summary: str, cwe_id: str, description: Optional[str]):
    # Parse the json tree and compare the vulnerability summary to the summaries in the tree, returning the most similar one
    prompt = f"""
        Given the following vulnerability summary and CWE description, find the most similar node in the provided JSON tree, using its summary. 
        
        Return:
        1) the summary of the most similar node, with its node ID, labbelled as "MOST_SIMILAR_SUMMARY: <summary>" and "MOST_SIMILAR_NODE_ID: <node_id>", each followed by a newline, and 
         2) a brief explanation, labelled "EXPLANATION: <explanation>", folowed by a newline, of why this node is the most similar. Specifically, justify why the vulnerability does not match with any of the finer-grained vulnerabilities from the next layer down.
        
        VULNERABILITY SUMMARY:
        {vuln_code_summary}
        CWE ID: {cwe_id}
        DESCRIPTION: {description}
        JSON TREE:
        {tree}
        """
    if provider == "openai":
        response = client.responses.create(
            model=model,
            input=[{"role": "user", "content": prompt}],
        )
        output = response.output_text.strip()
    if provider == "ollama":
        try:
            response = client.generate(model=model, prompt=prompt)
        except Exception as exc:
            return f"[ollama error: {exc}]"
        output = extract_ollama_response(response)
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    # Find the id, summary and explanation in the response
    most_similar_summary = None
    most_similar_node_id = None
    explanation = None
    for line in output.splitlines():
        if line.startswith("MOST_SIMILAR_SUMMARY:"): 
            most_similar_summary = line[len("MOST_SIMILAR_SUMMARY:"):].strip()
        elif line.startswith("MOST_SIMILAR_NODE_ID:"):
            most_similar_node_id = line[len("MOST_SIMILAR_NODE_ID:"):].strip()
        elif line.startswith("EXPLANATION:"):
            explanation = line[len("EXPLANATION:"):].strip()
    return most_similar_summary, most_similar_node_id, explanation


def retrieve_subtree(node_id: str, tree: dict):
    nodes = []
    most_similar_node = None
    # We already have the most similar node id, find the node
    for node in tree["nodes"].values():
        if node["node_id"] == node_id:
            most_similar_node = node
            nodes.append(node)
            break
    # Go up the tree until we reach the root, adding each parent node to the subtree
    if most_similar_node is not None:
        depth = most_similar_node["depth"]
        parent_node = retrieve_parent(depth, tree, most_similar_node["node_id"])
        # print(f"Parent node of most similar node (ID: {most_similar_node['node_id']}): {parent_node}    ")
        while parent_node is not None:
            nodes.append(parent_node)
            most_similar_node = parent_node
            depth += 1
            parent_node = retrieve_parent(depth, tree, most_similar_node["node_id"])
         
    return nodes

    
def retrieve_parent(depth: int, tree: dict, child_node_id: str):
    parent_node = None
    parent_depth = depth + 1
    # Assuming tree["nodes"] is a dict here based on the .values() usage above
    for node in tree["nodes"].values():
        if node["depth"] == parent_depth and child_node_id in node["children"]:
            parent_node = node
            break
    return parent_node


def extract_guidance(subtree: list):
    # print("Extracting guidance from subtree:")
    # print(subtree)
    guidance = ""
    for node in subtree:
        guidance += f"Depth {node['depth']}: {node['guidance']}\n"
    return guidance


def retrieve_guidance(client, provider, model, vul_code: str, cwe_id: str, description: Optional[str], tree_json: dict, cache_path: str):
    """
    Main function updated to check the CSV cache before hitting the LLM.
    """
    # 1. Load or initialize the cache DataFrame
    if os.path.exists(cache_path):
        cache_df = pd.read_csv(cache_path)
    else:
        cache_df = pd.DataFrame(columns=["vuln_code", "cwe_id", "vuln_code_summary", "most_similar_summary", "most_similar_summary_id", "explanation"])

    # 2. Check if the exact vulnerable code snippet is already in the cache
    cache_hit = cache_df[cache_df['vuln_code'] == vul_code]

    if not cache_hit.empty:
        print("Cache hit! Retrieving LLM responses from CSV cache...")
        vuln_code_summary = cache_hit.iloc[0]['vuln_code_summary']
        most_similar_summary = cache_hit.iloc[0]['most_similar_summary']
        most_similar_summary_id = str(cache_hit.iloc[0]['most_similar_summary_id'])
        explanation = cache_hit.iloc[0]['explanation']
    else:
        print("Cache miss. Generating LLM responses...")
        detail_level = "high"
        vuln_code_summary = process_vulnerable_code(client=client, provider=provider, model=model, code=vul_code, cwe_id=cwe_id, detail_level=detail_level, description=description)
        most_similar_summary, most_similar_summary_id, explanation = retrieve_most_similar_summary(client, provider, model, json.dumps(tree_json), vuln_code_summary, cwe_id, description)
        
        # 3. Save the new LLM generations to the cache and write to CSV
        new_row = pd.DataFrame([{
            "vuln_code": vul_code,
            "cwe_id": cwe_id,
            "vuln_code_summary": vuln_code_summary,
            "most_similar_summary": most_similar_summary,
            "most_similar_summary_id": most_similar_summary_id,
            "explanation": explanation
        }])
        cache_df = pd.concat([cache_df, new_row], ignore_index=True)
        cache_df.to_csv(cache_path, index=False)
        print("New responses saved to cache.")

    # 4. existing tree traversal 
    guidance_subtree = retrieve_subtree(most_similar_summary_id, tree_json)
    # print(guidance_subtree)
    guidance = extract_guidance(guidance_subtree)
    # print(guidance)
    # Returning all generated components so the main script can print them
    return guidance, vuln_code_summary, most_similar_summary, most_similar_summary_id, explanation


def remove_first_line(text: Optional[str]) -> str:
    if not isinstance(text, str):
        return ""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and lines[i].strip() == "":
        i += 1

    if i < len(lines) and lines[i].strip().startswith("---"):
        i += 1
        if i < len(lines) and lines[i].strip().startswith("+++"):
            i += 1

    return "\n".join(lines[i:])