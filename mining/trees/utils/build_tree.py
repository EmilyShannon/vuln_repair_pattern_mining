"""
Dynamic Abstraction Tree Builder

Key Design:
1. Layers are DYNAMIC - determined by LLM during construction
2. Layer count is NOT fixed - depends on diversity of vulnerabilities 
3. Each layer's guidance is INDEPENDENTLY extractable for experiments
4. Aims for STABILITY across runs
5. STRICT length constraints and layer differentiation
"""

import argparse
import json
import uuid
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv() 


# =========================
#  CONFIGURATION
# =========================

@dataclass
class TreeConfig:
    """Configuration for tree building - controls grouping behavior"""
    min_group_size: int = 1
    max_group_size: int = 6
    min_nodes_to_continue: int = 1  # Stop abstracting if fewer nodes
    max_depth: int = 10  # Safety limit
    force_merge_threshold: int = 2  # Force merge if nodes <= this
    
    # LLM settings for stability
    temperature: float = 0.0
    model: str = "gpt-5"
    tree_type: str = "repair"  # or "vulnerability"


# =========================
#  DATA STRUCTURES
# =========================

@dataclass
class TreeNode:
    """A node in the abstraction tree"""
    node_id: str
    depth: int  # 0 = leaf, increases upward
    children: List[str]  # Child node IDs
    patches: List[str]  # All leaf patch IDs covered by this subtree
    
    # Content
    label: str
    summary: str
    raw_patch: Optional[str] = None  # Only for leaf nodes
    guidance: Optional[str] = None  # Generated guidance for this node
    
    # Metadata
    features: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LayerGuidance:
    """Extracted guidance for one layer of the tree"""
    layer_depth: int
    node_count: int
    total_patches_covered: int
    
    # The actual guidance content
    guidances: List[Dict[str, Any]]  # List of {node_id, summary, guidance, patches_covered}
    
    # Formatted for experiments
    formatted_prompt: str


@dataclass 
class ExperimentPackage:
    """Complete package for running experiments"""
    cwe_id: str
    total_patches: int
    tree_depth: int  # How many layers (excluding leaves)
    
    # Guidance by layer - key is depth (1, 2, 3, ...)
    layer_guidances: Dict[int, LayerGuidance]
    
    # Summary
    layer_stats: List[Dict[str, Any]]


# =========================
#  LLM UTILITIES
# =========================

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)

def get_llm(temperature: float = 0.0, max_tokens: int = 4000000):
    return ChatOpenAI(
        model="gpt-5",
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=720,
        stop=None,
        max_retries=3,
        openai_api_key=OPENAI_API_KEY,
        reasoning={
            "effort": "high"
        },
        text={
            "verbosity": "high"
        }
    )

def parse_llm_response(response) -> str:
    """Extract string from LLM response"""
    content = response.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and "text" in block:
                parts.append(block["text"])
        return "".join(parts)
    return str(content)


def parse_json(text: str) -> Dict:
    """Parse JSON from LLM output, handling code blocks"""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            elif line.startswith("```") and in_block:
                break
            elif in_block:
                json_lines.append(line)
        text = "\n".join(json_lines)
    return json.loads(text)


def shorten(text: str, max_len: int = 150) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def enforce_word_limit(text: str, max_words: int) -> str:
    """Truncate text to max words if exceeded."""
    if not text:
        return ""
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]) + "..."


def remove_bullet_formatting(text: str) -> str:
    """Remove bullet points and numbered list formatting."""
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Remove bullet markers
        line = re.sub(r'^\s*[-*•]\s*', '', line)
        # Remove numbered list markers
        line = re.sub(r'^\s*\d+[.)]\s*', '', line)
        # Remove "Step N:" patterns
        line = re.sub(r'^Step\s*\d+[.:]\s*', '', line, flags=re.IGNORECASE)
        # Remove "Actions:" type headers
        line = re.sub(r'^(Actions?|Things? to look for|What to look for|Concrete actions?|Objective|Goal)[.:]\s*', '', line, flags=re.IGNORECASE)
        
        if line.strip():
            cleaned_lines.append(line.strip())
    
    # Join into paragraphs
    return ' '.join(cleaned_lines)


# =========================
#  LEAF NODE CONSTRUCTION
# =========================

def extract_patch_features(patch: Dict[str, Any]) -> Dict[str, Any]:
    """Extract relevant features from a raw patch"""    
    return {
        "raw_patch": patch,
        "summary": patch.get("summary", ""),
    }


def build_leaf_nodes(patches: List[Dict[str, Any]]) -> List[TreeNode]:
    """Convert patch info into leaf nodes without enforced sorting"""
    nodes = []
    
    for patch in patches:
        patch_id = str(patch["patch_id"])
        features = extract_patch_features(patch)
        summary = patch.get("summary", f"Patch {patch_id}")
        label = f"Patch {patch_id}"
        raw_patch = patch.get("patch", f"Patch {patch_id}")
        
        node = TreeNode(
            node_id=f"leaf_{patch_id}",
            depth=0,
            children=[],
            patches=[patch_id],
            label=label,
            summary=summary,
            raw_patch=raw_patch,
            guidance=None,
            features=features,
            provenance={"source": "leaf", "patch_id": patch_id},
        )
        nodes.append(node)
    
    return nodes


# =========================
#  DYNAMIC GROUPING
# =========================

def group_nodes_by_llm(
    nodes: List[TreeNode],
    current_depth: int,
    config: TreeConfig,
) -> List[List[TreeNode]]:
    """Use LLM to group nodes into semantic clusters."""
    if len(nodes) <= 1:
        return [nodes] if nodes else []
    
    if len(nodes) <= config.force_merge_threshold:
        print(f"  -> Force merging {len(nodes)} nodes into single group")
        return [nodes]
    
    if len(nodes) <= config.min_group_size:
        return [nodes]
    
    context_lines = []
    if current_depth == 1:
        for idx, node in enumerate(nodes):
            line = f"ID {idx}: {node.raw_patch}"
            context_lines.append(line)
    else:
        for idx, node in enumerate(nodes):
            line = f"ID {idx}: {node.summary}"
            context_lines.append(line)

    context_text = "\n\n".join(context_lines)
    print(f"  -> Grouping context:\n{context_text}\n")
    suggested_groups = max(2, min(5, len(nodes) // 3))
    
    if config.tree_type == "vulnerability":
        prompt_header = "You are grouping software vulnerabilities into semantic clusters."
        task_line = "TASK: Partition these nodes into groups by their vulnerability type or root cause."
        guidance_examples = "Prefer FEWER groups if many nodes share similar vulnerability causes, e.g. 'improper input validation'."
        theme_label = "vulnerability theme"
    elif config.tree_type == "repair":
        prompt_header = "You are grouping software vulnerabilities and their repairs into semantic clusters."
        task_line = "TASK: Partition these nodes into groups by their repair strategy."
        guidance_examples = "Prefer FEWER groups if many nodes share similar repair strategies, e.g. 'input validation'."
        theme_label = "repair strategy"
    else:
        prompt_header = "You are grouping software vulnerabilities and their repairs into semantic clusters."
        task_line = "TASK: Partition these nodes into groups by their vulnerability type or root cause."
        guidance_examples = "Prefer FEWER groups if many nodes share similar vulnerability types or repair strategies."
        theme_label = "vulnerability type or root cause"
    
    prompt = f"""{prompt_header}

{task_line}

CRITICAL RULES:
1. Do NOT create two different groups with very similar {theme_label}s. If two candidate groups would have the same underlying {theme_label}, you MUST merge them into a single group instead.
2. Group size: {config.min_group_size}-{config.max_group_size} nodes
3. You should produce BETWEEN 1 and {suggested_groups} groups in total.
   {guidance_examples}

Before grouping, identify the main themes:
1. List distinct {theme_label}s present in the nodes
2. Group nodes by {theme_label}, not by arbitrary splits or implementation details

NODES (ID 0 to {len(nodes) - 1}):
{context_text}

Return JSON:
{{
  "reasoning": "Brief explanation - ensure to distinguish groups by {theme_label}",
  "groups": [
    {{"start": 0, "end": 2, "strategy": "unique strategy 1"}},
    {{"start": 3, "end": 5, "strategy": "unique strategy 2 (different from 1)"}}
  ]
}}

All IDs from 0 to {len(nodes) - 1} must be covered exactly once.
"""
    
    llm = get_llm()
    
    try:
        response = llm.invoke(prompt)
        data = parse_json(parse_llm_response(response))
        
        groups_data = data.get("groups", [])
        if not groups_data:
            raise ValueError("No groups returned")
        
        covered = set()
        for g in groups_data:
            start, end = g["start"], g["end"]
            for i in range(start, end + 1):
                if i in covered or i < 0 or i >= len(nodes):
                    raise ValueError(f"Invalid coverage at ID {i}")
                covered.add(i)
        
        if covered != set(range(len(nodes))):
            raise ValueError("Incomplete coverage")
        
        result = []
        for g in groups_data:
            group_nodes = nodes[g["start"]:g["end"] + 1]
            for n in group_nodes:
                n.features["group_label"] = g.get("strategy", "")
            result.append(group_nodes)
        
        return result
        
    except Exception as e:
        print(f"[Grouping] Error at depth {current_depth}: {e}")
        print("[Grouping] Using fallback grouping")
        
        group_size = max(config.min_group_size, len(nodes) // suggested_groups)
        return [nodes[i:i + group_size] for i in range(0, len(nodes), group_size)]


# =========================
#  DYNAMIC ABSTRACTION
# =========================

def compute_detail_level(current_depth: int, estimated_max_depth: int) -> str:
    if estimated_max_depth <= 1:
        return "low"
    
    relative_pos = current_depth / estimated_max_depth
    if relative_pos < 0.4:
        return "high"
    elif relative_pos < 0.7:
        return "medium"
    else:
        return "low"


def get_layer_context(current_depth, estimated_max_depth, tree_type: str = "repair"):
    relative_pos = current_depth / max(estimated_max_depth, 1)
    
    if tree_type == "vulnerability":
        if relative_pos < 0.35:
            return """LAYER 1 (SPECIFIC):

SUMMARY:
Describe the vulnerability in specific implementation-level terms, excluding programming language constructs or programming entities.
Focus on the concrete conditions, triggers, and behavior that characterize the vulnerability.

GUIDANCE:
Describe the vulnerability in specific implementation-level terms.
Focus on the concrete conditions that cause the weakness and the resulting unsafe behavior.

Example Summary:
"Failure to validate externally supplied input lengths allows operations to exceed intended buffer boundaries."

Example Guidance:
"Improper validation of externally controlled sizes can permit memory corruption when data is processed using unchecked limits."
"""
        elif relative_pos < 0.7:
            return """LAYER 2 (STRATEGIC):

SUMMARY:
Describe the general vulnerability mechanism shared by the child nodes.
Focus on the common weakness without implementation details or programming entities.

GUIDANCE:
Describe the common vulnerability mechanism and the conditions that enable it.
Do not mention specific programming constructs.

Example Summary:
"Improper handling of externally controlled sizes creates unsafe memory access conditions."

Example Guidance:
"Reliance on untrusted size information without sufficient validation can compromise memory safety."
"""
        else:
            return """LAYER 3 (ABSTRACT):

SUMMARY:
Describe the underlying vulnerability concept at a high level.
Capture the common security weakness rather than specific manifestations.

GUIDANCE:
Describe the core security principle that explains the vulnerability.
Avoid implementation details entirely.

Example Summary:
"Insufficient validation of untrusted input undermines safe system behavior."

Example Guidance:
"Unsafe processing of attacker-controlled input can violate fundamental security boundaries."
"""
    else:
        if relative_pos < 0.35:
            return """LAYER 1 (SPECIFIC):

SUMMARY:
Describe the vulnerability in specific implementation-level terms.
Focus on the concrete conditions that make the weakness possible.
Do not mention the repair.

GUIDANCE:
Describe the concrete repair strategy used by the patches.

Focus on the defensive actions introduced by the repair while avoiding specific programming language constructs, API names, variables, or code entities.

Describe what is being validated, constrained, or protected, not how it is written.

Example Summary:
"Unchecked externally supplied lengths allow operations to exceed intended buffer boundaries."

Example Guidance:
"Validate data sizes before processing, restrict operations to verified limits, and ensure resulting data remains safely bounded."
"""

        elif relative_pos < 0.7:
            return """LAYER 2 (STRATEGIC):

SUMMARY:
Describe the common vulnerability mechanism shared by the child nodes.
Avoid implementation details.

GUIDANCE:
Describe the common methodology shared by the repairs.

Focus on how the repair establishes safe operating conditions before potentially unsafe operations occur.

Do not describe individual implementation steps.

Example Summary:
"Improper validation of externally controlled sizes creates unsafe memory conditions."

Example Guidance:
"Establish validation that ensures data-dependent operations occur only within verified safe limits."
"""

        else:
            return """LAYER 3 (ABSTRACT):

SUMMARY:
Describe the underlying security weakness at a conceptual level.
Capture the common vulnerability shared across the group.

GUIDANCE:
Describe the underlying defensive principle.

Focus on the general philosophy behind the repairs rather than individual validation techniques.

Avoid implementation details entirely.

Example Summary:
"Insufficient validation of untrusted input can undermine system safety."

Example Guidance:
"Enforce safety constraints before operations are permitted, preventing unsafe behavior through verified boundaries."
"""

def generate_node_guidance(
    children: List[TreeNode],
    current_depth: int,
    detail_level: str,
    estimated_max_depth: int,
    config: TreeConfig,
) -> Tuple[str, str]:
    """Generate summary and guidance for a parent node."""
    child_summaries = [n.summary for n in children]
    group_labels = [n.features.get("group_label", "") for n in children if n.features.get("group_label")]
    all_patches = [p for n in children for p in n.patches]
    
    context_lines = [f"- {s}" for s in child_summaries[:6]]
    context_text = "\n".join(context_lines)
    layer_context = get_layer_context(current_depth, estimated_max_depth, config.tree_type)
    
    if detail_level == "high":
        max_words = 60
    elif detail_level == "medium":
        max_words = 45
    else:
        max_words = 30
    
    if config.tree_type == "repair":
        summary_goal = "Generate a concise repair summary for this group."
        guidance_goal = "Generate the best abstraction that explains the common repair strategy shared by the child nodes."
        detail_instruction = f"""DETAIL: {detail_level.upper()}
- Describe the repair strategy at the appropriate level of abstraction.
- Focus on defensive safeguards, validation behavior, or high-level methodology.
- Avoid programming language constructs, specific API names, or overly procedural steps."""
        examples_string = """
GOOD (high, ~50 words):
Summary: "Validate externally supplied buffer sizes."
Guidance: "Verify externally provided length values before performing memory operations, restrict transfers to validated boundaries, and ensure copied data is safely terminated to prevent overflow from malformed or unterminated input."

GOOD (medium, ~35 words):
Summary: "Constrain untrusted data to validated boundaries."
Guidance: "Apply strict boundary validation to externally controlled input and ensure data handling operations remain limited to verified safe ranges."

GOOD (low, ~25 words):
Summary: "Enforce defensive handling of untrusted input."
Guidance: "Process externally influenced data only within validated operational constraints to preserve memory safety."
"""
    elif config.tree_type == "vulnerability":
        summary_goal = "Generate a concise vulnerability summary for this group."
        guidance_goal = "Generate the best abstraction that explains the common vulnerability shared by the child nodes."
        detail_instruction = f"""DETAIL: {detail_level.upper()}
- Describe the vulnerability at the appropriate level of abstraction.
- Focus on the underlying weakness, conditions, and impact."""
        examples_string = """
GOOD (high, ~50 words):
Summary: "Insufficient validation of data sizes allows operations to exceed safe memory or buffer boundaries."
Guidance: "Ensure all data size values are validated against fixed capacity limits before performing memory operations. Constrain processing to validated sizes and ensure resulting data remains within safe bounds."

GOOD (medium, ~35 words):
Summary: "Failure to validate data sizes allows unsafe memory or buffer access conditions."
Guidance: "Enforce strict validation of data size values and constrain processing to verified limits to prevent unsafe memory conditions."
"""
    else:
        summary_goal = "Generate a concise vulnerability summary for this group."
        guidance_goal = "Generate the best abstraction that explains the common repair strategy shared by the child nodes."
        detail_instruction = f"""DETAIL: {detail_level.upper()}
- For the summary, describe the vulnerability at the appropriate level of abstraction, focusing on the underlying weakness, conditions, and impact.
- For the guidance, describe the repair strategy at the appropriate level of abstraction, focusing on defensive safeguards, validation behavior, or high-level methodology.
- Avoid programming language constructs, specific API names, or overly procedural steps in both summary and guidance."""
        examples_string = """
GOOD (high, ~50–60 words):

Summary:
"Invalid or unchecked data sizes can lead to operations exceeding intended memory or buffer limits, creating unsafe processing conditions."

Guidance:
"Validate data sizes before processing, restrict operations to within verified limits, and ensure resulting data is safely terminated or bounded after processing."

GOOD (medium, ~35–45 words):

Summary:
"Insufficient validation of data-dependent sizes allows operations to exceed safe boundaries during processing."

Guidance:
"Establish validation checks that ensure operations remain within safe bounds before processing data."

GOOD (low, ~25–30 words):

Summary:
"Unchecked data sizes can violate safe operational boundaries."

Guidance:
"Apply validation to ensure operations remain within safe limits before execution."
"""

    prompt = f"""Generate a CONCISE label, summary, and guidance.

    {layer_context}

    {detail_instruction}

    SUMMARY AND GUIDANCE HAVE DIFFERENT PURPOSES:

    SUMMARY:
    - Always describe the COMMON VULNERABILITY represented by the child nodes.
    - Never describe the repair.
    - Follow the abstraction level specified in the layer instructions.

    GUIDANCE:
    - In a repair tree, describe the common repair strategy.
    - In a vulnerability tree, describe the common vulnerability mechanism.
    - Follow the abstraction level specified in the layer instructions.

    ===== STRICT CONSTRAINTS =====
    1. Label: ONE short phrase, MAX 15 words
    2. Summary: MAX {max_words} words, 1-2 short sentences
    3. Guidance: MAX {max_words} words, 1-2 short sentences
    4. NO bullet points, NO lists, NO headers
    5. NO commands (grep, ls, find)
    6. NO file paths
    7. Write as flowing prose

    DO NOT:

    - Restate the child summaries.
    - Describe code edits.
    - Mention variables, APIs, library calls, or language constructs.
    - Enumerate repair steps.
    - Describe one specific patch.
    - Explain how the code changed.

    Instead, identify the common defensive strategy that explains why the repairs belong together. 
    Imagine explaining why these repairs belong in the same category to an experienced software engineer. Capture the shared repair principle, not the individual implementation details.

    ===== EXAMPLES =====
    {examples_string}

    ===== CHILD NODES ({len(children)} items, {len(all_patches)} patches) =====
    {context_text}

    Return ONLY JSON:
    {{
    "label": "short label under 15 words",
    "summary": "1-2 sentences under {max_words} words",
    "guidance": "1-2 sentences under {max_words} words"
    }}"""
        
    llm = get_llm()
    
    try:
        response = llm.invoke(prompt)
        data = parse_json(parse_llm_response(response))
        
        label = data.get("label", "")
        summary = data.get("summary", "")
        guidance = data.get("guidance", "")
        
        label = enforce_word_limit(label, 15)
        summary = enforce_word_limit(summary, max_words + 15)
        guidance = enforce_word_limit(guidance, max_words + 15)
        guidance = remove_bullet_formatting(guidance)
        
        if not label:
            label = enforce_word_limit(summary or guidance or f"Group of {len(children)} nodes", 15)
        if not summary:
            summary = guidance or f"[FALLBACK] Vulnerability repair patterns across {len(children)} related cases"
        if not guidance:
            guidance = "[FALLBACK] Apply defensive validation and constrain unsafe behavior through consistent repair safeguards."
        
        return label, summary, guidance
        
    except Exception as e:
        print(f"[Guidance] Error at depth {current_depth}: {e}")
        
        if strategies:
            label = enforce_word_limit(strategies[0], 15)
            summary = shorten(strategies[0], 80)
        else:
            label = enforce_word_limit(f"Group of {len(children)} nodes", 15)
            summary = f"[FALLBACK] Vulnerability repair patterns across {len(children)} related cases"

        guidance = "[FALLBACK] Apply defensive validation and constrain unsafe behavior through consistent repair safeguards."
        return label, summary, guidance


def abstract_group(
    children: List[TreeNode],
    new_depth: int,
    detail_level: str,
    estimated_max_depth: int,
    config: TreeConfig,
) -> TreeNode:
    """Create a parent node from a group of children."""
    label, summary, guidance = generate_node_guidance(
        children, new_depth, detail_level, estimated_max_depth, config
    )
    
    # all_patches = [p for n in children for p in n.patches]
    node_id = f"L{new_depth}_{uuid.uuid4().hex[:8]}"
    
    return TreeNode(
        node_id=node_id,
        depth=new_depth,
        children=[n.node_id for n in children],
        patches=[p for n in children for p in n.patches],
        label=label,
        summary=summary,
        guidance=guidance,
        features={
            "detail_level": detail_level,
            "child_count": len(children),
        },
        provenance={
            "source": "abstraction",
            "depth": new_depth,
        },
    )


# =========================
#  MAIN TREE BUILDER
# =========================

def estimate_max_depth(num_leaves: int, config: TreeConfig) -> int:
    """Estimate maximum tree depth."""
    if num_leaves <= 1:
        return 1
    
    depth = 1
    current = num_leaves
    avg_group = (config.min_group_size + config.max_group_size) / 2
    
    while current > config.min_nodes_to_continue and depth < config.max_depth:
        current = current / avg_group
        depth += 1
        if current <= 1:
            break
    
    return depth


def build_tree(
    patches: List[Dict[str, Any]],
    config: Optional[TreeConfig] = None,
) -> Tuple[TreeNode, Dict[str, TreeNode], int]:
    """Build abstraction tree dynamically."""
    if config is None:
        config = TreeConfig()
    
    print(f"\n{'='*60}")
    print(f"Building Abstraction Tree ({len(patches)} patches)")
    print(f"{'='*60}\n")
    
    all_nodes: Dict[str, TreeNode] = {}
    estimated_max_depth = estimate_max_depth(len(patches), config)
    print(f"Estimated max depth: {estimated_max_depth}")
    
    print(f"\n[Depth 0] Building {len(patches)} leaf nodes...")
    current_nodes = build_leaf_nodes(patches)
    
    for node in current_nodes:
        all_nodes[node.node_id] = node
    
    current_depth = 1
    while len(current_nodes) > 1 and current_depth <= config.max_depth:
        print(f"\n[Depth {current_depth}] Processing {len(current_nodes)} nodes...")
        if len(current_nodes) == 2 or len(current_nodes) <= config.force_merge_threshold:
            print(f"  -> Only {len(current_nodes)} nodes, forcing merge")
            groups = [current_nodes]
        else:
            groups = group_nodes_by_llm(current_nodes, current_depth, config)
        
        print(f"  -> Formed {len(groups)} groups")
        
        if len(groups) >= len(current_nodes) and len(current_nodes) > 1:
            print("  -> No reduction, forcing merge")
            groups = [current_nodes]
        
        detail_level = compute_detail_level(current_depth, estimated_max_depth)
        next_level = []
        
        for i, group in enumerate(groups):
            parent = abstract_group(
                group, current_depth, detail_level, estimated_max_depth, config
            )
            next_level.append(parent)
            all_nodes[parent.node_id] = parent
            print(f"    Group {i}: {len(group)} nodes -> '{shorten(parent.summary, 50)}'")
        
        current_nodes = next_level
        current_depth += 1
    
    if len(current_nodes) > 1:
        print(f"\n[Final] Merging {len(current_nodes)} nodes into root...")
        root = abstract_group(
            current_nodes, current_depth, "low", estimated_max_depth, config
        )
        current_depth += 1
    else:
        root = current_nodes[0]
    
    final_depth = root.depth
    print(f"\n{'='*60}")
    print(f"Tree Complete")
    print(f"  Total nodes: {len(all_nodes)}")
    print(f"  Final depth: {final_depth}")
    print(f"{'='*60}\n")
    
    return root, all_nodes, final_depth


# =========================
#  LAYER EXTRACTION
# =========================

def extract_layer_guidance(
    all_nodes: Dict[str, TreeNode],
    target_depth: int
) -> LayerGuidance:
    """Extract guidance for all nodes at a specific depth."""
    layer_nodes = [n for n in all_nodes.values() if n.depth == target_depth]
    
    guidances = []
    total_patches = 0
    
    for node in layer_nodes:
        guidances.append({
            "node_id": node.node_id,
            "label": node.label,
            "summary": node.summary,
            "guidance": node.guidance,
            "patches_covered": node.patches,
            "num_patches": len(node.patches),
        })
        total_patches += len(node.patches)
    
    formatted = format_layer_prompt(target_depth, guidances)
    
    return LayerGuidance(
        layer_depth=target_depth,
        node_count=len(layer_nodes),
        total_patches_covered=total_patches,
        guidances=guidances,
        formatted_prompt=formatted,
    )


def format_layer_prompt(depth: int, guidances: List[Dict]) -> str:
    """Format layer guidance as a prompt for experiments."""
    lines = [
        f"# Layer {depth} Guidance",
        f"*{len(guidances)} guidance items at depth {depth}*\n",
    ]
    
    for i, g in enumerate(guidances, 1):
        lines.append(f"## Item {i}: {g['label']}")
        lines.append(f"\n**Summary:**\n{g['summary']}")
        lines.append(f"\n**Guidance:**\n{g['guidance']}")
        lines.append(f"\n*Covers {g['num_patches']} original patches*")
        lines.append("")
    
    return "\n".join(lines)


def create_experiment_package(
    cwe_id: str,
    root: TreeNode,
    all_nodes: Dict[str, TreeNode],
    total_patches: int,
    max_depth: int
) -> ExperimentPackage:
    """Extracts guidance details layer by layer and packages them into an ExperimentPackage."""
    layer_guidances: Dict[int, LayerGuidance] = {}
    layer_stats: List[Dict[str, Any]] = []
    
    # Traverse through all valid abstraction layers starting from depth 1 up to the max tree depth
    for current_depth in range(1, max_depth + 1):
        layer_data = extract_layer_guidance(all_nodes, current_depth)
        
        # Keep track of structural details only if the layer actually holds processed elements
        if layer_data.node_count > 0:
            layer_guidances[current_depth] = layer_data
            layer_stats.append({
                "layer_depth": current_depth,
                "node_count": layer_data.node_count,
                "total_patches_covered": layer_data.total_patches_covered
            })

    return ExperimentPackage(
        cwe_id=cwe_id,
        total_patches=total_patches,
        tree_depth=max_depth,
        layer_guidances=layer_guidances,
        layer_stats=layer_stats
    )

# =========================
#  SERIALIZATION
# =========================

def node_to_dict(node: TreeNode) -> Dict:
    return {
        "node_id": node.node_id,
        "depth": node.depth,
        "children": node.children,
        "patches": node.patches,
        "label": node.label,
        "summary": node.summary,
        "guidance": node.guidance,
        "features": node.features,
        "provenance": node.provenance,
    }


def layer_guidance_to_dict(lg: LayerGuidance) -> Dict:
    return {
        "layer_depth": lg.layer_depth,
        "node_count": lg.node_count,
        "total_patches_covered": lg.total_patches_covered,
        "guidances": lg.guidances,
        "formatted_prompt": lg.formatted_prompt,
    }


def package_to_dict(pkg: ExperimentPackage) -> Dict:
    return {
        "cwe_id": pkg.cwe_id,
        "total_patches": pkg.total_patches,
        "tree_depth": pkg.tree_depth,
        "layer_guidances": {
            str(k): layer_guidance_to_dict(v) 
            for k, v in pkg.layer_guidances.items()
        },
        "layer_stats": pkg.layer_stats,
    }


# =========================
#  MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="Build dynamic abstraction tree and extract layer-wise guidance"
    )
    # TODO make this a csv, either of full data or filtered for the CWE 
    parser.add_argument("--input", default="/home/emsha/projects/vuln_repair_pattern_mining/mining/cluster/clusters/ollama/qwen3-coder_480b-cloud/orig/fix/cluster_summaries_CWE-120_1778266389.json", help="Input patches JSON")
    parser.add_argument("--output-dir-base", default="/home/emsha/projects/vuln_repair_pattern_mining/mining/trees", help="Output directory")
    parser.add_argument("--cwe-id", default="CWE-120", help="Vulnerability identifier")
    
    # Config options
    # TODO we need to play with these. 
    parser.add_argument("--min-group-size", type=int, default=1)
    parser.add_argument("--max-group-size", type=int, default=6)
    parser.add_argument("--force-merge-threshold", type=int, default=3)
    parser.add_argument("--model", default="gpt-5", help="LLM model to use")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--tree-type", choices=["vulnerability", "repair", "combined"], default="combined", help="Type of tree to build (affects prompts)")
    
    args = parser.parse_args()
    
    config = TreeConfig(
        min_group_size=args.min_group_size,
        max_group_size=args.max_group_size,
        force_merge_threshold=args.force_merge_threshold,
        model=args.model,
        temperature=args.temperature,
        tree_type=args.tree_type,
    )
    
    # Load input
    print(f"Loading: {args.input}")
    with open(args.input) as f:
        data = json.load(f)
    
    patches = data.get("patches", [])
    if not patches:
        print("No patches found in input")
        return

    # Build tree
    root, all_nodes, max_depth = build_tree(patches, config)
    
    # Create experiment 
    package = create_experiment_package(
        args.cwe_id, root, all_nodes, len(patches), max_depth
    )
    
    # Create output directory
    output_dir = os.path.join(args.output_dir_base, args.tree_type, args.cwe_id)
    os.makedirs(output_dir, exist_ok=True)
    
    # Save tree
    tree_path = os.path.join(output_dir, "tree.json")
    with open(tree_path, "w") as f:
        json.dump({
            "root": root.node_id,
            "max_depth": max_depth,
            "total_nodes": len(all_nodes),
            "nodes": {nid: node_to_dict(n) for nid, n in all_nodes.items()},
        }, f, indent=2)
    print(f"\nSaved tree: {tree_path}")
    
    # Save experiment package
    package_path = os.path.join(output_dir, "experiment_package.json")
    with open(package_path, "w") as f:
        json.dump(package_to_dict(package), f, indent=2)
    print(f"Saved package: {package_path}")
    
    # Save each layer's guidance separately
    for depth, layer_guidance in package.layer_guidances.items():
        layer_path = os.path.join(output_dir, f"guidance_layer_{depth}.md")
        with open(layer_path, "w") as f:
            f.write(layer_guidance.formatted_prompt)
        print(f"Saved layer {depth}: {layer_path}")
    
    # Save combined guidance (all layers)
    combined_lines = ["# Combined Guidance (All Layers)\n"]
    for depth in sorted(package.layer_guidances.keys()):
        combined_lines.append(f"\n---\n")
        combined_lines.append(package.layer_guidances[depth].formatted_prompt)
    
    combined_path = os.path.join(output_dir, "guidance_combined.md")
    with open(combined_path, "w") as f:
        f.write("\n".join(combined_lines))
    print(f"Saved combined: {combined_path}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"CWE: {args.cwe_id}")
    print(f"Total patches: {len(patches)}")
    print(f"Tree depth: {max_depth}")
    print(f"Total nodes: {len(all_nodes)}")
    print(f"\nLayers for experiments:")
    # for stat in package.layer_stats:
    #     print(f"  Layer {stat['depth']}: {stat['node_count']} nodes, covers {stat['patches_covered']} patches")
    
    print(f"\nOutput files:")
    print(f"  tree.json - Full tree structure")
    print(f"  experiment_package.json - All data for experiments")
    for depth in sorted(package.layer_guidances.keys()):
        print(f"  guidance_layer_{depth}.md - Layer {depth} guidance only")
    print(f"  guidance_combined.md - All layers combined")


if __name__ == "__main__":
    main()
