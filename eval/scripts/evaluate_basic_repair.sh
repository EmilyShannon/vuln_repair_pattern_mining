#!/usr/bin/env bash
set -euo pipefail

cd /home/emsha/projects/vuln_repair_pattern_mining
source ~/anaconda3/etc/profile.d/conda.sh
conda activate vuln_repair_pattern_extraction

LIST_FILE="/home/emsha/projects/vuln_repair_pattern_mining/data/analysis/allowed_mappable_cwes.txt"
TREE_ROOT="/home/emsha/projects/vuln_repair_pattern_mining/eval/tree_building_outputs/ollama/zerocopia_deepseek-v4-flash_cloud/orig"
# OUTPUT_DIR_BASE="/home/emsha/projects/vuln_repair_pattern_mining/eval/results"

# mkdir -p "$OUTPUT_DIR"

while IFS= read -r cwe || [[ -n "$cwe" ]]; do
  [[ -z "$cwe" ]] && continue
  [[ "$cwe" =~ ^CWE-([0-9]+)$ ]] || continue
 
  cwe_id="cwe-${BASH_REMATCH[1],,}"
  echo "CWE ID: $cwe_id"
  tree_path="$TREE_ROOT/$cwe_id/combined/$cwe_id/tree.json"
  # output_path_guidance="$OUTPUT_DIR/${cwe_id}_guidance.csv"
  # output_path_no_guidance="$OUTPUT_DIR/${cwe_id}_no_guidance.csv"

  if [[ ! -f "$tree_path" ]]; then
    echo "Skipping $cwe: tree not found at $tree_path"
    continue
  fi

  echo "Running evaluation for $cwe"
#   echo "MODEL : deepseek"

#   python3 eval/llm_basic_repair.py \
#   --dataset "titanvul" \
#   --train \
#   --num_tests 15 \
#   --provider "ollama" \
#   --model "zerocopia/deepseek-v4-flash:cloud" \
#   --prompt_template "all" \
#   --num_examples 3 \
#   --tree_path "$tree_path" \
#   --cwe_filter "$cwe_id" || {
#       echo "Python call failed for $cwe, continuing..."
#   }

# python3 eval/llm_basic_repair.py \
#   --dataset "titanvul" \
#   --train \
#   --num_tests 15 \
#   --provider "ollama" \
#   --model "zerocopia/deepseek-v4-flash:cloud" \
#   --prompt_template "all" \
#   --num_examples 3 \
#   --tree_path "$tree_path" \
#   --cwe_filter "$cwe_id" \
#   --add_guidance|| {
#       echo "Python call failed for $cwe, continuing..."
#   }

#     python3 eval/llm_basic_repair.py \
#   --dataset "titanvul" \
#   --test \
#   --num_tests 15 \
#   --provider "ollama" \
#   --model "zerocopia/deepseek-v4-flash:cloud" \
#   --prompt_template "all" \
#   --num_examples 3 \
#   --tree_path "$tree_path" \
#   --cwe_filter "$cwe_id" || {
#       echo "Python call failed for $cwe, continuing..."
#   }

#   python3 eval/llm_basic_repair.py \
#     --dataset "titanvul" \
#     --test \
#     --num_tests 15 \
#     --provider "ollama" \
#     --model "zerocopia/deepseek-v4-flash:cloud" \
#     --prompt_template "all" \
#     --num_examples 3 \
#     --tree_path "$tree_path" \
#     --cwe_filter "$cwe_id" \
#     --add_guidance|| {
#         echo "Python call failed for $cwe, continuing..."
#     }

  echo "MODEL : deepseek"

  # python3 eval/llm_basic_repair.py \
  #   --dataset "titanvul" \
  #   --train \
  #   --num_tests 10 \
  #   --provider "ollama" \
  #   --model "zerocopia/deepseek-v4-flash:cloud" \
  #   --prompt_template "all" \
  #   --num_examples 3 \
  #   --tree_path "$tree_path" \
  #   --cwe_filter "$cwe_id" || {
  #       echo "Python call failed for $cwe, continuing..."
  #   }

  python3 eval/llm_basic_repair.py \
    --dataset "titanvul" \
    --train \
    --num_tests 10 \
    --provider "ollama" \
    --model "zerocopia/deepseek-v4-flash:cloud" \
    --prompt_template "all" \
    --num_examples 3 \
    --tree_path "$tree_path" \
    --cwe_filter "$cwe_id" \
    --add_guidance || {
        echo "Python call failed for $cwe, continuing..."
    }

  python3 eval/llm_basic_repair.py \
    --dataset "titanvul" \
    --test \
    --num_tests 10 \
    --provider "ollama" \
    --model "zerocopia/deepseek-v4-flash:cloud" \
    --prompt_template "all" \
    --num_examples 3 \
    --tree_path "$tree_path" \
    --cwe_filter "$cwe_id" || {
        echo "Python call failed for $cwe, continuing..."
    }

  python3 eval/llm_basic_repair.py \
    --dataset "titanvul" \
    --test \
    --num_tests 10 \
    --provider "ollama" \
    --model "zerocopia/deepseek-v4-flash:cloud" \
    --prompt_template "all" \
    --num_examples 3 \
    --tree_path "$tree_path" \
    --cwe_filter "$cwe_id" \
    --add_guidance || {
        echo "Python call failed for $cwe, continuing..."
    }

  # echo "MODEL : gpt"

  # python3 eval/llm_basic_repair.py \
  #   --dataset "titanvul" \
  #   --train \
  #   --num_tests 1 \
  #   --provider "openai" \
  #   --model "gpt-5.1" \
  #   --prompt_template "all" \
  #   --num_examples 3 \
  #   --tree_path "$tree_path" \
  #   --cwe_filter "$cwe_id" || {
  #       echo "Python call failed for $cwe, continuing..."
  #   }

  # python3 eval/llm_basic_repair.py \
  #   --dataset "titanvul" \
  #   --train \
  #   --num_tests 1 \
  #   --provider "openai" \
  #   --model "gpt-5.1" \
  #   --prompt_template "all" \
  #   --num_examples 3 \
  #   --tree_path "$tree_path" \
  #   --cwe_filter "$cwe_id" \
  #   --add_guidance|| {
  #       echo "Python call failed for $cwe, continuing..."
  #   }

  #     python3 eval/llm_basic_repair.py \
  #   --dataset "titanvul" \
  #   --test \
  #   --num_tests 1 \
  #   --provider "openai" \
  #   --model "gpt-5.1" \
  #   --prompt_template "all" \
  #   --num_examples 3 \
  #   --tree_path "$tree_path" \
  #   --cwe_filter "$cwe_id" || {
  #       echo "Python call failed for $cwe, continuing..."
  #   }

  # python3 eval/llm_basic_repair.py \
  #   --dataset "titanvul" \
  #   --test \
  #   --num_tests 1 \
  #   --provider "openai" \
  #   --model "gpt-5.1" \
  #   --prompt_template "all" \
  #   --num_examples 3 \
  #   --tree_path "$tree_path" \
  #   --cwe_filter "$cwe_id" \
  #   --add_guidance|| {
  #       echo "Python call failed for $cwe, continuing..."
  #   }
done < "$LIST_FILE"
