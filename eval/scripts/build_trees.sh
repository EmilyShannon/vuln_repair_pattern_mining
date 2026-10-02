#!/usr/bin/env bash
conda activate vuln_repair_pattern_mining
set -euo pipefail

LIST_FILE="/home/emsha/projects/vuln_repair_pattern_mining/data/analysis/allowed_mappable_cwes.txt"
BASE_INPUT_PATH="/home/emsha/projects/vuln_repair_pattern_mining/eval/tree_building_inputs"
BUILD_TREE_SCRIPT="/home/emsha/projects/vuln_repair_pattern_mining/mining/trees/utils/build_tree.py"
DRY_RUN=0
LIMIT=""

usage() {
  cat <<'EOF'
Usage: build_trees.sh [--dry-run] [--limit N]

Reads the allowed CWE list, looks for matching input directories under eval/tree_building_inputs,
and calls build_tree.py with the first CSV it finds for each CWE.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --limit)
      LIMIT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

count=0
while IFS= read -r cwe || [[ -n "$cwe" ]]; do
  [[ -z "$cwe" ]] && continue
  [[ "$cwe" =~ ^CWE-([0-9]+)$ ]] || continue

  cwe_num="${BASH_REMATCH[1]}"
  cwe_dir="$BASE_INPUT_PATH/cwe-${cwe_num,,}"
  cwe_id="cwe-${cwe_num,,}"

  if [[ ! -d "$cwe_dir" ]]; then
    echo "Skipping $cwe: directory not found at $cwe_dir"
    continue
  fi

  input_file="$(find "$cwe_dir" -maxdepth 1 -type f \( -name 'cluster_summaries_*.csv' -o -name '*.csv' \) 2>/dev/null | sort | head -n 1)"
  if [[ -z "$input_file" ]]; then
    echo "Skipping $cwe: no CSV file found in $cwe_dir"
    continue
  fi

  echo "Building tree for $cwe using $input_file"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "python3 $BUILD_TREE_SCRIPT --input "$input_file" --cwe-id "$cwe_id""
  else
    python3 "$BUILD_TREE_SCRIPT" --input "$input_file" --cwe-id "$cwe_id"
  fi

  count=$((count + 1))
  if [[ -n "$LIMIT" ]] && [[ "$count" -ge "$LIMIT" ]]; then
    break
  fi
done < "$LIST_FILE"

echo "Processed $count CWE entries"
