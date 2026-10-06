#!/bin/bash
conda init & conda activate vuln_repair_pattern_extraction
cwes=(119 120 125 189 190 20 200 22 254 264 269 284 287 295 310 320 327 347 362 388 399 415 416 476 617 703 704 754 770 772 78 787 79 834 835 862 89 94)
# cwes=(120 617)
configs=(ollama/qwen3-coder:480b-cloud/orig/vul 
        ollama/qwen3-coder:480b-cloud/hybrid/vul 
        ollama/qwen3-coder:480b-cloud/semantic/vul
        ollama/qwen3-coder:480b-cloud/orig/fix 
        ollama/qwen3-coder:480b-cloud/hybrid/fix 
        ollama/qwen3-coder:480b-cloud/semantic/fix
)


for cwe in "${cwes[@]}"; do
    for config in "${configs[@]}"; do
        echo "Processing CWE $cwe with config $config"
        python3 ../cluster/utils/label_clusters.py --cwe "$cwe" --config "$config"
        echo "Reconstructing trees for CWE $cwe with config $config"
        python3 ../cluster/utils/plotting/reconstruct.py --cwe "$cwe" --config "$config"
    done
done