conda activate vuln_repair_pattern_extraction 
cd ../summary_gen

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --num-summaries 3 \
# --commit-message_column 'message' \
# --provider-name 'ollama' \
# --model-name 'deepseek-v3.2:cloud' \
# --prompt_mode 'orig'

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -r -p "Continue with the rest of the models? (y/n) "
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'ollama' \
# --model-name 'qwen3-coder:480b-cloud' \
# --prompt_mode 'orig' 

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -p "Continue with the rest of the models? (y/n) " -n
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'ollama' \
# --model-name 'qwen3-coder:480b-cloud' \
# --prompt_mode 'hybrid' 

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -p "Continue with the rest of the models? (y/n) " -n
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'ollama' \
# --model-name 'qwen3-coder:480b-cloud' \
# --prompt_mode 'semantic' 

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -p "Continue with the rest of the models? (y/n) " -n
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'openai' \
# --model-name 'gpt-5-mini' \
# --prompt_mode 'orig' 

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -p "Continue with the rest of the models? (y/n) " -n
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'openai' \
# --model-name 'gpt-5-mini' \
# --prompt_mode 'hybrid' 

# # Confirm continuation so we don't waste tokens if there are any issues with the initial setup or the first few examples
# read -p "Continue with the rest of the models? (y/n) " -n
# echo    # move to a new line
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     echo "Continuing with the rest of the models..."
# else
#     echo "Exiting. No more models will be ran."
#     exit 0
# fi

# python3  generate_nl_summaries.py --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
# --patch_column 'patch' \
# --cwe_column 'cwe' \
# --commit-message_column 'message' \
# --provider-name 'openai' \
# --model-name 'gpt-5-mini' \
# --prompt_mode 'semantic' 

# parallel --tag --ungroup -j 3 python3 generate_nl_summaries.py \
#   --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
#   --patch_column 'patch' \
#   --cwe_column 'cwe' \
#   --commit-message_column 'message' \
#   --provider-name {1} \
#   --model-name {2} \
#   --prompt_mode {3} ::: ollama ::: "deepseek-v3.2:cloud" "qwen3-coder:480b-cloud" ::: orig hybrid semantic

# parallel --tag --ungroup -j 3 python3 -u generate_nl_summaries.py \
#   --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
#   --patch_column patch \
#   --cwe_column cwe \
#   --commit-message_column message \
#   --provider-name {1} \
#   --model-name {2} \
#   --prompt_mode {3} \
#   --resume-from {4} \
#   ::: ollama ollama ollama \
#   :::+ qwen3-coder:480b-cloud qwen3-coder:480b-cloud qwen3-coder:480b-cloud \
#ra   :::+ orig hybrid semantic \
#   :::+ /home/emsha/projects/vuln_repair_pattern_mining/mining/summaries/ollama/qwen3-coder_480b-cloud/orig/nl_summaries_1773443131.jsonl /home/emsha/projects/vuln_repair_pattern_mining/mining/summaries/ollama/qwen3-coder_480b-cloud/hybrid/nl_summaries_1773443134.jsonl /home/emsha/projects/vuln_repair_pattern_mining/mining/summaries/ollama/qwen3-coder_480b-cloud/semantic/nl_summaries_1773443136.jsonl

parallel --tag --ungroup -j 3 python3 generate_nl_summaries.py \
  --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
  --patch_column 'patch' \
  --cwe_column 'cwe' \
  --commit-message_column 'message' \
  --provider-name {1} \
  --model-name {2} \
  --prompt_mode {3} ::: ollama ::: "deepseek-v3.2:cloud" ::: orig hybrid semantic

parallel --tag --ungroup -j 3 python3 generate_nl_summaries.py \
  --input /home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv \
  --patch_column 'patch' \
  --cwe_column 'cwe' \
  --commit-message_column 'message' \
  --provider-name {1} \
  --model-name {2} \
  --prompt_mode {3} ::: openai ::: "gpt-5.1" "gpt-5-mini" ::: orig hybrid semantic