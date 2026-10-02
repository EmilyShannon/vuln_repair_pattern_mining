import pandas as pd
df_test_all_w_guidance = pd.read_csv("/home/emsha/projects/vuln_repair_pattern_mining/eval/llm_basic_repair_titanvul_test_gpt-5.1_guidance.csv")
df_test_all_no_guidance = pd.read_csv("/home/emsha/projects/vuln_repair_pattern_mining/eval/llm_basic_repair_titanvul_test_gpt-5.1_no_guidance.csv")
df_train_all_w_guidance = pd.read_csv("/home/emsha/projects/vuln_repair_pattern_mining/eval/llm_basic_repair_titanvul_train_gpt-5.1_guidance.csv")
df_train_all_no_guidance = pd.read_csv("/home/emsha/projects/vuln_repair_pattern_mining/eval/llm_basic_repair_titanvul_train_gpt-5.1_no_guidance.csv")

print("--------------------- NO GUIDANCE ----------------------")
print("--------------------- TRAIN ----------------------")
print(df_train_all_no_guidance.info())
print(df_train_all_no_guidance["cwe_id"].value_counts())

print("--------------------- TEST ----------------------")
print(df_test_all_no_guidance.info())
print(df_test_all_no_guidance["cwe_id"].value_counts())

print("--------------------- GUIDANCE ----------------------")
print("--------------------- TRAIN ----------------------")
print(df_train_all_w_guidance.info())
print(df_train_all_w_guidance["cwe_id"].value_counts())

print("--------------------- TEST ----------------------")
print(df_test_all_w_guidance.info())

print(df_test_all_w_guidance["cwe_id"].value_counts())

