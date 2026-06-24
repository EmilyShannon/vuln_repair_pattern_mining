import json
import difflib
import pandas as pd
from utils import get_commit_info  

INPUT_PATH = "./primevul_train_paired.jsonl"
OUTPUT_PATH = "./primevul_train_cleaned_from_extraction.csv"


def load_jsonl(path: str) -> pd.DataFrame:
	records = []
	with open(path, "r", encoding="utf-8") as handle:
		for line in handle:
			line = line.strip()
			if line:
				records.append(json.loads(line))
	return pd.DataFrame.from_records(records)

def extract_patch_diff(vul_func, fixed_func):
	if type(vul_func) != str or type(fixed_func) != str:
		print(f"Warning: vul_func or fixed_func is not a string. vul_func type: {type(vul_func)}, fixed_func type: {type(fixed_func)}")
		print(f"vul_func: {vul_func.isna()}")
		print(f"fixed_func: {fixed_func.isna()}")
	vul_lines = vul_func.splitlines()
	fixed_lines = fixed_func.splitlines()
	diff = difflib.unified_diff(vul_lines, fixed_lines, lineterm="")
	return "\n".join(diff)

def extract_line_edits(vul, fix):

    vul = vul.splitlines()
    fix = fix.splitlines()

    matcher = difflib.SequenceMatcher(None, vul, fix)

    edits = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            edits.append({
                "type": tag,
                "vul_lines": vul[i1:i2],
                "fix_lines": fix[j1:j2]
            })

    return edits

# def get_patch_stats(patch: str):
#     if not isinstance(patch, str) or patch.strip() == "":
#         return {
#             "patch_len": 0,
#             "added": 0,
#             "removed": 0,
#             "context": 0,
#             "change_ratio": 0
#         }

#     added = 0
#     removed = 0
#     context = 0

#     for line in patch.splitlines():
#         if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
#             continue
#         elif line.startswith('+'):
#             added += 1
#         elif line.startswith('-'):
#             removed += 1
#         elif line.startswith(' ') and line.strip() != "":
#             context += 1

#     total_changes = added + removed
#     total_lines = total_changes + context

# 	# change_ratio=total_changes/total_lines if total_lines>0 else 0
# 	# context_ratio=context/total_lines if total_lines>0 else 0
# 	# context_to_change_ratio=context/total_changes if total_changes>0 else 0
# 	# Correct (spaces only)
# 	# change_ratio = total_changes / total_lines if total_lines > 0 else 0
# 	# context_ratio = context / total_lines if total_lines > 0 else 0
# 	# context_to_change_ratio = context / total_changes if total_changes > 0 else 0
# # Correct (tabs only)
# 	change_ratio = total_changes / total_lines if total_lines > 0 else 0
# 	context_ratio = context / total_lines if total_lines > 0 else 0
# 	context_to_change_ratio = context / total_changes if total_changes > 0 else 0
#     return {
#         "patch_len": total_lines,
#         "added": added,
#         "removed": removed,
# 		"num_changed_lines": total_changes,
#         "num_context_lines": context,
#         "change_ratio": change_ratio,
# 		"context_ratio": context_ratio,
# 		"context_to_change_ratio": context_to_change_ratio
#     }
def get_patch_stats(patch: str):
    if not isinstance(patch, str) or patch.strip() == "":
        return {
            "patch_len": 0,
            "added": 0,
            "removed": 0,
            "context": 0,
            "change_ratio": 0
        }

    added = 0
    removed = 0
    context = 0

    for line in patch.splitlines():
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        elif line.startswith('+'):
            added += 1
        elif line.startswith('-'):
            removed += 1
        elif line.startswith(' ') and line.strip() != "":
            context += 1

    total_changes = added + removed
    total_lines = total_changes + context

    # Compute ratios
    change_ratio = total_changes / total_lines if total_lines > 0 else 0
    context_ratio = context / total_lines if total_lines > 0 else 0
    context_to_change_ratio = context / total_changes if total_changes > 0 else 0

    return {
        "patch_len": total_lines,
        "added": added,
        "removed": removed,
        "num_changed_lines": total_changes,
        "num_context_lines": context,
        "change_ratio": change_ratio,
        "context_ratio": context_ratio,
        "context_to_change_ratio": context_to_change_ratio
    }
# def explode_cwe(df):
# 	print("Exploding CWE lists...")
# 	print("Dataframe info before exploding CWE lists:")
# 	print(df.info())
# 	print("CWEs:", df['cwe'].value_counts())

# 	# Evaluate the lists in the 'cwe' column and explode them into separate rows	
# 	# not all of them are in llists, so we need to check if the value is a string before evaluating it
# 	df['cwe'] = df['cwe'].apply(lambda x: eval(x) if isinstance(x, str) else [])
# 	df = df.explode('cwe')
# 	print("Dataframe info after exploding CWE lists:")
# 	print(df.info())
# 	print("CWEs:", df['cwe'].value_counts())

# 	return df
# def get_fixed_functions(df):
# 	df = get_commit_info.get_all_repo_and_hash(df, 'commit_url')
# 	print("Dataframe info after getting repo and hash:")
# 	print(df.info())
# 	df["fixed_func"] = None

# 	try:
# 		for index, row in df.iterrows():
# 			changes, additions, deletions, patch = get_commit_info.get_commit_info_for_file(row['commit_url'], row['file_name'])
# 			if changes is not None:
# 				print(f"Commit {row['commit_id']} has {changes} changes, {additions} additions, and {deletions} deletions for file {row['file_name']}.")
# 				# print(f"Patch:\n{patch}")
# 				# print("-" * 80)
# 				# print(f"Processing commit {row['commit_id']} for function {row['func']} with patch:\n{patch}")
# 			if patch:
# 				print(f"Processing commit {row['commit_id']} for function {row['func']} with patch:\n{patch}")
# 			df.at[index, 'fixed_func'] = get_commit_info.get_changed_lines_from_patch(patch)
# 	except Exception as e:
# 		print(f"Error processing commit info: {e}")

def main() -> None:
	df = load_jsonl(INPUT_PATH)
	print("Initial dataframe info:")
	print(df.info())
	print("Initial CWE value counts:")
	print(df['cwe'].value_counts())
	# print("Initial number of unique CWEs:", df['cwe'].nunique())
	print("Number of rows labelled vulnerable (target == 1):", df[df['target'] == 1].shape[0])
	print("Number of rows labelled fixed (target == 0):", df[df['target'] == 0].shape[0])
	df = df.dropna(subset=['cwe'])
	df = df[df['cwe'] != '[]']
	df = df[~df['cwe'].apply(lambda x: isinstance(x, list) and len(x) == 0)]
	# Remove ones that are just whitespace or empty strings
	df = df[df['cwe'].str.strip() != '']

	# print("Number of rows after dropping NaN CWE values:", df.shape[0])
	print("Dataframe info after dropping NaN CWE values and empty lists:")
	print(df.info())
	print("CWE value counts after dropping NaN and empty lists:")
	print(df['cwe'].value_counts())
	print("Number of rows labelled vulnerable (target == 1):", df[df['target'] == 1].shape[0])
	print("Number of rows labelled fixed (target == 0):", df[df['target'] == 0].shape[0])

	print("Number of unique commit IDs:", df['commit_id'].nunique())

	# df = explode_cwe(df)
	# df = df[df['cwe'] != 'CWE-NoInfo']
	df_paired = df.groupby('commit_id')

	# # See how many are per group
	# print("Number of rows per commit:")
	# print(df_paired.size())
	commit_ids_to_drop = df_paired.size()[df_paired.size() != 2].index
	print(f"Number of commits with more than 2 rows: {len(commit_ids_to_drop)}")
	print(f"Number of commits with exactly 2 rows: {len(df_paired.size()[df_paired.size() == 2])}")
	df = df[~df['commit_id'].isin(commit_ids_to_drop)]

	print("Dataframe info after filtering commits with more or less than 2 rows:")
	print(df.info())

	for commit_id, group in df_paired:
		# print(f"Processing commit {commit_id} with {len(group)} rows.")
		if len(group) != 2:
			# print(f"Warning: Commit {commit_id} has {len(group)} rows, expected 2. Skipping.")
			continue
		# Save vul and fixed functions to one row
		# Get the vulnerable function (target == 1) and the fixed function (target == 0)
		vul_func = group[group['target'] == 1]['func'].values
		fixed_func = group[group['target'] == 0]['func'].values
		if len(vul_func) == 1 and len(fixed_func) == 1:
			# print(f"Commit {commit_id} has vulnerable function: {vul_func[0]} and fixed function: {fixed_func[0]}")
			df.loc[df['commit_id'] == commit_id, 'vul_func'] = vul_func[0]
			df.loc[df['commit_id'] == commit_id, 'fixed_func'] = fixed_func[0]
		else:
			# print(f"Warning: Commit {commit_id} does not have both vulnerable and fixed functions. Skipping.")
			continue

	print("Dataframe info after pairing vulnerable and fixed functions:")
	print(df.info())

	# Drop any null values in the vul_func and fixed_func columns, as these are necessary for our analysis
	df = df.dropna(subset=['vul_func', 'fixed_func'])

	# Now remove duplicates and keep only one row per commit_id
	df = df.drop_duplicates(subset=['commit_id'])
	print("Dataframe info after dropping null functions and duplicates:")
	print(df.info())
	print(df["cwe"].value_counts())

	# Now for the sake of plotting make a copy with them split into separate rows

	# First check the trypes of the cwe column bc some should be lists and some are strings
	print("CWE column types:")
	print(df['cwe'].apply(lambda x: type(x)).value_counts())


	# Extract the patches 
	df['patch'] = df.apply(
		lambda row: extract_patch_diff(row['vul_func'], row['fixed_func']),
		axis=1
	)

	# df = df.reset_index(drop=True)
	stats = df['patch'].apply(get_patch_stats).apply(pd.Series)
	df = pd.concat([df, stats], axis=1)
	print("After concatting with stats:")
	print(df[['patch', 'patch_len']].head())
	print(df['patch_len'].isna().sum())
	print(df['patch_len'].dtype)
	print("Missing values in 'cwe' column before exploding:", df['cwe'].isna().sum())
	
	# Explode only the values that are lists, and keep the ones that are strings as they are
	df['cwe'] = df['cwe'].apply(lambda x: x if isinstance(x, list) else [x])
	df_exploded = df.explode('cwe')
	# df_exploded = df.explode('cwe')
	# print("Dataframe info after exploding CWE lists:")
	# print(df_exploded.info())
	print("CWEs:", df_exploded['cwe'].value_counts())
	print("Number of unique CWEs after exploding:", df_exploded['cwe'].nunique())
	print("Number of unique CWEs with at least 2 occurrences after exploding:", df_exploded['cwe'].value_counts()[df_exploded['cwe'].value_counts() >= 2].shape[0])
	print("Number of unique CWEs with at least 2 occurrences after exploding and less than or equal 15:", df_exploded['cwe'].value_counts()[df_exploded['cwe'].value_counts() >= 2][df_exploded['cwe'].value_counts() <= 15].shape[0])

	print("Missing values in 'cwe' column after exploding:", df_exploded['cwe'].isna().sum())

	# Graph the CWE distribution
	import matplotlib.pyplot as plt
	plt.figure(figsize=(10, 6))
	# Get the top 25 CWEs
	top_25_cwes = df_exploded['cwe'].value_counts().head(25)
	top_25_cwes.plot(kind='bar')
	plt.title('CWE Distribution - PrimeVul Training Pairs')
	plt.xlabel('Count')
	plt.xticks(rotation=45, ha='right')
	plt.ylabel('CWE')
	plt.tight_layout()
	# plt.show()
	plt.savefig('analysis/plots/primevul_cwe_distribution_cleaned.png')	

	# Plot the sizes of the vulnerable and fixed functions
	print("----------------------------------------------")
	
	print(df['vul_func'].head(2))
	print("----------------------------------------------")
	print(df['fixed_func'].head(2))
	print("----------------------------------------------")

	df['vul_func_size'] = df['vul_func'].apply(lambda x: len(x.splitlines()) if isinstance(x, str) else 0)
	df['fixed_func_size'] = df['fixed_func'].apply(lambda x: len(x.splitlines()) if isinstance(x, str) else 0)

	print(df['vul_func_size'].describe())
	print(df['fixed_func_size'].describe())
	# print(df['patch_len'].describe())
	desc = df['patch_len'].describe()
	print("PATCH LEN DESCRIBE:")
	print(desc.to_string())
	# Sanity check that for the rows that have a non-null "size" column, the the vul_func and fixed_func columns match the expected sizes
	# print("Sanity check for function sizes:")
	# print(df[df['size'].notnull()][['fixed_func_size', 'vul_func_size', 'size']].head())
	# Make two plots, one for the distribution of vulnerable function sizes and one for the distribution of fixed function sizes, and save them to the analysis/plots directory
	plt.figure(figsize=(10, 6))
	# Make the bins so that there is a bin for each integer value from 0 to the maximum function size, and then one bin for all values above the maximum function size
	max_vul_func_size = df['vul_func_size'].max()
	bins = list(range(0, max_vul_func_size + 1)) + [max_vul_func_size + 1]
	plt.hist(df['vul_func_size'], bins=bins, label='Vulnerable Function Size')
	plt.title('Vulnerable Function Size Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_vulnerable_function_size_distribution_full.png')

	plt.figure(figsize=(10, 6))
	bins = list(range(0, 1001)) 
	plt.hist(df[df['vul_func_size'] <= 1000]['vul_func_size'], bins=bins, label='Vulnerable Function Size')
	plt.title('Vulnerable Function Size Distribution (Max 1000 Lines) - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_vulnerable_function_size_distribution_max_1000.png')

	plt.figure(figsize=(10, 6))
	bins = list(range(0, 301)) 
	plt.hist(df[df['vul_func_size'] <= 300]['vul_func_size'], bins=bins, label='Vulnerable Function Size')
	plt.title('Vulnerable Function Size Distribution (Max 300 Lines) - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_vulnerable_function_size_distribution_max_300.png')

	plt.figure(figsize=(10, 6))
	max_fixed_func_size = df['fixed_func_size'].max()
	bins = list(range(0, max_fixed_func_size + 1)) + [max_fixed_func_size + 1]
	plt.hist(df['fixed_func_size'], bins=bins, label='Fixed Function Size')
	plt.title('Fixed Function Size Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_fixed_function_size_distribution_full.png')

	plt.figure(figsize=(10, 6))
	bins = list(range(0, 1001))
	plt.hist(df[df['fixed_func_size'] <= 1000]['fixed_func_size'], bins=bins, label='Fixed Function Size')
	plt.title('Fixed Function Size Distribution (Max 1000 Lines) - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_fixed_function_size_distribution_max_1000.png')
	
	plt.figure(figsize=(10, 6))
	bins = list(range(0, 301))
	plt.hist(df[df['fixed_func_size'] <= 300]['fixed_func_size'], bins=bins, label='Fixed Function Size')
	plt.title('Fixed Function Size Distribution (Max 300 Lines) - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_fixed_function_size_distribution_max_300.png')


	plt.figure(figsize=(10, 6))
	# max_patch_size = int(df['patch_len'].max())
	# bins = list(range(0, max_patch_size + 1)) + [max_patch_size + 1]
	bins = list(range(0, 300))
	plt.hist(df['patch_len'], bins=bins, label='Patch Size')
	plt.title('Patch Size Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_patch_size_distribution_full.png')

	plt.figure(figsize=(10, 6))
	# max_diff_size = int(df['num_changed_lines'].max())
	# bins = list(range(0, max_diff_size + 1)) + [max_diff_size + 1]
	bins = list(range(0, 160))
	plt.hist(df['num_changed_lines'], bins=bins, label='Num Changed Lines (added or removed)')
	plt.title('Num Changed Lines Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_changed_size_distribution_full.png')

	plt.figure(figsize=(10, 6))
	# max_context_size = int(df['num_context_lines'].max())
	# bins = list(range(0, max_context_size + 1)) + [max_context_size + 1]
	bins = list(range(0, 60))
	plt.hist(df['num_context_lines'], bins=bins, label='Num Context Lines per Diff')
	plt.title('Num Context Lines Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_context_size_distribution_full.png')
	# df.to_csv(OUTPUT_PATH, index=False)
	# print(f"Wrote paired dataframe to: {OUTPUT_PATH}")


	plt.figure(figsize=(10, 6))
	# max_context_size = int(df['num_context_lines'].max())
	# bins = list(range(0, max_context_size + 1)) + [max_context_size + 1]
	bins = list(range(0, 60))
	plt.hist(df['num_context_lines'], bins=bins, label='Num Context Lines per Diff')
	plt.title('Num Context Lines Distribution - PrimeVul Training Pairs')
	plt.xlabel('Number of Lines')
	plt.savefig('analysis/plots/primevul_context_size_distribution_full.png')

	plt.figure(figsize=(8, 5))
	plt.hist(df['change_ratio'], bins=30)
	plt.title('Distribution of Change Ratio')
	plt.xlabel('Change Ratio (changed lines / total lines in diff)')
	plt.ylabel('Number of patches')
	plt.tight_layout()
	# plt.show()
	plt.savefig('analysis/plots/primevul_change_ratio_distribution_full.png')

	plt.figure(figsize=(8, 5))
	plt.hist(df['context_ratio'], bins=30)
	plt.title('Distribution of Context to Total Lines Ratio')
	plt.xlabel('Context Ratio (context lines / total lines in diff)')
	plt.ylabel('Number of patches')
	plt.tight_layout()
	# plt.show()
	plt.savefig('analysis/plots/primevul_context_ratio_distribution_full.png')

	plt.figure(figsize=(8, 5))
	plt.hist(df['context_to_change_ratio'], bins=30)
	plt.title('Distribution of Context to Changed Lines Ratio')
	plt.xlabel('Context Ratio (context lines / changed lines in diff)')
	plt.ylabel('Number of patches')
	plt.tight_layout()
	# plt.show()
	plt.savefig('analysis/plots/primevul_context_to_change_ratio_distribution_full.png')
if __name__ == "__main__":
	main()