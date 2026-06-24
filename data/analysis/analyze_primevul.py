import pandas as pd
import csv
import matplotlib.pyplot as plt

df = pd.read_csv("/home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train.csv")

print(df.info())
print(f"Number of unique values in 'patch' column: {df['patch'].nunique()}")
# print(df["patch"].iloc[0])
print(df["message"].isna().sum())
# print(df["line_edits"].head())
# First, make sure the vul_func and fixed_func columns do not contain NaN values, as this would affect the analysis of code sizes
print(f"Number of missing values in 'vul_func' column: {df['vul_func'].isna().sum()}")
print(f"Number of missing values in 'fixed_func' column: {df['fixed_func'].isna().sum()}")
# Also the size column
# TODO count the sizes using the api or something instead of relying on the size column in the dataset, which has a lot of missing values
print(f"Number of missing values in 'size' column: {df['size'].isna().sum()}")

# Plot the CWE distribution
cwe_counts_no_mod = df['cwe'].value_counts()
print(cwe_counts_no_mod)
#Count te number of missing values in the 'cwe' column
missing_cwe_count = df['cwe'].isna().sum()
print(f"Number of missing values in 'cwe' column: {missing_cwe_count}")
print(f"Dropping rows with missing 'cwe' values")
df = df.dropna(subset=['cwe'])
print(f"Number of rows after dropping missing 'cwe' values: {len(df)}")
import numpy as np

cwe_counts = {}
# Iterate through each value in the 'cwe' column and account for NaNs and list-strings
for cwe in df['cwe']:
    # pandas represents missing values as NaN (float), so check first
    if pd.isna(cwe):
        cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
        continue

    # Some rows encode multiple CWEs as a stringified list
    if isinstance(cwe, str) and cwe.startswith('[') and cwe.endswith(']'):
        cwes_list = cwe.replace('[', '').replace(']', '').split(', ')
        if not cwes_list:
            # TODO there should not be any no info cwes 
            cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
            continue
        for entry in cwes_list:
            entry = entry.strip().strip("'").strip('"')
            if entry:
                cwe_counts[entry] = cwe_counts.get(entry, 0) + 1
            else:
                cwe_counts['CWE-NoInfo'] = cwe_counts.get('CWE-NoInfo', 0) + 1
    else:
        # Normal string value (not a list) - just count
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

print("dropping rows with missing cwe values after counting cwe distribution from lists")
# drop where the cwe value is CWE-NoInfo, which means that it was either originally NaN or an empty list, since we counted those as 'CWE-NoInfo' in the distribution above
df = df[df['cwe'] != 'CWE-NoInfo']
print(f"Number of rows after dropping 'CWE-NoInfo' values: {len(df)}") 

# Save the cleaned version of the dataset to a new CSV file
df.to_csv("/home/emsha/projects/vuln_repair_pattern_mining/data/primevul_train_cleaned.csv", index=False)
# Plot a bar chart of the CWE distribution
# Adjust the horizontal size of the plot to accommodate long CWE names
# Also so that the labels don't get cut off at the bottom
plt.figure(figsize=(12, 6))
plt.tight_layout()

# Turn the cwe_counts dictionary into a pandas Series for plotting
cwe_counts = pd.Series(cwe_counts)
# Sort the counts in descending order
cwe_counts = cwe_counts.sort_values(ascending=False)
print(
    cwe_counts)
cwe_counts.head(25).plot(kind='bar')
plt.xlabel('CWE')
plt.xticks(rotation=30, ha='right')  # Rotate x-axis labels for better readability
plt.ylabel('Count')
plt.title('Distribution of CWEs in PrimeVul Training Dataset')
# plt.show()
plt.savefig('plots/primevul_train_cwe_distribution.png')
plt.close()

# Analyze the distribution of the size of the code 
# Calculate the size of the code snippets (number of lines)
# df['code_size'] = df['vul_func'].apply(lambda x: len(str(x).splitlines()))
# Plot the distribution of code sizes
# Make sure to remove na values from the size column before plotting
code_size_counts = df['size'].dropna().value_counts().sort_index()
# Filter to only include code sizes <= 1000 lines
code_size_counts = code_size_counts[code_size_counts.index <= 1000]
plt.figure(figsize=(10, 6))
plt.bar(code_size_counts.index, code_size_counts.values, edgecolor='black')
plt.xlabel('Code Size (Number of Lines)')
plt.ylabel('Frequency')
plt.title('Distribution of Vulnerable Function Sizes in PrimeVul Training Dataset (Sizes <= 1000)')
# plt.show()
plt.savefig('plots/primevul_train_vul_func_size_distribution.png')
plt.close()  

# Make the same plot but only going to 30 lines of code
code_size_counts = code_size_counts[code_size_counts.index <= 30]
plt.figure(figsize=(10, 6))
plt.bar(code_size_counts.index, code_size_counts.values, edgecolor='black')
# show all of the x-axis labels (instead of every 10th label)
plt.xticks(code_size_counts.index)
plt.xlabel('Code Size (Number of Lines)')
plt.ylabel('Frequency')
plt.title('Distribution of Vulnerable Function Sizes in PrimeVul Training Dataset (Sizes <= 30)')
# plt.show()
plt.savefig('plots/primevul_train_vul_func_size_distribution_30.png')
plt.close()

