import pandas as pd
import csv
# extracted_df = pd.read_csv('C:\\Users\\emsha\\Documents\\Courses_F2025\\Research\\Code\\auto_pattern_extraction\\llm-based\\OpenAI\\data\\extracted_data\\cvefixes_with_cwe_relationships.csv')
# extracted_df = pd.read_csv("C:\\Users\\emsha\\Documents\\Courses_F2025\\Research\\Code\\auto_pattern_extraction\\llm-based\\OpenAI\\data\\extracted_data\\cvefixes_merged_commit_view_v2.csv")
print("check")
extracted_df = pd.read_csv("../cvefixes.csv", engine='python', encoding="utf-8", nrows=1)
# with open('../cvefixes.csv', 'r', encoding='utf-8') as f:
#     reader = csv.reader(f)
#     header = next(reader)  # Read the header row
#     print("Header columns:", header)  # Print the header columns to check for issues
print(extracted_df.info())
print(extracted_df['method_change_count'].value_counts())
print("total number of method changes: ", extracted_df['method_change_count'].sum())
# Analyze the proportion of commits with multiple CWEs, per language 
# Since the languages column is a list of languages, we need to explode it to get the count of commits per language
extracted_df['languages'] = extracted_df['languages'].apply(lambda x: eval(x) if isinstance(x, str) else x)
exploded_df = extracted_df.explode('languages')
language_stats = exploded_df.groupby('languages')['is_multi_cwe'].agg(['mean', 'count'])
print(language_stats)

# Get counts of number of CWEs per commit, per language 
cwe_counts = exploded_df.groupby('languages')['num_cwes'].value_counts().unstack(fill_value=0)
print(cwe_counts)

# Get percentage, for each languageme, of commits with 1 CWE, 2 CWEs, etc.
cwe_percentage = exploded_df.groupby('languages')['num_cwes'].value_counts(normalize=True)
print(cwe_percentage)

target_languages = ['C', 'C++', 'Java', 'Python']
# Plot the distribution of number of CWEs per commit, for each language
import matplotlib.pyplot as plt
# for language in cwe_counts.index:
#     if language not in target_languages:
#         continue
#     plt.figure()
#     cwe_counts.loc[language].plot(kind='bar')
#     # Add legend with percentage of commits for each number of CWEs    percentages = cwe_percentage.loc[language]
#     for i, count in enumerate(cwe_counts.loc[language]):
#         num_cwes = cwe_counts.loc[language].index[i]    
#         percentage = cwe_percentage.loc[language].get(num_cwes, 0) * 100
#         plt.text(i, count, f'{percentage:.2f}%', ha='center', va='bottom')
#     plt.title(f'Number of CWEs per commit for {language}')
#     plt.xlabel('Number of CWEs')
#     plt.ylabel('Count of commits')
#     plt.xticks(rotation=0)
#     # plt.show()
#     plt.savefig(f'plots/cwe_count_distribution_{language}.png')

# Plot the number of files and functions modified per commit, for each language
for language in target_languages:
    plt.figure()
    language_df = exploded_df[exploded_df['languages'] == language]
    # Find number with is_multi_file column true 
    num_multi_file = language_df['is_multi_file'].sum()
    num_single_file = len(language_df) - num_multi_file
    plt.bar(['Single file modified', 'Multiple files modified'], [num_single_file, num_multi_file])
    plt.title(f'Number of files modified per commit for {language}')
    plt.xlabel('Number of files modified')
    plt.ylabel('Count of commits')

    # plt.scatter(language_df['num_files_modified'], language_df['num_functions_modified'])
    # plt.title(f'Number of files and functions modified per commit for {language}')
    # plt.xlabel('Number of files modified')
    # plt.ylabel('Number of functions modified')
    # # plt.show()
    plt.savefig(f'plots/files_functions_modified_{language}.png')


# Find the proportion of commits with relationships among their CWEs
print(extracted_df['cwe_relationships'].value_counts())
# relationship_stats = extracted_df['cwe_relationships'].apply(lambda y: y is not None and len(y) > 0)

# Find number of commits with multiple CWEs 
multi_cwe_commits = extracted_df[extracted_df['is_multi_cwe'] == True]
print(f"Number of commits with multiple CWEs: {len(multi_cwe_commits)}")

# Find number of commits with relationships among their CWEs
# They should all be lists but some of them might be empty lists or None, so we check for both cases
relationship_stats = extracted_df['cwe_relationships'].apply(lambda y: isinstance(y, list) and len(y) > 0  or (isinstance(y, str) and len(y) > 0))
print(f"Number of commits with CWE relationships: {relationship_stats.sum()}")
print(extracted_df.info())