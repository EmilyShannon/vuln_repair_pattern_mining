def find_repeating_cves(df, cve_column='cve_id'):
    """
    Identify repeating CVE IDs in the DataFrame.

    Args:
        df (pd.DataFrame): The input DataFrame containing CVE IDs.
        cve_column (str): The name of the column containing CVE IDs.

    Returns:
        pd.DataFrame: A DataFrame with repeating CVE IDs and their counts.
    """
    cve_to_commits = {}
    cve_counts = df[cve_column].value_counts()
    repeating_cves = cve_counts[cve_counts > 1]
    for cve_id, count in repeating_cves.items():
        row_for_cve = df[df[cve_column] == cve_id]
        # Check if these correspond to multiple commit hashes
        # # TODO this isn't correct, need the total num of unique commits for this CVE across all rows 
        cve_to_commits[cve_id] = row_for_cve['commit_hash'].unique()

    return repeating_cves.reset_index().rename(columns={'index': cve_column, cve_column: 'count'})