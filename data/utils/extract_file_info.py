import ast
import os

EXTENSION_TO_LANG = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".cpp": "C++",
    ".cc": "C++",
    ".c": "C",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".go": "Go",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".m": "Objective-C",
    ".scala": "Scala",
    ".pl": "Perl",
    ".sh": "Shell",
    ".r": "R",
    ".hs": "Haskell",
    ".lua": "Lua",
    ".dart": "Dart",
    ".jl": "Julia",
    ".vb": "Visual Basic",
    ".groovy": "Groovy",
    ".sql": "SQL"
}
def infer_language(filename):
    _, ext = os.path.splitext(filename)
    return EXTENSION_TO_LANG.get(ext.lower(), "Unknown")

def extract_file_info(df, column_name, filename_key='filename', nloc_key='nloc_changed'):
    # take one example to detect type
    sample = df[column_name].dropna().iloc[0]

    # if already parsed list/dict
    if isinstance(sample, list):
        return extract_file_info_from_list(df, column_name, filename_key, nloc_key)
    if isinstance(sample, dict):
        return extract_file_info_from_dict(df, column_name, filename_key, nloc_key)

    # if string-encoded
    if isinstance(sample, str):
        parsed = ast.literal_eval(sample)
        if isinstance(parsed, dict):
            return extract_file_info_from_dict(df, column_name, filename_key, nloc_key)
        if isinstance(parsed, list):
            return extract_file_info_from_list_of_dict(df, column_name, filename_key, nloc_key)

    raise ValueError(f"Unsupported file info type: {type(sample)}")

def extract_file_info_from_list_of_dict(df, column_name, filename_key='filename', nloc_key='nloc_changed'):
    df['file_names'] = df[column_name].apply(
        lambda x: [file_info[filename_key] for file_info in ast.literal_eval(x)]
    )
    df['avg_nloc_changed'] = df[column_name].apply(
        lambda x: sum(file_info[nloc_key] for file_info in ast.literal_eval(x)) / len(ast.literal_eval(x)) if len(ast.literal_eval(x)) > 0 else 0
    )
    df['programming_languages'] = df[column_name].apply(
        lambda x: set(infer_language(file_info[filename_key]) for file_info in ast.literal_eval(x))
    )
    return df

# def extract_file_info_from_dict(df, column_name, filename_key='filename', nloc_key='nloc_changed', lang_key='programming_language'):
#     df['file_names'] = df[column_name][filename_key]
#     df['avg_nloc_changed'] = df[column_name][nloc_key]
#     df['programming_languages'] = df[column_name][lang_key]
#     return df
#     # df['avg_nloc_changed'] = df[column_name].apply(
#     #     lambda x: sum(file_info[nloc_key] for file_info in x) / len(x) if len(x) > 0 else 0
#     # )
#     # df['programming_languages'] = df[column_name].apply(
#     #     lambda x: set(file_info[lang_key] for file_info in x)
#     # )
#     # return df
def extract_file_info_from_dict(
    df, column_name, filename_key='filename',
    nloc_key='nloc_changed'
):
    def parse(x):
        try:
            d = ast.literal_eval(x)  # x is "{...}"
        except Exception:
            return None, None, None

        return d.get(filename_key), d.get(nloc_key), infer_language(d.get(filename_key))

    df['file_names'], df['avg_nloc_changed'], df['programming_languages'] = zip(
        *df[column_name].apply(parse)
    )
    return df

def extract_file_info_from_list(df, column_name, filename_key='filename', nloc_key='nloc_changed'):
    df['file_names'] = df[column_name].apply(
        lambda x: [file_info[filename_key] for file_info in x]
    )
    df['avg_nloc_changed'] = df[column_name].apply(
        lambda x: sum(int(file_info[nloc_key]) for file_info in x) / len(x) if len(x) > 0 else 0
    )
    df['programming_languages'] = df[column_name].apply(
        lambda x: set(infer_language(file_info[filename_key]) for file_info in x)
    )
    return df

import ast

def extract_file_info_bigvul(df, column_name='files_changed',
                              filename_key='filename', nloc_key='changes'):
    """
    Extract file information from BigVul's 'files_changed' column.
    Handles strings with multiple dicts separated by '<_**next**_>'.
    """
    
    def parse_cell(cell):
        if not isinstance(cell, str) or not cell.strip():
            return [], 0, set()
        
        # Split the string by the custom delimiter
        chunks = cell.split('<_**next**_>')
        dicts = []
        for chunk in chunks:
            try:
                d = ast.literal_eval(chunk)
                if isinstance(d, dict):
                    dicts.append(d)
            except Exception:
                # Skip invalid chunks
                continue
        
        if not dicts:
            return [], 0, set()
        
        # Extract file names
        file_names = [d[filename_key] for d in dicts if filename_key in d]
        
        # Average nloc / changes
        total_changes = sum(d.get(nloc_key, 0) for d in dicts)
        avg_changes = total_changes / len(dicts) if dicts else 0
        
        # Programming languages
        languages = {infer_language(d[filename_key]) for d in dicts if filename_key in d and d[filename_key]}
        
        return file_names, avg_changes, languages

    # Apply parsing to each row
    df['file_names'], df['avg_nloc_changed'], df['programming_languages'] = zip(
        *df[column_name].apply(parse_cell)
    )
    
    return df
