import requests
import time
import json
import os
import re
from tree_sitter_languages import get_parser
from urllib.parse import urlparse, parse_qs

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

TOKEN = os.getenv('GITHUB_TOKEN') # GitHub token from environment variable

def infer_language(filename):
    _, ext = os.path.splitext(filename)
    return EXTENSION_TO_LANG.get(ext.lower(), "Unknown")

def get_parser_for_lang(lang):
    try:
        return get_parser(lang)
    except:
        return None

def get_commit_info_for_file(commit_url, file_path):
    # TODO refactor common code 
    time.sleep(1)  # to respect rate limits
    api_url = commit_url.replace("https://github.com/", "https://api.github.com/repos/")
    api_url = api_url.replace("/commit/", "/commits/")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if TOKEN:
        headers["Authorization"] = f"token {TOKEN}"
    try:
        r = requests.get(api_url, headers=headers, timeout=10)
        if r.status_code == 403:
            print(f"Rate limit hit or forbidden: {api_url}")
            # time.sleep(60)  # wait a minute and continue
            return 0, 0, 0
        elif r.status_code != 200:
            print(f"Warning: {r.status_code} for {api_url}")
            return 0, 0, 0

        data = r.json()
        for f in data.get('files', []):
            print(f"Checking file {f['filename']} against {file_path}")
            if f['filename'] == file_path:
                print(f"Found file {file_path} in commit {commit_url}")
                additions = f['additions']
                deletions = f['deletions']
                changes = f['changes']
                patch = f.get('patch', '')
                print(f"File {file_path} in commit {commit_url}: changes={changes}, additions={additions}, deletions={deletions}")
                return changes, additions, deletions, patch
        return 0, 0, 0  # file not found in commit
    except requests.exceptions.Timeout:
        print(f"Timeout for {api_url}")
        return 0, 0, 0
    except json.JSONDecodeError:
        print(f"Invalid JSON for {api_url}")
        return 0, 0, 0
    except Exception as e:
        print(f"Error for {api_url}: {e}")
        return 0, 0, 0
    finally:
        time.sleep(0.1) 

def get_changed_lines_from_patch(patch):

    changed_lines = []

    if not patch:
        return changed_lines

    new_line = None

    for line in patch.split("\n"):

        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                new_line = int(m.group(1))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            changed_lines.append(new_line)

        if not line.startswith("-"):
            new_line += 1

    return changed_lines

def get_changed_files(commit_url):
    time.sleep(0.1)
    api_url = commit_url.replace("https://github.com/", "https://api.github.com/repos/")
    api_url = api_url.replace("/commit/", "/commits/")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if TOKEN:
        headers["Authorization"] = f"TOKEN {TOKEN}"
    try:
        r = requests.get(api_url, headers=headers, timeout=10)
        if r.status_code == 403:
            print(f"Rate limit hit or forbidden: {api_url}")
            # time.sleep(60)  # wait a minute and continue
            return []
        elif r.status_code != 200:
            print(f"Warning: {r.status_code} for {api_url}")
            return []

        data = r.json()
        additions = data['stats']['additions']
        deletions = data['stats']['deletions']
        total_changes = data['stats']['total']
        languages = []
        for f in data.get('files', []):
            lang = infer_language(f['filename'])
            if lang not in languages:
                languages.append(lang)
        # total_loc = 0
        # languages = []
        # for f in data.get('files', []):
        #     r = requests.get(f["raw_url"], headers=headers)
        #     loc = len([line for line in r.text.splitlines() if line.strip()])
        #     total_loc += loc
        #     lang = infer_language(f['filename'])
        #     languages.append(lang)
        return [f['filename'] for f in data.get('files', [])], languages, total_changes, additions, deletions
    except requests.exceptions.Timeout:
        print(f"Timeout for {api_url}")
        return []
    except json.JSONDecodeError:
        print(f"Invalid JSON for {api_url}")
        return []
    except Exception as e:
        print(f"Error for {api_url}: {e}")
        return []
    finally:
        time.sleep(1) 
def normalize_url(url):
    if not url.startswith("http"):
        return "https://" + url
    return url

def fetch_changed_files(df, commit_url_column, max_iters=100):
    df["changed_files"] = None  # Initialize the column
    df["nloc"] = None  # Initialize the column
    df["languages"] = None  # Initialize the column
    # df_sample = df.sample(n=max_iters)
    # i = 0
    for index, row in df.iterrows():
        time.sleep(1)
        # if i >= max_iters:
        #     print("Reached maximum iterations")
        #     break
        url = normalize_url(row[commit_url_column])
        if "github.com" not in url:
            print(f"Skipping non-GitHub URL: {url}")
            # df.drop(index, inplace=True)
            continue
        try:
            changed_files, languages, n_total, n_added, n_deleted = get_changed_files(url)
            print(f"Changed files for {url}: {changed_files}")
            # Add them to the existing df
            if changed_files != []: 
                df.at[index, 'changed_files'] = changed_files
                df.at[index, 'nloc'] = n_total
                df.at[index, 'languages'] = languages
            else: 
                continue
                # df = df.drop(index, inplace=True)
        except Exception as e:
            print(f"Error fetching changed files for {url}: {e}")
            continue
            # df = df.drop(index, inplace=True)
        # i += 1
    return df

def get_commit_hash(commit_url):
    time.sleep(1)
    api_url = commit_url.replace("https://github.com/", "https://api.github.com/repos/")
    api_url = api_url.replace("/commit/", "/commits/")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if TOKEN:
        headers["Authorization"] = f"token {TOKEN}"

    r = requests.get(api_url, headers=headers)
    if r.status_code != 200:
        print(f"Warning: {r.status_code} for {api_url}")
        return []
    data = r.json()
    return data['sha']

def fetch_commit_hash(df, commit_url_column, max_iters=25):
    df["commit_hash"] = None  # Initialize the column
    df["repo_name"] = None  # Initialize the column
    for index, row in df.iterrows():
        url = normalize_url(row[commit_url_column])
        try:
            hash = get_commit_hash(url, TOKEN)
            print(f"Commit hash for {url}: {hash}")
            # Add them to the existing df
            df.at[index, 'commit_hash'] = hash
            repo_name = '/'.join(url.split('/')[3:5])
        except Exception as e:
            print(f"Error fetching commit hash for {url}: {e}")
            df.at[index, 'commit_hash'] = hash
    return df
    
# def extract_repo_and_hash(commit_url):
#     match = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)", commit_url)
#     if match:
#         owner, repo, commit_hash = match.groups()
#         full_repo_name = f"{owner}/{repo}"
#         return full_repo_name, commit_hash
#     else:
#         print(f"Could not extract repo and hash from URL: {commit_url}")
#         return None, None
    
def extract_repo_and_hash(commit_url):

    # GitHub
    m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)", commit_url)
    if m:
        owner, repo, commit_hash = m.groups()
        return f"{owner}/{repo}", commit_hash

    # GitLab
    m = re.search(r"gitlab\.com/([^/]+)/([^/]+)/-/commit/([a-f0-9]+)", commit_url)
    if m:
        owner, repo, commit_hash = m.groups()
        return f"{owner}/{repo}", commit_hash

    # Bitbucket
    m = re.search(r"bitbucket\.org/([^/]+)/([^/]+)/commits/([a-f0-9]+)", commit_url)
    if m:
        owner, repo, commit_hash = m.groups()
        return f"{owner}/{repo}", commit_hash

    # libssh style
    m = re.search(r"id=([a-f0-9]+)", commit_url)
    if m:
        commit_hash = m.group(1)
        return None, commit_hash

    # gitweb (OpenSSL etc)
    parsed = urlparse(commit_url)
    query = parse_qs(parsed.query)

    if "h" in query:
        commit_hash = query["h"][0]
        return None, commit_hash

    print(f"Could not extract repo and hash from URL: {commit_url}")
    return None, None

def fetch_file(repo, file_path, commit_hash):

    url = f"https://raw.githubusercontent.com/{repo}/{commit_hash}/{file_path}"

    r = requests.get(url)

    if r.status_code != 200:
        print("Failed:", url)
        return None

    return r.text

def get_all_repo_and_hash(df, commit_url_column, max_iters=100):
    df["repo_name"] = None
    df["commit_hash"] = None
    # df_sample = df.sample(n=max_iters)
    # i = 0
    for index, row in df.iterrows():
        # if i >= max_iters:
        #     print("Reached maximum iterations")
        #     break
        url = normalize_url(row[commit_url_column])
        repo_name, commit_hash = extract_repo_and_hash(url)
        df.at[index, 'repo_name'] = repo_name
        df.at[index, 'commit_hash'] = commit_hash
        # i += 1
    return df

def compute_loc_from_patch(patch: str):
    additions = 0
    deletions = 0
    if not patch:
        return 0, 0, 0
    for line in patch.splitlines():
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue  # skip patch metadata
        elif line.startswith('+'):
            additions += 1
        elif line.startswith('-'):
            deletions += 1
    total = additions + deletions
    return additions, deletions, total
