import re
from urllib.parse import urlparse, parse_qs

# def get_projet_name_from_url(url):
#     parsed = urlparse(url)
#     path = parsed.path  # e.g., /owner/repo/commit/sha
#     parts = path.strip("/").split("/")
#     if len(parts) >= 2:
#         owner = parts[0]
#         repo = parts[1]
#         return f"{owner}/{repo}"
#     print(f"Could not extract project name from URL: {url}")
#     return None


def get_project_name_from_url(url):
    if not isinstance(url, str) or not url.strip():
        return None
    parsed = urlparse(url)
    
    # Case 1: GitHub-style or /owner/repo/... path
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    
    # Case 2: query parameter ?p=owner/repo.git or .../repo.git
    q = parse_qs(parsed.query).get('p')
    if q:
        # remove .git suffix if present
        repo_path = q[0].rstrip(".git")
        # take last two parts as owner/repo
        repo_parts = repo_path.strip("/").split("/")[-2:]
        if len(repo_parts) == 2:
            return f"{repo_parts[0]}/{repo_parts[1]}"
    
    # fallback
    print(f"Could not extract project name from URL: {url}")
    return None