# File: src/utils/git_utils.py
import subprocess
from pathlib import Path
import shutil
import os
import re
import urllib.parse
import requests
from typing import Optional
from src.utils.file_utils import cleanup_workspace

def _scrub(msg: str, token: Optional[str] = None) -> str:
    if not token:
        return msg
    return msg.replace(token, "*****")

def _parse_git_provider(repo_url: str):
    """
    Parse repo host and owner/repo path for common providers (github, gitlab, azure).
    Returns (provider, api_base, owner, repo) or (None, None, None, None) if unknown.
    """
    try:
        u = urllib.parse.urlparse(repo_url)
    except Exception:
        return None, None, None, None
    host = u.netloc.lower()
    path = u.path.strip("/")
    # Support https://github.com/owner/repo(.git) and git@github.com:owner/repo.git
    if host.endswith("github.com"):
        # path could be like owner/repo or owner/repo.git
        parts = path.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1].replace(".git", "")
            return "github", "https://api.github.com", owner, repo
    if host.endswith("gitlab.com"):
        parts = path.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1].replace(".git", "")
            # GitLab API uses project path form
            return "gitlab", "https://gitlab.com/api/v4", owner, repo
    # Azure DevOps: urls like dev.azure.com/org/project/_git/repo OR org@dev.azure.com:project/_git/repo
    if "dev.azure.com" in host or host.endswith("visualstudio.com"):
        # Azure APIs are more complex; return azure and let code handle best-effort
        return "azure", "https://dev.azure.com", None, path
    return None, None, None, None

def _github_repo_info(owner: str, repo: str, token: Optional[str] = None):
    api = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    resp = requests.get(api, headers=headers, timeout=10)
    return resp

def probe_repo_access(repo: str, token: Optional[str] = None) -> str:
    """
    Heuristic to determine repo visibility:
      - 'public' (anonymous access possible)
      - 'private' (exists but requires auth)
      - 'auth_required' (needs auth)
      - 'ok' (auth validated)
      - 'not_found' (404)
      - 'network_error' (couldn't reach remote)
      - 'auth_failed' (token rejected)
      - 'unknown' (fallback)
    The function uses git ls-remote + platform API where available (Github/GitLab/Azure) for reliability.
    """
    # 1) Quick git ls-remote attempt (anonymous)
    try:
        res = subprocess.run(["git", "ls-remote", repo], capture_output=True, text=True, timeout=15)
        if res.returncode == 0:
            # ls-remote succeeded — repository may be public or allow anonymous read
            # but this alone is not sufficient to claim public for GitHub private repos in some mirror setups.
            maybe_public = True
        else:
            maybe_public = False
            stderr = (res.stderr or "").lower()
            if "authentication required" in stderr or "access denied" in stderr or "fatal: could not read" in stderr or "403" in stderr:
                # likely needs auth
                maybe_public = False
    except Exception:
        maybe_public = False

    # 2) If provider is GitHub/GitLab/Azure, use API to confirm visibility
    provider, api_base, owner, repo_name = _parse_git_provider(repo)
    if provider == "github" and owner and repo_name:
        # First try unauthenticated API to see if repo exists publicly
        try:
            resp_anon = _github_repo_info(owner, repo_name, token=None)
            if resp_anon.status_code == 200:
                # public repo
                return "public"
            if resp_anon.status_code == 404:
                # might be private or not found. If token provided, validate token and request again
                if token:
                    resp_auth = _github_repo_info(owner, repo_name, token=token)
                    if resp_auth.status_code == 200:
                        # repository exists and is private (or auth revealed details)
                        return "private" if resp_auth.json().get("private") else "public"
                    elif resp_auth.status_code in (401, 403):
                        return "auth_failed"
                    elif resp_auth.status_code == 404:
                        return "not_found"
                    else:
                        return "unknown"
                else:
                    # no token: likely private or not found
                    return "auth_required"
            # other statuses: fallback to git behavior
        except requests.RequestException:
            # network issues - but we can fall back to git behavior
            pass

    # If provider is GitLab, attempt API call pattern
    if provider == "gitlab" and owner and repo_name:
        try:
            # GitLab public projects endpoint (URL-encoded path)
            proj = f"{owner}/{repo_name}"
            url = f"https://gitlab.com/api/v4/projects/{urllib.parse.quote(proj, safe='')}"
            headers = {}
            if token:
                headers["PRIVATE-TOKEN"] = token
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                # project visible; check 'visibility' in response
                vis = resp.json().get("visibility") or ""
                if vis == "public":
                    return "public"
                else:
                    return "private"
            if resp.status_code == 404:
                return "auth_required" if not token else "not_found"
        except requests.RequestException:
            pass

    # azure: best-effort - if ls-remote worked, treat as ok; otherwise unknown
    if provider == "azure":
        if maybe_public:
            return "public"
        else:
            return "auth_required"

    # Fallback logic based on ls-remote
    if maybe_public:
        return "public"
    else:
        # if we couldn't access anonymously, request auth required
        return "auth_required"

def verify_pat(repo: str, token: str, username: Optional[str] = None) -> str:
    """
    Verify token by attempting a shallow authenticated ls-remote or platform API call.
    Returns:
      - "ok" if token works and repo accessible
      - "auth_failed" if token invalid or insufficient
      - "not_found" if repo not found even with token
      - "unknown" on network/other errors
    """
    if not token:
        return "no_token"

    provider, api_base, owner, repo_name = _parse_git_provider(repo)

    # Prefer provider API validation (GitHub/GitLab)
    if provider == "github" and owner and repo_name:
        try:
            resp = _github_repo_info(owner, repo_name, token=token)
            if resp.status_code == 200:
                return "ok"
            if resp.status_code in (401, 403):
                return "auth_failed"
            if resp.status_code == 404:
                return "not_found"
            return "unknown"
        except requests.RequestException:
            return "unknown"

    if provider == "gitlab" and owner and repo_name:
        try:
            proj = f"{owner}/{repo_name}"
            url = f"https://gitlab.com/api/v4/projects/{urllib.parse.quote(proj, safe='')}"
            headers = {"PRIVATE-TOKEN": token}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return "ok"
            if resp.status_code == 401 or resp.status_code == 403:
                return "auth_failed"
            if resp.status_code == 404:
                return "not_found"
            return "unknown"
        except requests.RequestException:
            return "unknown"

    # Generic fallback: attempt an authenticated git ls-remote using token in HTTPS URL
    try:
        if repo.startswith("https://"):
            cred = username or "x-access-token"
            proto, rest = repo.split("://", 1)
            auth_repo = f"{proto}://{cred}:{token}@{rest}"
            res = subprocess.run(["git", "ls-remote", auth_repo], capture_output=True, text=True, timeout=20)
            if res.returncode == 0:
                return "ok"
            stderr = (res.stderr or "").lower()
            if "unauthorized" in stderr or "403" in stderr or "authentication required" in stderr:
                return "auth_failed"
            if "Repository not found" in stderr or res.returncode == 128:
                return "not_found"
            return "unknown"
        else:
            # can't easily embed token for SSH/GIT protocol fallback to unknown
            return "unknown"
    except Exception:
        return "unknown"

def git_clone(repo: str, dst: Path, token: Optional[str] = None, username: Optional[str] = None):
    """
    Clone into dst. If token provided and repo is https, try using token in URL.
    """
    dst = Path(dst)
    if dst.exists() and any(dst.iterdir()):
        # Use the robust cleanup function instead of simple rmtree
        print(f"   -> Cleaning existing directory: {dst}")
        cleanup_workspace(dst, "", dst.parent)
        dst.mkdir(parents=True, exist_ok=True)
    
    if token and repo.startswith("https://"):
        cred = username or "x-access-token"
        proto, rest = repo.split("://", 1)
        auth_repo = f"{proto}://{cred}:{token}@{rest}"
        cmd = ["git", "clone", "--depth", "1", auth_repo, str(dst)]
    else:
        cmd = ["git", "clone", "--depth", "1", repo, str(dst)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        out = (res.stdout or "") + (res.stderr or "")
        raise RuntimeError(_scrub(f"git clone failed: {out}", token))
    return str(dst)
