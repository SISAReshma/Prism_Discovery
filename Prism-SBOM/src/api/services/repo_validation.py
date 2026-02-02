"""Repository validation helpers for API endpoints."""

from __future__ import annotations

from typing import Optional, Tuple, Dict
from urllib.parse import urlparse, quote
import re

import requests

from src.config.config import SUPPORTED_PROVIDERS


def validate_url_format(url: str) -> Tuple[bool, str]:
    """
    Validate URL format.
    Returns: (is_valid, error_message)
    """
    if not url or not url.strip():
        return False, "repository_url is required"

    url = url.strip()

    # Check if it's a valid URL format
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    if not re.match(url_pattern, url):
        return False, "Invalid URL format. Please provide a valid URL (e.g., https://github.com/owner/repo)"

    # Check if it's a supported provider
    provider_found = False
    for provider in SUPPORTED_PROVIDERS:
        if provider in url.lower():
            provider_found = True
            break

    if not provider_found:
        return False, "Unsupported repository provider. Supported: GitHub, GitLab, Bitbucket"

    # Check repository path format (owner/repo)
    path_pattern = r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)/[\w\-\.]+/[\w\-\.]+/?"
    if not re.match(path_pattern, url, re.IGNORECASE):
        return False, "Invalid repository path. URL should be in format: https://github.com/owner/repo"

    return True, ""


def get_provider_from_url(url: str) -> str:
    """Get provider name from URL"""
    if "github.com" in url.lower():
        return "github"
    if "gitlab.com" in url.lower():
        return "gitlab"
    if "bitbucket.org" in url.lower():
        return "bitbucket"
    return "unknown"


def extract_repo_name(url: str) -> str:
    """Extract repository name from URL"""
    parts = url.rstrip("/").split("/")
    return parts[-1].replace(".git", "") if parts else "unknown"


def extract_owner_repo(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract owner and repo from URL"""
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1].replace(".git", "")
            return owner, repo
    except Exception:
        pass
    return None, None


def check_github_owner_exists(owner: str, headers: dict) -> bool:
    """
    Check if a GitHub user/organization exists.
    This helps differentiate between typos and private repos.
    """
    try:
        user_url = f"https://api.github.com/users/{owner}"
        response = requests.get(user_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return True

        org_url = f"https://api.github.com/orgs/{owner}"
        response = requests.get(org_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return True

        return False
    except Exception:
        return True


def check_github_repo(url: str, token: str = None, rate_limiter=None) -> Dict:
    """
    Check GitHub repository accessibility with rate limiting.
    Returns: {"accessible": bool, "is_private": bool, "error": str or None, "repo_info": dict or None, "rate_limit_warning": str or None}
    """
    owner, repo = extract_owner_repo(url)
    if not owner or not repo:
        return {"accessible": False, "is_private": False, "error": "Invalid GitHub URL format", "repo_info": None}

    # Check rate limit before making request
    rate_limit_warning = None
    if rate_limiter:
        usage = rate_limiter.get_current_usage("github")
        if usage["percentage"] >= 80:
            rate_limit_warning = (
                f"Warning: GitHub API rate limit at {usage['percentage']:.0f}% ({usage['remaining']} calls remaining). Consider providing a token."
            )

        if usage["remaining"] <= 0:
            return {
                "accessible": False,
                "is_private": False,
                "error": f"GitHub API rate limit exceeded. Resets in {usage['reset_in']} seconds. Please provide a token using /set_token to increase limit.",
                "repo_info": None,
                "rate_limit_warning": rate_limit_warning,
            }

        # Record this API call
        rate_limiter.record_call("github")

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github.v3+json"}

    if token:
        headers["Authorization"] = f"token {token}"

    try:
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            result = {
                "accessible": True,
                "is_private": data.get("private", False),
                "error": None,
                "repo_info": {
                    "full_name": data.get("full_name"),
                    "description": data.get("description"),
                    "default_branch": data.get("default_branch"),
                    "language": data.get("language"),
                    "private": data.get("private", False),
                },
            }
            if rate_limit_warning:
                result["rate_limit_warning"] = rate_limit_warning
            return result
        if response.status_code == 404:
            # Check if owner exists to differentiate typos from private repos
            if rate_limiter:
                rate_limiter.record_call("github")
            owner_exists = check_github_owner_exists(owner, {"Accept": "application/vnd.github.v3+json"})

            if not owner_exists:
                result = {
                    "accessible": False,
                    "is_private": False,
                    "error": f"GitHub user or organization '{owner}' not found. Please check the spelling",
                    "repo_info": None,
                }
                if rate_limit_warning:
                    result["rate_limit_warning"] = rate_limit_warning
                return result

            if token:
                result = {
                    "accessible": False,
                    "is_private": False,
                    "error": (
                        f"Repository '{owner}/{repo}' not found or token lacks access. "
                        "Please verify: 1) Repository exists, 2) Token has 'repo' scope, 3) Token is from the correct GitHub account"
                    ),
                    "repo_info": None,
                }
            else:
                result = {
                    "accessible": False,
                    "is_private": True,
                    "error": f"Repository '{owner}/{repo}' is private or does not exist. If private, provide token using /set_token",
                    "repo_info": None,
                }
            if rate_limit_warning:
                result["rate_limit_warning"] = rate_limit_warning
            return result
        if response.status_code == 401:
            return {"accessible": False, "is_private": True, "error": "Token is invalid or expired. Please generate a new token", "repo_info": None}
        if response.status_code == 403:
            if "rate limit" in response.text.lower():
                return {
                    "accessible": False,
                    "is_private": False,
                    "error": "GitHub API rate limit exceeded. Please try again later or provide token using /set_token",
                    "repo_info": None,
                }
            return {
                "accessible": False,
                "is_private": True,
                "error": "Token does not have required permissions. Please ensure 'repo' scope is enabled",
                "repo_info": None,
            }
        return {"accessible": False, "is_private": False, "error": f"GitHub API error: {response.status_code}", "repo_info": None}

    except requests.exceptions.Timeout:
        return {"accessible": False, "is_private": False, "error": "Request timed out. Please try again", "repo_info": None}
    except requests.exceptions.ConnectionError:
        return {"accessible": False, "is_private": False, "error": "Unable to connect to repository. Please check your internet connection", "repo_info": None}
    except Exception as e:
        return {"accessible": False, "is_private": False, "error": f"Network error: {str(e)}", "repo_info": None}


def check_gitlab_repo(url: str, token: str = None) -> Dict:
    """Check GitLab repository accessibility."""
    try:
        parsed = urlparse(url)
        path = parsed.path.strip("/").replace(".git", "")
        if not path:
            return {"accessible": False, "is_private": False, "error": "Invalid GitLab URL format", "repo_info": None}
    except Exception:
        return {"accessible": False, "is_private": False, "error": "Invalid GitLab URL format", "repo_info": None}

    api_url = f"https://gitlab.com/api/v4/projects/{quote(path, safe='')}"
    headers = {}

    if token:
        headers["PRIVATE-TOKEN"] = token

    try:
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            return {
                "accessible": True,
                "is_private": data.get("visibility") == "private",
                "error": None,
                "repo_info": {
                    "full_name": data.get("path_with_namespace"),
                    "description": data.get("description"),
                    "default_branch": data.get("default_branch"),
                    "private": data.get("visibility") == "private",
                },
            }
        if response.status_code == 404:
            if token:
                return {"accessible": False, "is_private": True, "error": "Repository not found. Please check the URL", "repo_info": None}
            return {"accessible": False, "is_private": True, "error": "Repository is private. Please provide token using /set_token", "repo_info": None}
        if response.status_code == 401:
            return {"accessible": False, "is_private": True, "error": "Token is invalid or expired. Please generate a new token", "repo_info": None}
        return {"accessible": False, "is_private": False, "error": f"GitLab API error: {response.status_code}", "repo_info": None}

    except requests.exceptions.Timeout:
        return {"accessible": False, "is_private": False, "error": "Request timed out. Please try again", "repo_info": None}
    except requests.exceptions.ConnectionError:
        return {"accessible": False, "is_private": False, "error": "Unable to connect to repository. Please check your internet connection", "repo_info": None}
    except Exception as e:
        return {"accessible": False, "is_private": False, "error": f"Network error: {str(e)}", "repo_info": None}


def check_bitbucket_repo(url: str, token: str = None) -> Dict:
    """Check Bitbucket repository accessibility."""
    owner, repo = extract_owner_repo(url)
    if not owner or not repo:
        return {"accessible": False, "is_private": False, "error": "Invalid Bitbucket URL format", "repo_info": None}

    api_url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}"
    headers = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            return {
                "accessible": True,
                "is_private": data.get("is_private", False),
                "error": None,
                "repo_info": {
                    "full_name": data.get("full_name"),
                    "description": data.get("description"),
                    "private": data.get("is_private", False),
                },
            }
        if response.status_code == 404:
            if token:
                return {"accessible": False, "is_private": True, "error": "Repository not found. Please check the URL", "repo_info": None}
            return {"accessible": False, "is_private": True, "error": "Repository is private. Please provide token using /set_token", "repo_info": None}
        if response.status_code == 401:
            return {"accessible": False, "is_private": True, "error": "Token is invalid or expired. Please generate a new token", "repo_info": None}
        return {"accessible": False, "is_private": False, "error": f"Bitbucket API error: {response.status_code}", "repo_info": None}

    except requests.exceptions.Timeout:
        return {"accessible": False, "is_private": False, "error": "Request timed out. Please try again", "repo_info": None}
    except requests.exceptions.ConnectionError:
        return {"accessible": False, "is_private": False, "error": "Unable to connect to repository. Please check your internet connection", "repo_info": None}
    except Exception as e:
        return {"accessible": False, "is_private": False, "error": f"Network error: {str(e)}", "repo_info": None}


def check_repository(url: str, token: str = None, rate_limiter=None) -> Dict:
    """Check repository accessibility based on provider."""
    provider = get_provider_from_url(url)

    if provider == "github":
        return check_github_repo(url, token, rate_limiter=rate_limiter)
    if provider == "gitlab":
        return check_gitlab_repo(url, token)
    if provider == "bitbucket":
        return check_bitbucket_repo(url, token)
    return {"accessible": False, "is_private": False, "error": "Unsupported provider", "repo_info": None}


def validate_token_format(token: str, provider: str) -> Tuple[bool, str]:
    """
    Validate token format based on provider.
    Returns: (is_valid, error_message)
    """
    if not token or not token.strip():
        return False, "token is required"

    token = token.strip()

    if provider == "github":
        valid_prefixes = ["ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"]
        if not any(token.startswith(prefix) for prefix in valid_prefixes):
            return False, "Invalid GitHub token format. GitHub tokens start with 'ghp_' or 'github_pat_'"
        if len(token) < 40:
            return False, "Token is too short (minimum 40 characters)"
    elif provider == "gitlab":
        if not token.startswith("glpat-"):
            return False, "Invalid GitLab token format. GitLab tokens start with 'glpat-'"

    return True, ""
