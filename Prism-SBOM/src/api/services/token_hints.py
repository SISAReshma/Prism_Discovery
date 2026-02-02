"""Token-related hint helpers for API responses."""

from __future__ import annotations


def get_token_format_hint(provider: str) -> str:
    if provider == "github":
        return "GitHub tokens start with 'ghp_' or 'github_pat_' and must have 'repo' scope for private repos"
    if provider == "gitlab":
        return "GitLab tokens start with 'glpat-' and must have appropriate scopes"
    if provider == "bitbucket":
        return "Bitbucket tokens are JWT-based and must have repository access"
    return "Unknown provider"


def get_token_troubleshooting_hint(provider: str, error: str) -> str:
    if provider == "github":
        if "scope" in error.lower():
            return "Ensure token has 'repo' scope enabled in GitHub settings"
        if "expired" in error.lower() or "invalid" in error.lower():
            return "Generate a new token from https://github.com/settings/tokens"
    if provider == "gitlab":
        if "invalid" in error.lower():
            return "Generate a new token from https://gitlab.com/-/profile/personal_access_tokens"
    return "Please verify token permissions and try again"
