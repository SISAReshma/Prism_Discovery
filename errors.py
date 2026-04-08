"""
AIBOM Error Handlers
Unified error handling for all API endpoints
"""

from fastapi import HTTPException


# =============================================================================
# UNIFIED ERROR RAISER
# =============================================================================

def raise_error(
    code: str,
    message: str,
    status: int = 400,
    hint: str = None,
    **extra
):
    """
    Unified error raising function.
    All other error functions use this internally.
    """
    detail = {"error": code, "message": message}
    if hint:
        detail["hint"] = hint
    detail.update(extra)
    raise HTTPException(status_code=status, detail=detail)


# =============================================================================
# VALIDATION ERRORS (400)
# =============================================================================

def raise_validation_error(code: str, message: str, hint: str = None):
    """Raise a 400 validation error for invalid input"""
    raise_error(code, message, status=400, hint=hint)


# =============================================================================
# UPLOAD ERRORS
# =============================================================================

def raise_upload_error(code: str, message: str, status: int = 400, hint: str = None):
    """Raise an upload-related error"""
    raise_error(code, message, status=status, hint=hint)


# =============================================================================
# GITHUB API ERRORS
# =============================================================================

# Error code mappings for GitHub API
_GITHUB_API_ERRORS = {
    # Connection errors
    "connection_timeout": (503, "GITHUB_UNREACHABLE", "Unable to connect to GitHub (timeout)"),
    "connection_failed": (503, "GITHUB_UNREACHABLE", "Unable to connect to GitHub"),
    "request_error": (503, "GITHUB_UNREACHABLE", "GitHub request failed"),
    
    # Auth errors
    "invalid_pat": (401, "INVALID_PAT", "Personal Access Token is invalid or expired"),
    "invalid_pat_format": (401, "INVALID_PAT_FORMAT", "PAT format is invalid (should start with ghp_)"),
    
    # Access errors
    "rate_limited": (429, "RATE_LIMITED", "GitHub API rate limit exceeded"),
    "access_forbidden": (403, "ACCESS_DENIED", "Access denied to this repository"),
}


def raise_api_error(error_code: str, owner: str = "", repo: str = ""):
    """
    Convert GitHub API error codes to HTTPException.
    Reusable across any endpoint that calls GitHub API.
    """
    if error_code == "not_found":
        raise_error("REPO_NOT_FOUND", f"Repository '{owner}/{repo}' not found", status=404)
    
    if error_code in _GITHUB_API_ERRORS:
        status, code, msg = _GITHUB_API_ERRORS[error_code]
        raise_error(code, msg, status=status)
    
    # Unknown API error
    if error_code and error_code.startswith("github_api_error_"):
        raise_error("GITHUB_API_ERROR", f"GitHub API error: {error_code}", status=502)


# =============================================================================
# GIT CLONE ERRORS
# =============================================================================

# Error code mappings for git clone
_CLONE_ERRORS = {
    "GIT_NOT_INSTALLED": (500, "GIT_NOT_INSTALLED", "Git is not installed on server"),
    "CLONE_TIMEOUT": (504, "CLONE_TIMEOUT", "Clone timed out (>2 minutes)"),
    "CLONE_AUTH_FAILED": (401, "CLONE_AUTH_FAILED", "Authentication failed during clone"),
    "CLONE_PERMISSION_DENIED": (403, "CLONE_PERMISSION_DENIED", "Permission denied during clone"),
    "CLONE_REPO_NOT_FOUND": (404, "CLONE_REPO_NOT_FOUND", "Repository not found during clone"),
}


def raise_clone_error(error_msg: str):
    """
    Convert clone error messages to HTTPException.
    Reusable across any endpoint that clones repos.
    """
    for key, (status, code, msg) in _CLONE_ERRORS.items():
        if key in error_msg:
            raise_error(code, msg, status=status)
    
    # Generic clone error
    raise_error("CLONE_FAILED", error_msg[:200], status=500)
