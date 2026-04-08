"""
Log Sanitization Utilities for PrismAIBOM
Centralized utilities to remove sensitive data from log messages.

This module provides:
- URL sanitization (removes embedded credentials)
- Token/PAT redaction
- Session token masking
- General sensitive data sanitization

Usage:
    from core.log_sanitizer import sanitize_url, sanitize_sensitive

    # Sanitize URL before logging
    logger.info("Processing repo", extra={"url": sanitize_url(repo_url)})
    
    # Sanitize any string that might contain sensitive data
    logger.error("Git error", extra={"message": sanitize_sensitive(error_msg, pat=user_pat)})
"""

import re
from typing import Optional
from urllib.parse import urlparse, urlunparse


# =============================================================================
# REGEX PATTERNS FOR SENSITIVE DATA
# =============================================================================

# GitHub PAT patterns (ghp_, gho_, ghu_, ghs_, ghr_)
GITHUB_PAT_PATTERN = re.compile(r'\b(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}\b')

# GitLab tokens (glpat- prefix)
GITLAB_PAT_PATTERN = re.compile(r'\bglpat-[a-zA-Z0-9]{20,}\b')

# Azure DevOps PAT (52-char base64)
AZURE_PAT_PATTERN = re.compile(r'\b[a-z0-9]{52}\b', re.IGNORECASE)

# Bearer tokens in headers
BEARER_TOKEN_PATTERN = re.compile(r'Bearer\s+[a-zA-Z0-9_-]+', re.IGNORECASE)

# Authorization headers
AUTH_HEADER_PATTERN = re.compile(r'Authorization:\s*\S+', re.IGNORECASE)

# Generic API key patterns
API_KEY_PATTERN = re.compile(r'\b(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+', re.IGNORECASE)

# Credentials in URLs (https://user:pass@host)
URL_CREDENTIALS_PATTERN = re.compile(r'https?://[^@:]+(?::[^@]+)?@')

# HuggingFace tokens (hf_)
HF_TOKEN_PATTERN = re.compile(r'\bhf_[a-zA-Z0-9]{30,}\b')

# Groq API keys
GROQ_KEY_PATTERN = re.compile(r'\bgsk_[a-zA-Z0-9]{48,}\b')

# OpenAI API keys
OPENAI_KEY_PATTERN = re.compile(r'\bsk-[a-zA-Z0-9]{32,}\b')

# Generic long alphanumeric tokens (potential secrets)
# Only match if they look like tokens (specific lengths common for tokens)
GENERIC_TOKEN_PATTERN = re.compile(r'\b[a-zA-Z0-9_-]{40,64}\b')

REDACTED = "[REDACTED]"


# =============================================================================
# URL SANITIZATION
# =============================================================================

def sanitize_url(url: str) -> str:
    """
    Remove credentials from a URL for safe logging.
    
    Args:
        url: The URL that may contain embedded credentials
    
    Returns:
        URL with credentials replaced by [REDACTED]
    
    Examples:
        >>> sanitize_url("https://ghp_token123@github.com/owner/repo")
        'https://[REDACTED]@github.com/owner/repo'
        >>> sanitize_url("https://user:password@github.com/owner/repo")
        'https://[REDACTED]@github.com/owner/repo'
        >>> sanitize_url("https://github.com/owner/repo")
        'https://github.com/owner/repo'
    """
    if not url:
        return url
    
    try:
        parsed = urlparse(url)
        
        # Check if URL has username or password
        if parsed.username or parsed.password:
            # Replace credentials with REDACTED
            # netloc format: user:pass@host:port
            if parsed.port:
                sanitized_netloc = f"{REDACTED}@{parsed.hostname}:{parsed.port}"
            else:
                sanitized_netloc = f"{REDACTED}@{parsed.hostname}"
            
            sanitized = parsed._replace(netloc=sanitized_netloc)
            return urlunparse(sanitized)
        
        return url
    except Exception:
        # If parsing fails, try regex-based sanitization
        return URL_CREDENTIALS_PATTERN.sub(f'https://{REDACTED}@', url)


def extract_repo_identifier(url: str) -> str:
    """
    Extract just the owner/repo part from a Git URL for logging.
    
    Args:
        url: Full repository URL
    
    Returns:
        Just the owner/repo portion (safe for logging)
    
    Examples:
        >>> extract_repo_identifier("https://github.com/owner/repo")
        'owner/repo'
        >>> extract_repo_identifier("https://token@github.com/owner/repo.git")
        'owner/repo'
    """
    if not url:
        return ""
    
    try:
        # Remove .git suffix
        url = url.rstrip('.git')
        
        # Parse URL
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        
        # For GitHub/GitLab style URLs, path is owner/repo
        parts = path.split('/')
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        
        return path or "[unknown]"
    except Exception:
        return "[parse-error]"


# =============================================================================
# TOKEN AND CREDENTIAL SANITIZATION
# =============================================================================

def sanitize_token(value: str, token: Optional[str] = None) -> str:
    """
    Mask a specific token or truncate for logging.
    
    Args:
        value: The string that may contain the token
        token: Optional specific token to redact
    
    Returns:
        String with token replaced or masked
    """
    if not value:
        return value
    
    result = value
    
    # Replace specific token if provided
    if token:
        result = result.replace(token, REDACTED)
    
    return result


def mask_session_token(token: str) -> str:
    """
    Mask a session token for logging (show first/last 4 chars).
    
    Args:
        token: Full session token
    
    Returns:
        Masked token like "abcd...wxyz"
    """
    if not token or len(token) < 12:
        return REDACTED
    
    return f"{token[:4]}...{token[-4:]}"


# =============================================================================
# COMPREHENSIVE SANITIZATION
# =============================================================================

def sanitize_sensitive(
    text: str,
    pat: Optional[str] = None,
    extra_tokens: Optional[list] = None
) -> str:
    """
    Comprehensively sanitize a string by removing all sensitive data patterns.
    
    Args:
        text: The text to sanitize
        pat: Optional specific PAT token to redact
        extra_tokens: Optional list of additional tokens to redact
    
    Returns:
        Sanitized text with all sensitive data replaced by [REDACTED]
    
    This function sanitizes:
    - Explicit PAT if provided
    - GitHub PAT patterns (ghp_, gho_, ghu_, ghs_, ghr_)
    - GitLab PAT patterns (glpat-)
    - HuggingFace tokens (hf_)
    - Groq API keys (gsk_)
    - OpenAI API keys (sk-)
    - Bearer tokens
    - Authorization headers
    - Credentials in URLs
    - API key patterns
    """
    if not text:
        return text
    
    result = text
    
    # First, redact explicitly provided tokens
    if pat:
        result = result.replace(pat, REDACTED)
    
    if extra_tokens:
        for token in extra_tokens:
            if token:
                result = result.replace(token, REDACTED)
    
    # Apply regex patterns
    patterns = [
        (GITHUB_PAT_PATTERN, REDACTED),
        (GITLAB_PAT_PATTERN, REDACTED),
        (HF_TOKEN_PATTERN, REDACTED),
        (GROQ_KEY_PATTERN, REDACTED),
        (OPENAI_KEY_PATTERN, REDACTED),
        (BEARER_TOKEN_PATTERN, f'Bearer {REDACTED}'),
        (AUTH_HEADER_PATTERN, f'Authorization: {REDACTED}'),
        (URL_CREDENTIALS_PATTERN, f'https://{REDACTED}@'),
        (API_KEY_PATTERN, f'api_key: {REDACTED}'),
    ]
    
    for pattern, replacement in patterns:
        result = pattern.sub(replacement, result)
    
    return result


def sanitize_dict(
    data: dict,
    sensitive_keys: Optional[set] = None,
    pat: Optional[str] = None
) -> dict:
    """
    Sanitize a dictionary by redacting values of sensitive keys.
    
    Args:
        data: Dictionary to sanitize
        sensitive_keys: Set of key names to redact (case-insensitive)
        pat: Optional specific PAT to redact from all string values
    
    Returns:
        New dictionary with sensitive values redacted
    """
    if not data:
        return data
    
    # Default sensitive key names
    default_sensitive = {
        'pat', 'token', 'password', 'secret', 'api_key', 'apikey',
        'access_token', 'auth', 'authorization', 'credential',
        'private_key', 'secret_key', 'hf_token', 'groq_api_key'
    }
    
    keys_to_redact = sensitive_keys or default_sensitive
    
    result = {}
    for key, value in data.items():
        lower_key = key.lower()
        
        if any(sensitive in lower_key for sensitive in keys_to_redact):
            result[key] = REDACTED
        elif isinstance(value, str):
            result[key] = sanitize_sensitive(value, pat=pat)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value, sensitive_keys, pat)
        else:
            result[key] = value
    
    return result


# =============================================================================
# LOGGING HELPER
# =============================================================================

def safe_log_context(**kwargs) -> dict:
    """
    Create a safe logging context by sanitizing all values.
    
    Usage:
        logger.info("Processing", extra=safe_log_context(url=repo_url, token=session_token))
    
    Args:
        **kwargs: Key-value pairs for logging context
    
    Returns:
        Dictionary safe for logging (all sensitive data redacted)
    """
    pat = kwargs.pop('_pat', None)  # Special key for PAT to redact
    
    result = {}
    for key, value in kwargs.items():
        if value is None:
            result[key] = None
        elif isinstance(value, str):
            # Check if key name suggests sensitive data
            lower_key = key.lower()
            if any(s in lower_key for s in ['token', 'pat', 'key', 'secret', 'password', 'auth']):
                if lower_key == 'session_token':
                    result[key] = mask_session_token(value)
                else:
                    result[key] = REDACTED
            elif 'url' in lower_key:
                result[key] = sanitize_url(value)
            else:
                result[key] = sanitize_sensitive(value, pat=pat)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value, pat=pat)
        else:
            result[key] = value
    
    return result
