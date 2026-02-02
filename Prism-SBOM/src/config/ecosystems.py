"""
Centralized ecosystem and language configuration.

This module provides a single source of truth for language→ecosystem mappings.
To add a new language: Just add it to LANGUAGE_TO_ECOSYSTEM and ECOSYSTEM_INFO below.
"""

from typing import Dict, Optional

from src.registry.language_registry import get_language_definitions

# Language → Ecosystem mapping
# CURRENTLY SUPPORTED: Python and JavaScript only
# OSV requires exact ecosystem names: "PyPI", "npm", etc.
# To add new language: Add entries here (e.g., "java": "Maven")
LANGUAGE_TO_ECOSYSTEM = {d.language: d.ecosystem for d in get_language_definitions()}

# Common aliases for language names
ALIAS_MAP = {
    "py": "python",
    "js": "javascript",
    "node": "javascript",
}

# Expand language→ecosystem mapping with aliases
for alias, canonical in ALIAS_MAP.items():
    if canonical in LANGUAGE_TO_ECOSYSTEM:
        LANGUAGE_TO_ECOSYSTEM[alias] = LANGUAGE_TO_ECOSYSTEM[canonical]

# Ecosystem metadata (registry URLs, API endpoints, etc.)
# Keys must match the values in LANGUAGE_TO_ECOSYSTEM (case-sensitive for OSV)
ECOSYSTEM_INFO = {
    "PyPI": {
        "name": "PyPI",
        "registry_url": "https://pypi.org/project/{package}",
        "api_url": "https://pypi.org/pypi/{package}/json",
    },
    "npm": {
        "name": "npm",
        "registry_url": "https://www.npmjs.com/package/{package}",
        "api_url": "https://registry.npmjs.org/{package}",
    },
    "conda": {
        "name": "Conda",
        "registry_url": "https://anaconda.org/conda-forge/{package}",
    },
}


def get_ecosystem(language: str) -> str:
    """
    Get ecosystem name for a given language OR validate an ecosystem name.
    
    Args:
        language: Language name (e.g., "python") or ecosystem name (e.g., "PyPI")
        
    Returns:
        Ecosystem name in OSV format (e.g., "PyPI", "npm")
        Returns "unknown" if not recognized
        
    Examples:
        >>> get_ecosystem("python")
        'PyPI'
        >>> get_ecosystem("pypi")
        'PyPI'
        >>> get_ecosystem("JavaScript")
        'npm'
    """
    if not language:
        return "unknown"
    
    lower = language.lower()
    
    # Check if it's already a valid ecosystem name (normalize to OSV format)
    ecosystem_normalize = {
        "pypi": "PyPI",
        "npm": "npm",
        "conda": "conda"
    }
    if lower in ecosystem_normalize:
        return ecosystem_normalize[lower]
    
    # Otherwise, treat as language name and map to ecosystem
    return LANGUAGE_TO_ECOSYSTEM.get(normalize_language(lower), "unknown")


def get_ecosystem_url(ecosystem: str, package: str) -> Optional[str]:
    """
    Get registry URL for a package in an ecosystem.
    
    Args:
        ecosystem: Ecosystem name (e.g., "PyPI", "npm")
        package: Package name
        
    Returns:
        Registry URL or None if ecosystem not found
        
    Examples:
        >>> get_ecosystem_url("PyPI", "requests")
        'https://pypi.org/project/requests'
        >>> get_ecosystem_url("npm", "express")
        'https://www.npmjs.com/package/express'
    """
    # Try exact match first, then try normalized version
    info = ECOSYSTEM_INFO.get(ecosystem)
    if not info:
        # Try lowercase
        info = ECOSYSTEM_INFO.get(ecosystem.lower())
    if not info or "registry_url" not in info:
        return None
    
    return info["registry_url"].format(package=package)


def normalize_language(language: str) -> str:
    """
    Normalize language name to canonical form.
    
    Args:
        language: Language name (any alias)
        
    Returns:
        Canonical language name
        
    Examples:
        >>> normalize_language("js")
        'javascript'
        >>> normalize_language("py")
        'python'
    """
    lang_lower = language.lower()
    
    # Map aliases to canonical names (only for currently supported languages)
    return ALIAS_MAP.get(lang_lower, language)


def is_supported_language(language: str) -> bool:
    """
    Check if a language is supported.
    
    Args:
        language: Language name
        
    Returns:
        True if supported, False otherwise
    """
    return language.lower() in LANGUAGE_TO_ECOSYSTEM
