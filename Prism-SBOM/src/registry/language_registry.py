"""
Language registry for catalogers and manifest detection.

Single source of truth for:
- Supported languages
- Manifest file names
- Cataloger classes
- PURL / deps.dev ecosystem mapping
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Iterable
import importlib
import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LanguageDefinition:
    language: str
    ecosystem: str  # OSV ecosystem name (case-sensitive where applicable)
    purl_type: str  # PURL / deps.dev ecosystem name (lowercase)
    manifest_files: List[str]
    cataloger: Optional[str] = None  # import path "module.Class"


LANGUAGE_REGISTRY: List[LanguageDefinition] = [
    LanguageDefinition(
        language="python",
        ecosystem="PyPI",
        purl_type="pypi",
        manifest_files=["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock", "poetry.lock"],
        cataloger="src.catalogers.python_cataloger.PythonCataloger",
    ),
    LanguageDefinition(
        language="javascript",
        ecosystem="npm",
        purl_type="npm",
        manifest_files=["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        cataloger="src.catalogers.npm_cataloger.NpmCataloger",
    ),
    LanguageDefinition(
        language="conda",
        ecosystem="conda",
        purl_type="conda",
        manifest_files=["environment.yml", "environment.yaml", "conda.yml", "conda.yaml"],
        cataloger="src.catalogers.conda_cataloger.CondaCataloger",
    ),
]


def get_language_definitions() -> List[LanguageDefinition]:
    return list(LANGUAGE_REGISTRY)


def get_supported_manifest_files() -> Dict[str, List[str]]:
    return {lang.language: list(lang.manifest_files) for lang in LANGUAGE_REGISTRY}


def get_all_manifest_files() -> List[str]:
    files: List[str] = []
    for lang in LANGUAGE_REGISTRY:
        files.extend(lang.manifest_files)
    return files


def get_language_for_manifest(filename: str) -> Optional[str]:
    name = filename.lower()
    for lang in LANGUAGE_REGISTRY:
        if name in [f.lower() for f in lang.manifest_files]:
            return lang.language
    return None


def get_purl_type(language: str) -> str:
    lang = (language or "").lower()
    for entry in LANGUAGE_REGISTRY:
        if entry.language.lower() == lang:
            return entry.purl_type
    return lang or "unknown"


# Alias map for common language name variations
ALIAS_MAP = {
    "py": "python",
    "js": "javascript",
    "node": "javascript",
    "npm": "javascript",
}


def get_ecosystem(language: str) -> str:
    """
    Get OSV ecosystem name for a given language.
    
    Args:
        language: Language name (e.g., "python", "py", "javascript", "js")
                  or ecosystem name (e.g., "PyPI", "npm")
        
    Returns:
        Ecosystem name in OSV format (e.g., "PyPI", "npm")
        Returns "unknown" if not recognized
        
    Examples:
        >>> get_ecosystem("python")
        'PyPI'
        >>> get_ecosystem("pypi")
        'PyPI'
        >>> get_ecosystem("js")
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
    
    # Resolve aliases first
    canonical = ALIAS_MAP.get(lower, lower)
    
    # Find in registry
    for entry in LANGUAGE_REGISTRY:
        if entry.language.lower() == canonical:
            return entry.ecosystem
    
    return "unknown"


def get_language_to_ecosystem_map() -> Dict[str, str]:
    """
    Get a dictionary mapping language names to ecosystem names.
    
    Returns:
        Dict like {"python": "PyPI", "javascript": "npm", ...}
    """
    mapping = {entry.language: entry.ecosystem for entry in LANGUAGE_REGISTRY}
    # Add aliases
    for alias, canonical in ALIAS_MAP.items():
        if canonical in mapping:
            mapping[alias] = mapping[canonical]
    return mapping


def get_cataloger_instances() -> List[object]:
    catalogers: List[object] = []
    for entry in LANGUAGE_REGISTRY:
        if not entry.cataloger:
            continue
        try:
            module_path, class_name = entry.cataloger.rsplit(".", 1)
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            catalogers.append(cls())
        except Exception as exc:
            logger.warning("Failed to load cataloger %s: %s", entry.cataloger, exc)
    return catalogers


def iter_manifest_patterns() -> Iterable[str]:
    for entry in LANGUAGE_REGISTRY:
        for name in entry.manifest_files:
            yield name
