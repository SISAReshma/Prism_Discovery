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
