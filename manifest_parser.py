"""
AIBOM Manifest Parser
Detects languages, finds manifest files, and extracts dependencies.
Simplified version of unified_manifest_parser for the AIBOM API.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Optional


# =============================================================================
# LANGUAGE DETECTION
# =============================================================================

# File extensions for each language
LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyx", ".pyi", ".ipynb"},
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
}


def detect_languages(files: List[str]) -> Set[str]:
    """
    Detect programming languages based on file extensions.
    
    Returns set of detected language names (e.g., {"python", "javascript"})
    """
    languages = set()
    
    for file_path in files:
        ext = Path(file_path).suffix.lower()
        for lang, extensions in LANGUAGE_EXTENSIONS.items():
            if ext in extensions:
                languages.add(lang)
    
    return languages


# =============================================================================
# MANIFEST DETECTION
# =============================================================================

# Manifest files for each language
MANIFEST_FILES = {
    "python": {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
    },
    "javascript": {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    },
}


def find_manifest_files(files: List[str], languages: Set[str]) -> Dict[str, List[str]]:
    """
    Find manifest files for detected languages.
    
    Returns dict mapping language to list of manifest file paths.
    """
    manifests = {lang: [] for lang in languages}
    
    for file_path in files:
        filename = Path(file_path).name.lower()
        
        for lang in languages:
            if lang in MANIFEST_FILES:
                # Direct match
                if filename in {m.lower() for m in MANIFEST_FILES[lang]}:
                    manifests[lang].append(file_path)
                # Also check for requirements*.txt pattern
                elif lang == "python" and filename.startswith("requirements") and filename.endswith(".txt"):
                    manifests[lang].append(file_path)
    
    return manifests


# =============================================================================
# DEPENDENCY EXTRACTION
# =============================================================================

def parse_requirements_txt(content: str) -> List[str]:
    """Parse requirements.txt format and extract package names."""
    packages = []
    
    for line in content.strip().split("\n"):
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        
        # Remove version specifiers and extras
        # Handles: package, package==1.0, package>=1.0, package[extra]>=1.0
        match = re.match(r'^([a-zA-Z0-9_-]+)', line)
        if match:
            packages.append(match.group(1).lower())
    
    return packages


def parse_pyproject_toml(content: str) -> List[str]:
    """Parse pyproject.toml and extract dependencies."""
    packages = []
    
    # Simple regex-based parsing for dependencies
    # Look for dependencies = [...] or dependencies = [...]
    dep_pattern = r'dependencies\s*=\s*\[(.*?)\]'
    matches = re.findall(dep_pattern, content, re.DOTALL)
    
    for match in matches:
        # Extract quoted strings
        quoted = re.findall(r'["\']([^"\']+)["\']', match)
        for dep in quoted:
            # Remove version specifiers
            pkg_match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
            if pkg_match:
                packages.append(pkg_match.group(1).lower())
    
    return packages


def parse_package_json(content: str) -> List[str]:
    """Parse package.json and extract dependencies."""
    packages = []
    
    try:
        data = json.loads(content)
        
        # Get both dependencies and devDependencies
        for key in ["dependencies", "devDependencies", "peerDependencies"]:
            deps = data.get(key, {})
            if isinstance(deps, dict):
                packages.extend(deps.keys())
    except json.JSONDecodeError:
        pass
    
    return packages


def parse_manifest(checkout_path: Path, manifest_path: str, language: str) -> List[str]:
    """Parse a single manifest file and extract package names."""
    full_path = checkout_path / manifest_path
    
    if not full_path.exists():
        return []
    
    try:
        content = full_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    
    filename = Path(manifest_path).name.lower()
    
    if language == "python":
        if "requirements" in filename and filename.endswith(".txt"):
            return parse_requirements_txt(content)
        elif filename == "pyproject.toml":
            return parse_pyproject_toml(content)
        # TODO: Add setup.py, Pipfile parsing if needed
    
    elif language == "javascript":
        if filename == "package.json":
            return parse_package_json(content)
    
    return []


def extract_dependencies(checkout_path: Path, manifests: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Extract all dependencies from found manifest files.
    
    Returns dict mapping language to sorted list of unique package names.
    """
    all_deps = {}
    
    for lang, manifest_paths in manifests.items():
        deps = []
        for manifest_path in manifest_paths:
            parsed = parse_manifest(checkout_path, manifest_path, lang)
            deps.extend(parsed)
        
        # Remove duplicates and sort
        all_deps[lang] = sorted(set(deps))
    
    return all_deps


# =============================================================================
# COMBINED FUNCTION
# =============================================================================

def analyze_packages(checkout_path: Path, files: List[str]) -> dict:
    """
    Complete package analysis: detect languages, find manifests, extract dependencies.
    
    Returns combined result with all package information.
    """
    # 1. Detect languages
    languages = detect_languages(files)
    
    # 2. Find manifest files
    manifests = find_manifest_files(files, languages)
    
    # 3. Extract dependencies
    dependencies = extract_dependencies(checkout_path, manifests)
    
    return {
        "languages_detected": sorted(languages),
        "manifests_found": {
            "python": manifests.get("python", []),
            "javascript": manifests.get("javascript", []),
        },
        "dependencies": {
            "python": dependencies.get("python", []),
            "javascript": dependencies.get("javascript", []),
        },
        "summary": {
            "total_languages": len(languages),
            "total_manifests": sum(len(m) for m in manifests.values()),
            "total_dependencies": sum(len(d) for d in dependencies.values()),
        }
    }
