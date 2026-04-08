"""
AIBOM Manifest Parser
Detects languages, finds manifest files, and extracts dependencies.
Simplified version of unified_manifest_parser for the AIBOM API.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set

# Import language configuration from config
from config import EXT_TO_LANG, MANIFEST_FILES

# =============================================================================
# LANGUAGE DETECTION
# =============================================================================


def detect_languages(files: List[str]) -> Set[str]:
    """
    Detect programming languages based on file extensions.
    Returns set of detected language names (e.g., {"python", "javascript"})
    """
    languages = set()
    # Use pre-computed reverse mapping from config for O(1) lookup per file
    for file_path in files:
        ext = Path(file_path).suffix.lower()
        lang = EXT_TO_LANG.get(ext)
        if lang:
            languages.add(lang)
    return languages


# =============================================================================
# MANIFEST DETECTION
# =============================================================================

def find_manifest_files(files: List[str], languages: Set[str]) -> Dict[str, List[str]]:
    """
    Find manifest files for detected languages.
    Returns dict mapping language to list of manifest file paths.
    """
    manifests = {lang: [] for lang in languages}
    
    for file_path in files:
        filename = Path(file_path).name.lower()
        
        for lang in languages:
            manifest_set = MANIFEST_FILES.get(lang)
            if not manifest_set:
                continue
            # Direct O(1) lookup in pre-lowercased frozenset
            if filename in manifest_set:
                manifests[lang].append(file_path)
            # Also check for requirements*.txt pattern (Python only)
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


def parse_setup_py(content: str) -> List[str]:
    """Parse setup.py and extract packages from install_requires (regex-based, no eval)."""
    packages = []
    
    # Find install_requires=[...] or install_requires = [...]
    pattern = r'install_requires\s*=\s*\[([^\]]+)\]'
    matches = re.findall(pattern, content, re.DOTALL)
    
    for match in matches:
        # Extract quoted strings (single or double quotes)
        quoted = re.findall(r'["\']([^"\',]+)["\']', match)
        for dep in quoted:
            dep = dep.strip()
            # Remove version specifiers and extras
            pkg_match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
            if pkg_match:
                packages.append(pkg_match.group(1).lower())
    
    return packages


def parse_setup_cfg(content: str) -> List[str]:
    """Parse setup.cfg and extract packages from [options] install_requires."""
    packages = []
    
    # Find [options] section and extract install_requires
    in_options = False
    in_install_requires = False
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Check for [options] section
        if line.lower() == '[options]':
            in_options = True
            continue
        
        # Check for new section (exit options)
        if in_options and line.startswith('['):
            break
        
        # Check for install_requires key
        if in_options and line.startswith('install_requires'):
            in_install_requires = True
            # Handle inline format: install_requires = package1, package2
            if '=' in line:
                inline = line.split('=', 1)[1].strip()
                if inline:
                    pkg_match = re.match(r'^([a-zA-Z0-9_-]+)', inline)
                    if pkg_match:
                        packages.append(pkg_match.group(1).lower())
            continue
        
        # Parse multi-line install_requires
        if in_install_requires:
            if not line or line.startswith('['):
                in_install_requires = False
                continue
            
            # Extract package name (handle version specifiers)
            pkg_match = re.match(r'^([a-zA-Z0-9_-]+)', line)
            if pkg_match:
                packages.append(pkg_match.group(1).lower())
    
    return packages


def parse_pipfile(content: str) -> List[str]:
    """Parse Pipfile (TOML format) and extract packages from [packages] section."""
    packages = []
    
    # Find [packages] section
    in_packages = False
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Check for [packages] section
        if line == '[packages]':
            in_packages = True
            continue
        
        # Exit on new section
        if in_packages and line.startswith('['):
            break
        
        # Parse package lines: package = "version" or package = {version = "*"}
        if in_packages and line and not line.startswith('#'):
            if '=' in line:
                pkg_name = line.split('=')[0].strip()
                # Validate package name format
                if re.match(r'^[a-zA-Z0-9_-]+$', pkg_name):
                    packages.append(pkg_name.lower())
    
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
        elif filename == "setup.py":
            return parse_setup_py(content)
        elif filename == "setup.cfg":
            return parse_setup_cfg(content)
        elif filename == "pipfile":
            return parse_pipfile(content)
    
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
