"""
Package Resolver for Python packages
Maps package names (from manifests) to import names (from semgrep).
Resolution: static mapping → PyPI wheel download → heuristics.
Only needed for Python - JavaScript package names = import names.
"""

import os
import re
import json
import zipfile
import tempfile
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta

from config import (
    CACHE_DIR, CACHE_FILE, CACHE_DURATION_DAYS, 
    KNOWN_PACKAGE_MAPPINGS, MAX_WHEEL_DOWNLOAD_SIZE
)


class PyPIImportCache:
    """Cache for package → import name mappings."""
    
    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_cache(self):
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass
    
    def get(self, package_name: str) -> Optional[List[str]]:
        key = package_name.lower()
        if key not in self._cache:
            return None
        
        entry = self._cache[key]
        cached_time = datetime.fromisoformat(entry['cached_at'])
        
        if datetime.now() - cached_time > timedelta(days=CACHE_DURATION_DAYS):
            del self._cache[key]
            self._save_cache()
            return None
        
        return entry.get('import_names')
    
    def set(self, package_name: str, import_names: List[str]):
        key = package_name.lower()
        self._cache[key] = {
            'import_names': import_names,
            'cached_at': datetime.now().isoformat()
        }
        self._save_cache()


# Global cache instance
_cache = PyPIImportCache()

# Pre-computed normalized mappings for O(1) lookup (avoid repeated normalization)
_NORMALIZE_RE = re.compile(r'[-_.]+')
_NORMALIZED_MAPPINGS = {
    _NORMALIZE_RE.sub('-', pkg).lower(): imports
    for pkg, imports in KNOWN_PACKAGE_MAPPINGS.items()
}

# =============================================================================
# PYPI RESOLUTION (download wheel → read top_level.txt)
# =============================================================================

def _normalize_package_name(name: str) -> str:
    """Normalize package name for comparison (PEP 503)."""
    return _NORMALIZE_RE.sub('-', name).lower()


def _fetch_wheel_url(package_name: str) -> Optional[str]:
    """
    Fetch the smallest wheel URL from PyPI.
    Args:
        package_name: Package name to fetch
    Returns:
        URL to wheel file, or None if not found
    """
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 404:
            return None
        
        response.raise_for_status()
        data = response.json()
        # Get latest version's files
        urls = data.get('urls', [])
        
        if not urls:
            # Try releases
            releases = data.get('releases', {})
            version = data.get('info', {}).get('version')
            if version and version in releases:
                urls = releases[version]
        
        # Find smallest wheel (prefer py3, any platform)
        wheels = [
            u for u in urls 
            if u.get('packagetype') == 'bdist_wheel'
        ]
        
        if not wheels:
            # No wheels, try source dist
            sdists = [u for u in urls if u.get('packagetype') == 'sdist']
            if sdists:
                return sdists[0].get('url')
            return None
        
        # Sort by size, prefer pure Python wheels
        def wheel_priority(w):
            filename = w.get('filename', '')
            size = w.get('size', float('inf'))
            # Prefer py3-none-any (pure Python)
            if 'py3-none-any' in filename or 'py2.py3-none-any' in filename:
                return (0, size)
            return (1, size)
        
        wheels.sort(key=wheel_priority)
        return wheels[0].get('url')
        
    except Exception:
        return None


def _extract_top_level_from_wheel(wheel_url: str) -> Optional[List[str]]:
    """
    Download wheel and extract top_level.txt.
    Args:
        wheel_url: URL to the wheel file
    Returns:
        List of import names from top_level.txt, or None
    """
    tmp_path = None
    try:
        # Download to temp file
        with tempfile.NamedTemporaryFile(suffix='.whl', delete=False) as tmp:
            tmp_path = tmp.name
            
            response = requests.get(wheel_url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Limit download size
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=8192):
                downloaded += len(chunk)
                if downloaded > MAX_WHEEL_DOWNLOAD_SIZE:
                    tmp.close()
                    return None  # Cleanup in finally block
                tmp.write(chunk)
        # Extract top_level.txt from wheel (it's a ZIP file)
        import_names = []
        
        with zipfile.ZipFile(tmp_path, 'r') as whl:
            # Find top_level.txt in any .dist-info directory
            for name in whl.namelist():
                if name.endswith('top_level.txt'):
                    content = whl.read(name).decode('utf-8')
                    import_names = [
                        line.strip() 
                        for line in content.strip().split('\n')
                        if line.strip()
                    ]
                    break
            
            # If no top_level.txt, try RECORD file to infer packages
            if not import_names:
                for name in whl.namelist():
                    if name.endswith('RECORD'):
                        content = whl.read(name).decode('utf-8')
                        # Parse RECORD to find top-level packages
                        seen = set()
                        for line in content.split('\n'):
                            if '/' in line:
                                top = line.split('/')[0]
                                if top and not top.endswith('.dist-info') and top not in seen:
                                    seen.add(top)
                                    import_names.append(top)
                        break
        
        return import_names if import_names else None
        
    except Exception:
        return None
    finally:
        # Always cleanup temp file (even on error)
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def resolve_from_pypi(package_name: str) -> Optional[List[str]]:
    """
    Resolve package → import names using PyPI.
    
    Flow:
    1. Check cache
    2. Fetch wheel URL from PyPI JSON API
    3. Download smallest wheel
    4. Extract top_level.txt
    5. Cache result and cleanup
    
    Args:
        package_name: PyPI package name
        
    Returns:
        List of import names, or None if resolution failed
    """
    # Check cache first
    cached = _cache.get(package_name)
    if cached is not None:
        return cached
    
    # Fetch wheel URL
    wheel_url = _fetch_wheel_url(package_name)
    if not wheel_url:
        return None
    
    # Extract top_level.txt
    import_names = _extract_top_level_from_wheel(wheel_url)
    
    if import_names:
        # Cache successful result
        _cache.set(package_name, import_names)
        return import_names
    
    return None


# =============================================================================
# HEURISTIC RESOLUTION (fallback)
# =============================================================================

def _heuristic_import_names(package_name: str) -> List[str]:
    """Generate heuristic import names from package name."""
    # Normalize then convert to underscore format (inverse of normalization)
    normalized = _normalize_package_name(package_name)
    base_name = normalized.replace('-', '_')
    names = [base_name]
    
    # Also try first segment for compound packages (google-genai → google)
    if '-' in normalized:
        prefix = normalized.split('-')[0]
        if prefix != base_name:
            names.append(prefix)
    
    return names
# =============================================================================
# MAIN RESOLUTION FUNCTION
# =============================================================================

def resolve_package_imports(package_name: str) -> Tuple[List[str], str]:
    """
    Resolve a PyPI package name to its possible import names.
    Uses 3-tier resolution: static mapping → PyPI wheel → heuristics.
    Args:
        package_name: Package name from manifest (e.g., "scikit-learn")
    Returns:
        Tuple of (list of import names, resolution method)
    """
    # 1. Check static mappings first (O(1) lookup with normalized key)
    normalized = _normalize_package_name(package_name)
    if normalized in _NORMALIZED_MAPPINGS:
        return (_NORMALIZED_MAPPINGS[normalized], "static")
    
    # 2. Try PyPI wheel download (accurate)
    import_names = resolve_from_pypi(package_name)
    if import_names:
        return (import_names, "pypi")
    
    # 3. Fallback to heuristics
    return (_heuristic_import_names(package_name), "heuristic")


# =============================================================================
# PACKAGE COMPARISON & UNUSED DETECTION
# =============================================================================

def _build_import_set(imports_data: List[Dict], is_js: bool = False) -> Set[str]:
    """Build normalized set of imports for comparison."""
    imports_set: Set[str] = set()
    for imp in imports_data:
        pkg = imp.get("package", "")
        if not pkg:
            continue
        imports_set.add(pkg.lower())
        if is_js:
            # Scoped packages: @scope/name → also add 'name'
            if pkg.startswith("@") and "/" in pkg:
                imports_set.add(pkg.split("/")[1].lower())
        else:
            # Python: langchain.agents → also add 'langchain'
            if "." in pkg:
                imports_set.add(pkg.split(".")[0].lower())
    return imports_set

def _check_is_used(pkg: str, import_names: List[str], actual_imports: Set[str], is_js: bool = False) -> bool:
    """Check if a package is used based on import names."""
    # Pre-compute lowercased import names
    import_names_lower = {n.lower() for n in import_names}
    
    # Check if any resolved import matches
    if import_names_lower & actual_imports:
        return True
    if is_js:
        # Check without scope for @scope/name
        if pkg.startswith("@") and "/" in pkg:
            return pkg.split("/")[1].lower() in actual_imports
    else:
        # Python: also check normalized package name
        pkg_normalized = pkg.lower().replace("-", "_")
        if pkg_normalized in actual_imports:
            return True
        # Check partial matches (langchain in langchain_community)
        return any(pkg_normalized in ai.replace("-", "_") for ai in actual_imports)
    
    return False


def _process_language(
    manifest: List[str],
    imports_data: List[Dict],
    language: str,
    result: Dict,
    method_counts: Dict,
    is_js: bool = False
) -> None:
    """Process packages for a single language."""
    actual_imports = _build_import_set(imports_data, is_js)
    
    result["resolution_summary"]["total_manifest_packages"] += len(manifest)
    
    for pkg in manifest:
        if not pkg:
            continue
        
        # Resolve: Python uses 3-tier, JS uses direct
        if is_js:
            import_names = [pkg]
            method = "direct"
        else:
            import_names, method = resolve_package_imports(pkg)
        
        method_counts[method] = method_counts.get(method, 0) + 1
        
        is_used = _check_is_used(pkg, import_names, actual_imports, is_js)
        
        resolved_entry = {
            "package": pkg,
            "language": language,
            "import_names": import_names,
            "resolution_method": method,
            "is_used": is_used
        }
        result["resolved_packages"].append(resolved_entry)
        
        lib_entry = {
            "package": pkg,
            "import_names": import_names,
            "resolution_method": method
        }
        
        if is_used:
            result["used_libraries"][language].append(lib_entry)
            result["resolution_summary"]["total_used"] += 1
        else:
            lib_entry["reason"] = "in manifest, not found in code imports"
            result["unused_libraries"][language].append(lib_entry)
            result["resolution_summary"]["total_unused"] += 1
    
    result["resolution_summary"]["total_resolved"] += len(manifest)

def resolve_and_compare(
    manifest_packages: Dict[str, List[str]],
    semgrep_imports: Dict[str, List[Dict]],
    languages: List[str]
) -> Dict:
    """
    Resolve manifest packages and compare with semgrep imports.
    Tags packages as used or unused.
    
    Args:
        manifest_packages: {python: [...], javascript: [...]}
        semgrep_imports: {python_imports: [...], javascript_imports: [...]}
        languages: Detected languages
    
    Returns:
        {
            resolved_packages: [...],
            used_libraries: {python: [...], javascript: [...]},
            unused_libraries: {python: [...], javascript: [...]},
            resolution_summary: {...}
        }
    """
    result = {
        "resolved_packages": [],
        "used_libraries": {"python": [], "javascript": []},
        "unused_libraries": {"python": [], "javascript": []},
        "resolution_summary": {
            "total_manifest_packages": 0,
            "total_resolved": 0,
            "total_used": 0,
            "total_unused": 0,
            "resolution_methods": {}
        }
    }
    method_counts = {}
    
    if "python" in languages:
        _process_language(
            manifest=manifest_packages.get("python", []),
            imports_data=semgrep_imports.get("python_imports", []),
            language="python",
            result=result,
            method_counts=method_counts,
            is_js=False
        )
    
    if "javascript" in languages:
        _process_language(
            manifest=manifest_packages.get("javascript", []),
            imports_data=semgrep_imports.get("javascript_imports", []),
            language="javascript",
            result=result,
            method_counts=method_counts,
            is_js=True
        )
    
    result["resolution_summary"]["resolution_methods"] = method_counts
    return result
