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


# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

CACHE_DIR = Path(__file__).parent / ".cache"
CACHE_FILE = CACHE_DIR / "pypi_imports_cache.json"
CACHE_DURATION_DAYS = 7


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


# =============================================================================
# KNOWN STATIC MAPPINGS (fast path)
# =============================================================================

KNOWN_PACKAGE_MAPPINGS = {
    # Google AI packages
    "google-genai": ["google"],
    "google-ai-generativelanguage": ["google"],
    "google-cloud-aiplatform": ["google", "vertexai"],
    "google-cloud-storage": ["google"],
    "google-generativeai": ["google"],
    
    # AI/LLM frameworks
    "openai": ["openai"],
    "anthropic": ["anthropic"],
    "langchain": ["langchain"],
    "langchain-core": ["langchain_core"],
    "langchain-community": ["langchain_community"],
    "langchain-openai": ["langchain_openai"],
    "langchain-anthropic": ["langchain_anthropic"],
    "transformers": ["transformers"],
    "torch": ["torch"],
    "tensorflow": ["tensorflow", "tf"],
    "tensorflow-gpu": ["tensorflow", "tf"],
    
    # Image processing
    "Pillow": ["PIL"],
    "pillow": ["PIL"],
    "opencv-python": ["cv2"],
    "opencv-contrib-python": ["cv2"],
    
    # Machine Learning
    "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"],
    
    # Data science
    "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"],
    "beautifulsoup4": ["bs4"],
    
    # Deep Learning
    "torchvision": ["torchvision"],
    
    # NLP
    "sentence-transformers": ["sentence_transformers"],
    
    # Others
    "PyYAML": ["yaml"],
    "pyyaml": ["yaml"],
    "protobuf": ["google.protobuf"],
}


# =============================================================================
# PYPI RESOLUTION (download wheel → read top_level.txt)
# =============================================================================

def _normalize_package_name(name: str) -> str:
    """Normalize package name for comparison (PEP 503)."""
    return re.sub(r'[-_.]+', '-', name).lower()


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
    try:
        # Download to temp file
        with tempfile.NamedTemporaryFile(suffix='.whl', delete=False) as tmp:
            tmp_path = tmp.name
            
            response = requests.get(wheel_url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Limit download size (10MB max)
            max_size = 10 * 1024 * 1024
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=8192):
                downloaded += len(chunk)
                if downloaded > max_size:
                    tmp.close()
                    os.unlink(tmp_path)
                    return None
                tmp.write(chunk)
        
        # Extract top_level.txt from wheel (it's a ZIP file)
        import_names = []
        
        try:
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
        finally:
            # Cleanup temp file
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        
        return import_names if import_names else None
        
    except Exception:
        return None


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
    names = []
    
    # Base: replace hyphens with underscores
    base_name = package_name.replace('-', '_')
    names.append(base_name)
    
    # Also add original name
    if package_name != base_name:
        names.append(package_name)
    
    # For packages like "google-genai", try "google"
    if '-' in package_name:
        prefix = package_name.split('-')[0]
        if prefix not in names:
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
    # 1. Check static mappings first (fast path)
    if package_name in KNOWN_PACKAGE_MAPPINGS:
        return (KNOWN_PACKAGE_MAPPINGS[package_name], "static")
    
    # Normalize for case-insensitive matching
    normalized = _normalize_package_name(package_name)
    for known_pkg, imports in KNOWN_PACKAGE_MAPPINGS.items():
        if _normalize_package_name(known_pkg) == normalized:
            return (imports, "static")
    
    # 2. Try PyPI wheel download (accurate)
    import_names = resolve_from_pypi(package_name)
    if import_names:
        return (import_names, "pypi")
    
    # 3. Fallback to heuristics
    return (_heuristic_import_names(package_name), "heuristic")


# =============================================================================
# PACKAGE COMPARISON & UNUSED DETECTION
# =============================================================================

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
    
    # ==========================================================================
    # PYTHON: Resolve package → import names, then compare
    # ==========================================================================
    
    if "python" in languages:
        python_manifest = manifest_packages.get("python", [])
        python_imports_data = semgrep_imports.get("python_imports", [])
        
        # Build set of actual imports from semgrep
        actual_imports: Set[str] = set()
        for imp in python_imports_data:
            pkg = imp.get("package", "")
            if pkg:
                actual_imports.add(pkg.lower())
                # Also add base package (e.g., "langchain.agents" → "langchain")
                if "." in pkg:
                    actual_imports.add(pkg.split(".")[0].lower())
        
        result["resolution_summary"]["total_manifest_packages"] += len(python_manifest)
        
        for pkg in python_manifest:
            if not pkg:
                continue
            
            # Resolve package → import names
            import_names, method = resolve_package_imports(pkg)
            method_counts[method] = method_counts.get(method, 0) + 1
            
            resolved_entry = {
                "package": pkg,
                "language": "python",
                "import_names": import_names,
                "resolution_method": method
            }
            
            # Check if any resolved import matches actual imports
            is_used = any(
                imp.lower() in actual_imports or
                actual_imports & {n.lower() for n in import_names}
                for imp in import_names
            )
            
            # More thorough check - also check if package name itself matches
            if not is_used:
                pkg_lower = pkg.lower().replace("-", "_")
                is_used = pkg_lower in actual_imports or any(
                    pkg_lower in ai.replace("-", "_") or ai.replace("-", "_") in pkg_lower
                    for ai in actual_imports
                )
            
            resolved_entry["is_used"] = is_used
            result["resolved_packages"].append(resolved_entry)
            
            if is_used:
                result["used_libraries"]["python"].append({
                    "package": pkg,
                    "import_names": import_names,
                    "resolution_method": method
                })
                result["resolution_summary"]["total_used"] += 1
            else:
                result["unused_libraries"]["python"].append({
                    "package": pkg,
                    "import_names": import_names,
                    "resolution_method": method,
                    "reason": "in manifest, not found in code imports"
                })
                result["resolution_summary"]["total_unused"] += 1
        
        result["resolution_summary"]["total_resolved"] += len(python_manifest)
    
    # ==========================================================================
    # JAVASCRIPT: Direct comparison (package name = import name)
    # ==========================================================================
    
    if "javascript" in languages:
        js_manifest = manifest_packages.get("javascript", [])
        js_imports_data = semgrep_imports.get("javascript_imports", [])
        
        # Build set of actual imports from semgrep
        actual_js_imports: Set[str] = set()
        for imp in js_imports_data:
            pkg = imp.get("package", "")
            if pkg:
                actual_js_imports.add(pkg.lower())
                # For scoped packages, also add without scope
                if pkg.startswith("@") and "/" in pkg:
                    actual_js_imports.add(pkg.split("/")[1].lower())
        
        result["resolution_summary"]["total_manifest_packages"] += len(js_manifest)
        
        for pkg in js_manifest:
            if not pkg:
                continue
            
            method_counts["direct"] = method_counts.get("direct", 0) + 1
            
            resolved_entry = {
                "package": pkg,
                "language": "javascript",
                "import_names": [pkg],  # JS: package = import
                "resolution_method": "direct"
            }
            
            # Direct comparison for JS
            is_used = pkg.lower() in actual_js_imports
            
            # Also check without scope
            if not is_used and pkg.startswith("@") and "/" in pkg:
                is_used = pkg.split("/")[1].lower() in actual_js_imports
            
            resolved_entry["is_used"] = is_used
            result["resolved_packages"].append(resolved_entry)
            
            if is_used:
                result["used_libraries"]["javascript"].append({
                    "package": pkg,
                    "import_names": [pkg],
                    "resolution_method": "direct"
                })
                result["resolution_summary"]["total_used"] += 1
            else:
                result["unused_libraries"]["javascript"].append({
                    "package": pkg,
                    "import_names": [pkg],
                    "resolution_method": "direct",
                    "reason": "in manifest, not found in code imports"
                })
                result["resolution_summary"]["total_unused"] += 1
        
        result["resolution_summary"]["total_resolved"] += len(js_manifest)
    
    result["resolution_summary"]["resolution_methods"] = method_counts
    
    return result
