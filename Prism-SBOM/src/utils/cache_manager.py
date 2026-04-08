"""
Local File-Based Cache Manager for StackSQScanner

Provides caching for:
- OSV vulnerabilities (TTL: 24 hours)
- deps.dev metadata (TTL: 7 days)  
- PyPI metadata (TTL: 7 days) - MINIMIZED format
- NPM metadata (TTL: 7 days) - MINIMIZED format
- Common libraries (pre-populated, no expiry)

Cache Structure:
cache/
├── osv/
│   └── pypi_flask_2.0.1.json
├── depsdev/
│   └── pypi_flask_2.0.1.json
├── pypi/
│   └── flask_2.0.1.json       # Minimized: license, supplier, description, release_date, hashes
├── npm/
│   └── express_4.18.2.json    # Minimized: license, supplier, description, release_date, hashes
└── common/
    └── libraries.json          # Pre-populated common libraries

MINIMIZED FORMAT (only what we need for reports):
{
    "name": "flask",
    "version": "2.0.1",
    "license": "BSD-3-Clause",
    "supplier": "Pallets",
    "description": "A micro web framework",
    "release_date": "2021-05-21T00:00:00Z",
    "homepage": "https://palletsprojects.com/p/flask",
    "hashes": [{"alg": "SHA-256", "content": "abc123..."}]
}
"""

import os
import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps
import threading

# Thread-safe lock for cache operations
_cache_lock = threading.Lock()

# Default TTLs in hours
TTL_OSV = 24  # 24 hours for vulnerabilities
TTL_DEPSDEV = 168  # 7 days for deps.dev metadata
TTL_PYPI = 168  # 7 days for PyPI metadata
TTL_NPM = 168  # 7 days for NPM metadata

# Cache directory (relative to project root)
CACHE_DIR = Path(__file__).parent.parent.parent / "cache"


def _ensure_cache_dir(subdir: str) -> Path:
    """Ensure cache subdirectory exists."""
    cache_path = CACHE_DIR / subdir
    cache_path.mkdir(parents=True, exist_ok=True)
    return cache_path


def _sanitize_key(key: str) -> str:
    """Sanitize cache key to be filesystem-safe."""
    # Replace problematic characters
    safe_key = key.replace("/", "_").replace("\\", "_").replace(":", "_")
    safe_key = safe_key.replace("@", "_").replace(" ", "_")
    # Limit length
    if len(safe_key) > 200:
        # Use hash for long keys
        hash_suffix = hashlib.md5(key.encode()).hexdigest()[:8]
        safe_key = safe_key[:190] + "_" + hash_suffix
    return safe_key


def _get_cache_path(cache_type: str, key: str) -> Path:
    """Get full path to cache file."""
    cache_dir = _ensure_cache_dir(cache_type)
    safe_key = _sanitize_key(key)
    return cache_dir / f"{safe_key}.json"


def _is_cache_valid(cache_path: Path, ttl_hours: int) -> bool:
    """Check if cache file exists and is within TTL."""
    if not cache_path.exists():
        return False
    
    try:
        # Check file modification time
        mtime = cache_path.stat().st_mtime
        age_hours = (time.time() - mtime) / 3600
        return age_hours < ttl_hours
    except Exception:
        return False


def get_cache(cache_type: str, key: str, ttl_hours: int) -> Optional[Dict[str, Any]]:
    """
    Get cached data if valid.
    
    Args:
        cache_type: Type of cache (osv, depsdev, pypi, npm)
        key: Cache key (e.g., "flask_2.0.1")
        ttl_hours: Time-to-live in hours
        
    Returns:
        Cached data or None if not found/expired
    """
    cache_path = _get_cache_path(cache_type, key)
    
    with _cache_lock:
        if not _is_cache_valid(cache_path, ttl_hours):
            return None
        
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("data")
        except Exception:
            return None


def set_cache(cache_type: str, key: str, data: Any) -> bool:
    """
    Store data in cache.
    
    Args:
        cache_type: Type of cache (osv, depsdev, pypi, npm)
        key: Cache key (e.g., "flask_2.0.1")
        data: Data to cache
        
    Returns:
        True if cached successfully
    """
    cache_path = _get_cache_path(cache_type, key)
    
    with _cache_lock:
        try:
            cache_entry = {
                "key": key,
                "cached_at": datetime.utcnow().isoformat() + "Z",
                "data": data
            }
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"[WARN] Failed to cache {cache_type}/{key}: {e}")
            return False


def invalidate_cache(cache_type: str, key: Optional[str] = None) -> int:
    """
    Invalidate cache entries.
    
    Args:
        cache_type: Type of cache (osv, depsdev, pypi, npm)
        key: Specific key to invalidate, or None to invalidate all
        
    Returns:
        Number of entries invalidated
    """
    count = 0
    cache_dir = CACHE_DIR / cache_type
    
    if not cache_dir.exists():
        return 0
    
    with _cache_lock:
        if key:
            # Invalidate specific key
            cache_path = _get_cache_path(cache_type, key)
            if cache_path.exists():
                try:
                    cache_path.unlink()
                    count = 1
                except Exception:
                    pass
        else:
            # Invalidate all in this cache type
            for cache_file in cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                    count += 1
                except Exception:
                    pass
    
    return count


def clear_all_cache() -> Dict[str, int]:
    """
    Clear all cache directories.
    
    Returns:
        Dict with count of cleared entries per cache type
    """
    results = {}
    for cache_type in ["osv", "depsdev", "pypi", "npm"]:
        results[cache_type] = invalidate_cache(cache_type)
    return results


def get_cache_stats() -> Dict[str, Any]:
    """
    Get cache statistics.
    
    Returns:
        Dict with cache statistics
    """
    stats = {
        "cache_dir": str(CACHE_DIR),
        "types": {}
    }
    
    total_size = 0
    total_files = 0
    
    for cache_type in ["osv", "depsdev", "pypi", "npm"]:
        cache_dir = CACHE_DIR / cache_type
        if cache_dir.exists():
            files = list(cache_dir.glob("*.json"))
            size = sum(f.stat().st_size for f in files if f.exists())
            stats["types"][cache_type] = {
                "entries": len(files),
                "size_bytes": size,
                "size_kb": round(size / 1024, 2)
            }
            total_size += size
            total_files += len(files)
        else:
            stats["types"][cache_type] = {
                "entries": 0,
                "size_bytes": 0,
                "size_kb": 0
            }
    
    stats["total_entries"] = total_files
    stats["total_size_bytes"] = total_size
    stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)
    
    return stats


def cleanup_expired_cache() -> Dict[str, int]:
    """
    Remove expired cache entries.
    
    Returns:
        Dict with count of removed entries per cache type
    """
    ttl_map = {
        "osv": TTL_OSV,
        "depsdev": TTL_DEPSDEV,
        "pypi": TTL_PYPI,
        "npm": TTL_NPM
    }
    
    results = {}
    
    for cache_type, ttl_hours in ttl_map.items():
        cache_dir = CACHE_DIR / cache_type
        removed = 0
        
        if cache_dir.exists():
            with _cache_lock:
                for cache_file in cache_dir.glob("*.json"):
                    if not _is_cache_valid(cache_file, ttl_hours):
                        try:
                            cache_file.unlink()
                            removed += 1
                        except Exception:
                            pass
        
        results[cache_type] = removed
    
    return results


# =============================================================================
# HIGH-LEVEL CACHE FUNCTIONS (for specific data types)
# =============================================================================

def get_osv_cache(ecosystem: str, package: str, version: Optional[str] = None) -> Optional[List[Dict]]:
    """Get cached OSV vulnerabilities for a package."""
    key = f"{ecosystem}_{package}"
    if version:
        key += f"_{version}"
    return get_cache("osv", key, TTL_OSV)


def set_osv_cache(ecosystem: str, package: str, vulns: List[Dict], version: Optional[str] = None) -> bool:
    """Cache OSV vulnerabilities for a package."""
    key = f"{ecosystem}_{package}"
    if version:
        key += f"_{version}"
    return set_cache("osv", key, vulns)


def get_depsdev_cache(ecosystem: str, package: str, version: str) -> Optional[Dict]:
    """Get cached deps.dev metadata for a package."""
    key = f"{ecosystem}_{package}_{version}"
    return get_cache("depsdev", key, TTL_DEPSDEV)


def _minimize_depsdev_metadata(raw_meta: Dict, package: str, version: str) -> Dict:
    """
    Minimize raw deps.dev API response to only fields needed for reports.
    
    Fields kept:
    - name, version, license, supplier, description, homepage, dependencies
    """
    if not raw_meta:
        return {}
    
    # deps.dev format varies - extract what we need
    # Handle licenses - can be string, list of strings, or list of dicts
    licenses = raw_meta.get("licenses", [])
    if isinstance(licenses, str):
        license_str = licenses
    elif isinstance(licenses, list) and licenses:
        first_license = licenses[0]
        if isinstance(first_license, dict):
            license_str = first_license.get("license", "NOASSERTION")
        else:
            license_str = str(first_license)
    else:
        license_str = raw_meta.get("license", "NOASSERTION")
    
    # Links/homepage - deps.dev returns links as a LIST of {label, url} objects
    links = raw_meta.get("links", [])
    homepage = ""
    if isinstance(links, list):
        for link in links:
            if isinstance(link, dict):
                label = link.get("label", "")
                url = link.get("url", "")
                if label in ("HOMEPAGE", "SOURCE_REPO") and url:
                    homepage = url
                    break
    elif isinstance(links, dict):
        homepage = links.get("homepage") or links.get("repo") or ""
    
    if not homepage:
        homepage = raw_meta.get("homepage", "")
    
    # Description - deps.dev may have it in different places
    description = raw_meta.get("description") or ""
    
    return {
        "name": package,
        "version": version,
        "license": license_str,
        "homepage": homepage,
        "description": description
    }


def set_depsdev_cache(ecosystem: str, package: str, version: str, metadata: Dict) -> bool:
    """
    Cache deps.dev metadata for a package (MINIMIZED).
    """
    key = f"{ecosystem}_{package}_{version}"
    # Minimize the data before caching
    minimized = _minimize_depsdev_metadata(metadata, package, version)
    return set_cache("depsdev", key, minimized)


def get_pypi_cache(package: str, version: Optional[str] = None) -> Optional[Dict]:
    """Get cached PyPI metadata for a package."""
    key = f"{package}"
    if version:
        key += f"_{version}"
    return get_cache("pypi", key, TTL_PYPI)


def _minimize_pypi_metadata(raw_meta: Dict, package: str, version: Optional[str] = None) -> Dict:
    """
    Minimize raw PyPI API response to only fields needed for reports.
    
    Input: Full PyPI API response (~10-50KB)
    Output: Minimized data with ALL required fields (~1KB)
    
    Fields kept:
    - name, version, license, supplier, description, release_date, homepage, hashes
    - executable, archive, structured_properties (for SBOM reports)
    """
    if not raw_meta:
        return {}
    
    info = raw_meta.get("info", {}) or {}
    target_version = version or info.get("version")
    
    # Extract license (same logic as package_metadata_utils)
    license_str = (info.get("license") or "").strip()
    if not license_str:
        # Try classifiers
        for c in info.get("classifiers", []) or []:
            if "License ::" in c:
                license_str = c.split("::")[-1].strip()
                break
    if not license_str:
        license_str = "NOASSERTION"
    
    # Extract supplier (author/maintainer)
    supplier = info.get("author") or info.get("maintainer") or "Unknown"
    
    # Extract description (summary, not full description)
    description = info.get("summary") or ""
    
    # Extract homepage
    homepage = info.get("home_page") or info.get("project_url") or ""
    if not homepage:
        # Try project_urls
        urls = info.get("project_urls") or {}
        homepage = urls.get("Homepage") or urls.get("homepage") or urls.get("Home") or ""
    
    # Extract release_date
    release_date = ""
    if target_version:
        releases = raw_meta.get("releases", {}).get(target_version, [])
        if releases and isinstance(releases, list):
            for rf in releases:
                rd = rf.get("upload_time_iso_8601") or rf.get("upload_time")
                if rd:
                    release_date = rd
                    break
    # Fallback to urls
    if not release_date:
        urls = raw_meta.get("urls", [])
        if urls:
            release_date = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time") or ""
    
    # Extract hashes (just first SHA-256)
    hashes = []
    for url_info in raw_meta.get("urls", []) or []:
        digests = url_info.get("digests", {}) or {}
        sha256 = digests.get("sha256", "")
        if sha256:
            hashes.append({"alg": "SHA-256", "content": sha256})
            break  # Only first one
    
    # Extract executable property - check for console scripts
    classifiers = info.get("classifiers", []) or []
    has_console = any("Console" in c or "Script" in c for c in classifiers)
    project_urls = info.get("project_urls") or {}
    has_cli_url = any("cli" in str(v).lower() or "command" in str(v).lower() for v in project_urls.values())
    
    if has_console or has_cli_url:
        executable = "Yes - Console scripts/CLI present"
    else:
        executable = "No - Library package (not directly executable)"
    
    # Extract archive format - check available distributions
    archive = "wheel (.whl) / source tarball (.tar.gz)"  # Default
    if target_version:
        releases = raw_meta.get("releases", {}).get(target_version, [])
        if releases:
            formats = set()
            for r in releases:
                filename = r.get("filename", "")
                if filename.endswith(".whl"):
                    formats.add("wheel (.whl)")
                elif filename.endswith(".tar.gz"):
                    formats.add("source tarball (.tar.gz)")
                elif filename.endswith(".zip"):
                    formats.add("source zip (.zip)")
            if formats:
                archive = " / ".join(sorted(formats))
    
    # Extract structured properties
    requires_python = info.get("requires_python")
    if requires_python:
        structured_properties = f"PEP 517/518 compliant, requires Python {requires_python}"
    else:
        structured_properties = "PEP 517/518 compliant (pyproject.toml / setup.py)"
    
    return {
        "name": info.get("name") or package,
        "version": target_version or "",
        "license": license_str,
        "supplier": supplier,
        "description": description,
        "release_date": release_date,
        "homepage": homepage,
        "hashes": hashes,
        "executable": executable,
        "archive": archive,
        "structured_properties": structured_properties
    }


def set_pypi_cache(package: str, metadata: Dict, version: Optional[str] = None) -> bool:
    """
    Cache PyPI metadata for a package (MINIMIZED).
    
    Takes raw PyPI API response and stores only essential fields.
    """
    key = f"{package}"
    if version:
        key += f"_{version}"
    
    # Minimize the data before caching
    minimized = _minimize_pypi_metadata(metadata, package, version)
    return set_cache("pypi", key, minimized)


def get_npm_cache(package: str, version: Optional[str] = None) -> Optional[Dict]:
    """Get cached NPM metadata for a package."""
    key = f"{package}"
    if version:
        key += f"_{version}"
    return get_cache("npm", key, TTL_NPM)


def _minimize_npm_metadata(raw_meta: Dict, package: str, version: Optional[str] = None) -> Dict:
    """
    Minimize raw NPM API response to only fields needed for reports.
    
    Input: Full NPM registry response (can be HUGE - 100KB+)
    Output: Minimized data with ALL required fields (~1KB)
    
    Fields kept:
    - name, version, license, supplier, description, release_date, homepage, hashes
    - executable, archive, structured_properties (for SBOM reports)
    """
    if not raw_meta:
        return {}
    
    # NPM has different structure depending on whether version was specified
    # If version specified: returns that version's data directly
    # If not: returns all versions under "versions" key
    
    target_version = version
    version_data = raw_meta
    
    if "versions" in raw_meta:
        # Full package response - get specific version or latest
        if target_version:
            version_data = raw_meta.get("versions", {}).get(target_version, {})
        else:
            # Get latest
            dist_tags = raw_meta.get("dist-tags", {})
            target_version = dist_tags.get("latest", "")
            if target_version:
                version_data = raw_meta.get("versions", {}).get(target_version, {})
            else:
                version_data = raw_meta
    
    # Extract license
    license_str = version_data.get("license", "")
    if isinstance(license_str, dict):
        license_str = license_str.get("type", "") or license_str.get("name", "")
    if not license_str:
        license_str = raw_meta.get("license", "NOASSERTION")
        if isinstance(license_str, dict):
            license_str = license_str.get("type", "NOASSERTION")
    if not license_str:
        license_str = "NOASSERTION"
    
    # Extract supplier (author)
    author = version_data.get("author") or raw_meta.get("author") or {}
    if isinstance(author, dict):
        supplier = author.get("name", "Unknown")
    elif isinstance(author, str):
        supplier = author
    else:
        supplier = "Unknown"
    
    # Extract description
    description = version_data.get("description") or raw_meta.get("description") or ""
    
    # Extract homepage
    homepage = version_data.get("homepage") or raw_meta.get("homepage") or ""
    
    # Extract release_date
    release_date = ""
    time_data = raw_meta.get("time", {})
    if target_version and time_data:
        release_date = time_data.get(target_version, "")
    
    # Extract hashes
    hashes = []
    dist = version_data.get("dist", {})
    shasum = dist.get("shasum", "")
    if shasum:
        hashes.append({"alg": "SHA-1", "content": shasum})
    integrity = dist.get("integrity", "")
    if integrity and integrity.startswith("sha512-"):
        hashes.append({"alg": "SHA-512", "content": integrity.replace("sha512-", "")})
    
    # Extract executable property - check for bin field
    bin_field = version_data.get("bin")
    if bin_field:
        if isinstance(bin_field, dict):
            bin_names = list(bin_field.keys())
            executable = f"Yes - CLI commands: {', '.join(bin_names[:3])}" + ("..." if len(bin_names) > 3 else "")
        else:
            executable = "Yes - Has executable binary"
    else:
        executable = "No - Library package (not directly executable)"
    
    # Archive format
    archive = "npm tarball (.tgz)"
    
    # Module type from package.json type field
    module_type = version_data.get("type", "commonjs")
    if module_type == "module":
        structured_properties = "ESM module (package.json with type=module)"
    else:
        structured_properties = "CommonJS module (package.json)"
    
    return {
        "name": version_data.get("name") or raw_meta.get("name") or package,
        "version": target_version or version_data.get("version") or "",
        "license": license_str,
        "supplier": supplier,
        "description": description,
        "release_date": release_date,
        "homepage": homepage,
        "hashes": hashes[:1],  # Just keep first hash
        "executable": executable,
        "archive": archive,
        "structured_properties": structured_properties
    }


def set_npm_cache(package: str, metadata: Dict, version: Optional[str] = None) -> bool:
    """
    Cache NPM metadata for a package (MINIMIZED).
    
    Takes raw NPM registry response and stores only essential fields.
    """
    key = f"{package}"
    if version:
        key += f"_{version}"
    
    # Minimize the data before caching
    minimized = _minimize_npm_metadata(metadata, package, version)
    return set_cache("npm", key, minimized)


# =============================================================================
# DECORATOR FOR AUTOMATIC CACHING
# =============================================================================

def cached(cache_type: str, ttl_hours: int, key_func=None):
    """
    Decorator for automatic caching of function results.
    
    Usage:
        @cached("pypi", TTL_PYPI)
        def fetch_pypi_meta(pkg: str, ver: Optional[str] = None):
            ...
    
    Args:
        cache_type: Type of cache
        ttl_hours: TTL in hours
        key_func: Optional function to generate cache key from args
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default: use all args
                key_parts = [str(a) for a in args]
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = "_".join(key_parts)
            
            # Check cache
            cached_data = get_cache(cache_type, cache_key, ttl_hours)
            if cached_data is not None:
                return cached_data
            
            # Call function
            result = func(*args, **kwargs)
            
            # Cache result (only if not None)
            if result is not None:
                set_cache(cache_type, cache_key, result)
            
            return result
        
        return wrapper
    return decorator
