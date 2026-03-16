"""
NuGet Client for .NET package metadata enrichment.

Provides functions to:
- Fetch package metadata from NuGet.org API
- Extract license information
- Get package details (description, authors, hashes)

NuGet API: https://api.nuget.org/v3/index.json

Note: NuGet API provides comprehensive metadata.
deps.dev also supports NuGet packages.
"""

from __future__ import annotations
import requests
from typing import Optional, Dict, Any

from sbom.src.config.config import API_TIMEOUT
from sbom.src.utils.cache_manager import get_cache, set_cache

# NuGet API base URL
NUGET_API = "https://api.nuget.org/v3"

# Cache TTL for NuGet metadata (24 hours)
NUGET_CACHE_TTL_HOURS = 24


def _get_nuget_cache(name: str, version: str) -> Optional[Dict[str, Any]]:
    """Get NuGet metadata from cache."""
    key = f"{name.lower()}@{version}" if version else name.lower()
    return get_cache("nuget", key, NUGET_CACHE_TTL_HOURS)


def _set_nuget_cache(name: str, version: str, data: Dict[str, Any]) -> bool:
    """Set NuGet metadata in cache."""
    key = f"{name.lower()}@{version}" if version else name.lower()
    return set_cache("nuget", key, data)


def fetch_nuget_meta(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata for a NuGet package.
    ALWAYS calls the live API first. Cache is ONLY used as fallback on
    rate-limit, timeout, or network error.
    
    Args:
        name: Package name (e.g., "Newtonsoft.Json")
        version: Optional specific version
        
    Returns:
        Dict with metadata or None if not found
    """
    if not name:
        return None
    
    try:
        # NuGet uses lowercase package IDs in URLs
        name_lower = name.lower()
        
        if version:
            # Get specific version metadata
            url = f"{NUGET_API}/registration5-semver1/{name_lower}/{version}.json"
        else:
            # Get package index to find latest
            url = f"{NUGET_API}/registration5-semver1/{name_lower}/index.json"
        
        resp = requests.get(url, timeout=API_TIMEOUT)
        
        if resp.status_code == 404:
            return None
        
        if resp.status_code == 429:
            # Rate limited - fallback to cache
            print(f"[RATE LIMITED] NuGet: {name}@{version} - falling back to cache")
            if version:
                cached = _get_nuget_cache(name, version)
                if cached:
                    return cached
            return None
        
        resp.raise_for_status()
        data = resp.json()
        
        # For version-specific request
        if version:
            catalog_entry = data.get("catalogEntry", data)
            # catalogEntry may be a URL string — resolve it
            if isinstance(catalog_entry, str):
                try:
                    cat_resp = requests.get(catalog_entry, timeout=API_TIMEOUT)
                    cat_resp.raise_for_status()
                    catalog_entry = cat_resp.json()
                except Exception:
                    catalog_entry = data  # fallback to original data
            # Extract hash if available from catalog entry
            hashes = []
            pkg_hash = catalog_entry.get("packageHash", "")
            pkg_hash_alg = catalog_entry.get("packageHashAlgorithm", "SHA512")
            if pkg_hash:
                alg_map = {"SHA512": "SHA-512", "SHA256": "SHA-256", "SHA1": "SHA-1"}
                hashes = [{"alg": alg_map.get(pkg_hash_alg, pkg_hash_alg), "content": pkg_hash}]
            result = {
                "id": catalog_entry.get("id", name),
                "version": catalog_entry.get("version", version),
                "description": catalog_entry.get("description", ""),
                "authors": catalog_entry.get("authors", ""),
                "licenseExpression": catalog_entry.get("licenseExpression", ""),
                "licenseUrl": catalog_entry.get("licenseUrl", ""),
                "projectUrl": catalog_entry.get("projectUrl", ""),
                "tags": catalog_entry.get("tags", []),
                "published": catalog_entry.get("published", ""),
                "deprecation": catalog_entry.get("deprecation", None),
                "listed": catalog_entry.get("listed", True),
                "hashes": hashes,
            }
            # Cache for future fallback
            _set_nuget_cache(name, version, result)
            return result
        
        # For package index, get latest version
        items = data.get("items", [])
        if items:
            # Get the last page (contains latest versions)
            last_page = items[-1]
            page_items = last_page.get("items", [])
            if page_items:
                latest = page_items[-1]
                catalog_entry = latest.get("catalogEntry", {})
                # catalogEntry may be a URL string — resolve it
                if isinstance(catalog_entry, str):
                    try:
                        cat_resp = requests.get(catalog_entry, timeout=API_TIMEOUT)
                        cat_resp.raise_for_status()
                        catalog_entry = cat_resp.json()
                    except Exception:
                        catalog_entry = {}
                # Extract hash if available
                hashes = []
                pkg_hash = catalog_entry.get("packageHash", "")
                pkg_hash_alg = catalog_entry.get("packageHashAlgorithm", "SHA512")
                if pkg_hash:
                    alg_map = {"SHA512": "SHA-512", "SHA256": "SHA-256", "SHA1": "SHA-1"}
                    hashes = [{"alg": alg_map.get(pkg_hash_alg, pkg_hash_alg), "content": pkg_hash}]
                result = {
                    "id": catalog_entry.get("id", name),
                    "version": catalog_entry.get("version", ""),
                    "description": catalog_entry.get("description", ""),
                    "authors": catalog_entry.get("authors", ""),
                    "licenseExpression": catalog_entry.get("licenseExpression", ""),
                    "licenseUrl": catalog_entry.get("licenseUrl", ""),
                    "projectUrl": catalog_entry.get("projectUrl", ""),
                    "tags": catalog_entry.get("tags", []),
                    "published": catalog_entry.get("published", ""),
                    "deprecation": catalog_entry.get("deprecation", None),
                    "listed": catalog_entry.get("listed", True),
                    "hashes": hashes,
                }
                if result.get("version"):
                    _set_nuget_cache(name, result["version"], result)
                return result
        
        return None
        
    except Exception as e:
        print(f"[WARN] NuGet API error for {name}: {e} - falling back to cache")
        # Fallback to cache on error
        if version:
            cached = _get_nuget_cache(name, version)
            if cached:
                return cached
        return None


def extract_license_from_nuget_meta(meta: Optional[Dict]) -> str:
    """
    Extract license string from NuGet metadata.
    
    Args:
        meta: Metadata dict from fetch_nuget_meta
        
    Returns:
        License string or "NOASSERTION"
    """
    if not meta:
        return "NOASSERTION"
    
    # Check license expression first (SPDX)
    license_expr = meta.get("licenseExpression", "")
    if license_expr:
        return license_expr
    
    # Check license URL
    license_url = meta.get("licenseUrl", "")
    if license_url:
        # Try to infer license from URL
        url_lower = license_url.lower()
        if "mit" in url_lower:
            return "MIT"
        elif "apache" in url_lower:
            return "Apache-2.0"
        elif "gpl" in url_lower:
            return "GPL"
        elif "bsd" in url_lower:
            return "BSD"
        elif "ms-pl" in url_lower or "microsoft" in url_lower:
            return "MS-PL"
        return f"See {license_url}"
    
    return "NOASSERTION"


def extract_release_date_from_nuget(meta: Optional[Dict]) -> str:
    """
    Extract release date from NuGet metadata.
    
    Args:
        meta: Metadata dict from fetch_nuget_meta
        
    Returns:
        ISO date string or empty string
    """
    if not meta:
        return ""
    
    published = meta.get("published", "")
    if published:
        return published
    
    return ""


def infer_license_type(license_str: str) -> str:
    """
    Infer component origin (open-source vs commercial) from license.
    
    Args:
        license_str: License identifier
        
    Returns:
        "open-source" or "third-party"
    """
    if not license_str or license_str.upper() in ("NOASSERTION", "UNKNOWN"):
        return "third-party"
    
    open_source_indicators = [
        "mit", "apache", "bsd", "gpl", "lgpl", "mpl", "isc",
        "unlicense", "cc0", "wtfpl", "zlib", "boost", "ms-pl",
        "artistic", "ofl", "public domain"
    ]
    
    lower = license_str.lower()
    for indicator in open_source_indicators:
        if indicator in lower:
            return "open-source"
    
    return "third-party"
