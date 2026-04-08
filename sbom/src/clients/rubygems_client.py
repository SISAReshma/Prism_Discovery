"""
RubyGems Client for Ruby package metadata enrichment.

Provides functions to:
- Fetch package metadata from RubyGems.org API
- Extract license information
- Get package details (description, authors, hashes)

RubyGems API: https://rubygems.org/api/v1

Note: deps.dev supports RubyGems and is the primary source.
This client serves as fallback when deps.dev fails.
"""

from __future__ import annotations
import requests
from typing import Optional, Dict, Any

from sbom.src.config.config import RUBYGEMS_API, API_TIMEOUT
from sbom.src.utils.cache_manager import get_rubygems_cache, set_rubygems_cache


def fetch_rubygems_meta(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata for a RubyGems package.
    ALWAYS calls the live API first. Cache is ONLY used as fallback on
    rate-limit, timeout, or network error.
    
    Args:
        name: Gem name (e.g., "rails")
        version: Optional specific version
        
    Returns:
        Dict with metadata or None if not found
    """
    if not name:
        return None
    
    try:
        if version:
            # Get specific version metadata
            url = f"{RUBYGEMS_API}/versions/{name}.json"
            resp = requests.get(url, timeout=API_TIMEOUT)
            
            if resp.status_code == 404:
                return None
            
            if resp.status_code == 429:
                # Rate limited - fallback to cache
                print(f"[RATE LIMITED] RubyGems: {name}@{version} - falling back to cache")
                cached = get_rubygems_cache(name, version)
                if cached:
                    return cached
                return None
            
            resp.raise_for_status()
            versions = resp.json()
            
            # Find the specific version
            for v in versions:
                if v.get("number") == version:
                    gem_url = f"{RUBYGEMS_API}/gems/{name}.json"
                    gem_resp = requests.get(gem_url, timeout=API_TIMEOUT)
                    if gem_resp.status_code == 200:
                        gem_data = gem_resp.json()
                        gem_data["version_info"] = v
                        # Cache for future fallback
                        set_rubygems_cache(name, version, gem_data)
                        return gem_data
                    return v
            
            return None
        else:
            # Get latest version metadata
            url = f"{RUBYGEMS_API}/gems/{name}.json"
            resp = requests.get(url, timeout=API_TIMEOUT)
            
            if resp.status_code == 404:
                return None
            
            if resp.status_code == 429:
                # Rate limited - no version to look up in cache
                print(f"[RATE LIMITED] RubyGems: {name} - falling back to cache")
                return None
            
            resp.raise_for_status()
            data = resp.json()
            
            # Cache for future fallback
            if data.get("version"):
                set_rubygems_cache(name, data["version"], data)
            
            return data
        
    except Exception as e:
        print(f"[WARN] RubyGems API error for {name}: {e} - falling back to cache")
        # Fallback to cache on error
        if version:
            cached = get_rubygems_cache(name, version)
            if cached:
                return cached
        return None


def extract_license_from_rubygems_meta(meta: Optional[Dict]) -> str:
    """Extract license string from RubyGems metadata."""
    if not meta:
        return "NOASSERTION"
    
    licenses = meta.get("licenses", [])
    if licenses:
        if isinstance(licenses, list):
            return " AND ".join(licenses) if len(licenses) > 1 else licenses[0]
        return str(licenses)
    
    license_str = meta.get("license", "")
    if license_str:
        return license_str
    
    return "NOASSERTION"


def extract_release_date_from_rubygems(meta: Optional[Dict]) -> str:
    """Extract release date from RubyGems metadata."""
    if not meta:
        return ""
    
    version_info = meta.get("version_info", {})
    if version_info.get("created_at"):
        return version_info["created_at"]
    
    if meta.get("built_at"):
        return meta["built_at"]
    
    if meta.get("version_created_at"):
        return meta["version_created_at"]
    
    return ""


def extract_sha256_from_rubygems(meta: Optional[Dict]) -> str:
    """Extract SHA256 hash from RubyGems metadata."""
    if not meta:
        return ""
    
    version_info = meta.get("version_info", {})
    if version_info.get("sha"):
        return version_info["sha"]
    
    if meta.get("sha"):
        return meta["sha"]
    
    return ""


def infer_license_type(license_str: str) -> str:
    """Infer component origin (open-source vs commercial) from license."""
    if not license_str or license_str.upper() in ("NOASSERTION", "UNKNOWN"):
        return "third-party"
    
    open_source_indicators = [
        "mit", "apache", "bsd", "gpl", "lgpl", "mpl", "isc",
        "unlicense", "cc0", "wtfpl", "zlib", "boost", "ruby",
        "artistic", "ofl", "public domain", "rails"
    ]
    
    lower = license_str.lower()
    for indicator in open_source_indicators:
        if indicator in lower:
            return "open-source"
    
    return "third-party"
