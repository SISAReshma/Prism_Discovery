"""
Crates.io Client for Rust package metadata enrichment.

Provides functions to:
- Fetch crate metadata from crates.io API
- Extract license information
- Get crate details (description, repository, hashes)

crates.io API: https://crates.io/api/v1

Note: crates.io API has rate limiting. Be respectful of limits.
deps.dev is the preferred source for Rust metadata enrichment.
"""

from __future__ import annotations
import requests
from typing import Optional, Dict, Any

from sbom.src.config.config import CRATES_IO_API, API_TIMEOUT
from sbom.src.utils.cache_manager import get_cargo_cache, set_cargo_cache


# Required User-Agent for crates.io API
CRATES_IO_USER_AGENT = "prism-sbom/1.0 (github.com/SISA-Security/prism-sbom)"


def fetch_cargo_meta(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata for a Cargo crate.
    ALWAYS calls the live API first. Cache is ONLY used as fallback on
    rate-limit, timeout, or network error.
    
    Args:
        name: Crate name (e.g., "serde")
        version: Optional specific version
        
    Returns:
        Dict with metadata or None if not found
    """
    if not name:
        return None
    
    try:
        headers = {"User-Agent": CRATES_IO_USER_AGENT}
        
        if version:
            # Get specific version
            url = f"{CRATES_IO_API}/crates/{name}/{version}"
        else:
            # Get latest/crate info
            url = f"{CRATES_IO_API}/crates/{name}"
        
        resp = requests.get(url, headers=headers, timeout=API_TIMEOUT)
        
        if resp.status_code == 404:
            return None
        
        if resp.status_code == 429:
            # Rate limited - fallback to cache
            print(f"[RATE LIMITED] crates.io: {name}@{version} - falling back to cache")
            if version:
                cached = get_cargo_cache(name, version)
                if cached:
                    return cached
            return None
        
        resp.raise_for_status()
        data = resp.json()
        
        # Cache the result for future fallback
        if version:
            set_cargo_cache(name, version, data)
        elif data.get("crate", {}).get("newest_version"):
            # Cache with newest version
            newest = data["crate"]["newest_version"]
            set_cargo_cache(name, newest, data)
        
        return data
        
    except Exception as e:
        print(f"[WARN] crates.io API error for {name}: {e} - falling back to cache")
        # Fallback to cache on error
        if version:
            cached = get_cargo_cache(name, version)
            if cached:
                return cached
        return None


def extract_license_from_cargo_meta(meta: Optional[Dict]) -> str:
    """
    Extract license string from Cargo metadata.
    
    Args:
        meta: Metadata dict from fetch_cargo_meta
        
    Returns:
        License string or "NOASSERTION"
    """
    if not meta:
        return "NOASSERTION"
    
    # Check version data first
    version = meta.get("version", {})
    if version.get("license"):
        return version["license"]
    
    # Check crate data
    crate = meta.get("crate", {})
    if crate.get("license"):
        return crate["license"]
    
    return "NOASSERTION"


def extract_release_date_from_cargo(meta: Optional[Dict]) -> str:
    """
    Extract release date from Cargo metadata.
    
    Args:
        meta: Metadata dict from fetch_cargo_meta
        
    Returns:
        ISO date string or empty string
    """
    if not meta:
        return ""
    
    version = meta.get("version", {})
    created_at = version.get("created_at", "")
    if created_at:
        return created_at
    
    return ""


def extract_checksum_from_cargo(meta: Optional[Dict]) -> str:
    """
    Extract checksum from Cargo metadata.
    
    Args:
        meta: Metadata dict from fetch_cargo_meta
        
    Returns:
        SHA-256 checksum or empty string
    """
    if not meta:
        return ""
    
    version = meta.get("version", {})
    return version.get("checksum", "")


def infer_license_type(license_str: str) -> str:
    """
    Infer component origin (open-source vs commercial) from license.
    
    Args:
        license_str: License identifier (e.g., "MIT", "Apache-2.0")
        
    Returns:
        "open-source" or "third-party"
    """
    if not license_str or license_str.upper() in ("NOASSERTION", "UNKNOWN"):
        return "third-party"
    
    open_source_indicators = [
        "mit", "apache", "bsd", "gpl", "lgpl", "mpl", "isc",
        "unlicense", "cc0", "wtfpl", "zlib", "boost", "0bsd",
        "artistic", "ofl", "public domain"
    ]
    
    lower = license_str.lower()
    for indicator in open_source_indicators:
        if indicator in lower:
            return "open-source"
    
    return "third-party"
