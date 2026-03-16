"""
Packagist API Client

Fetches package metadata from packagist.org for PHP/Composer packages.
API Documentation: https://packagist.org/apidoc

Endpoints:
- Package info: https://repo.packagist.org/p2/{vendor}/{package}.json
- Search: https://packagist.org/search.json?q={query}
"""

from __future__ import annotations

import logging
import requests
from typing import Any, Dict, List, Optional

from sbom.src.config import config
from sbom.src.utils.cache_manager import get_packagist_cache, set_packagist_cache

logger = logging.getLogger(__name__)

# Request timeout
TIMEOUT = 10


def fetch_packagist_meta(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch package metadata from Packagist.
    ALWAYS calls the live API first. Cache is ONLY used as fallback on
    rate-limit, timeout, or network error.
    
    Args:
        name: Package name in format "vendor/package"
        version: Optional specific version
        
    Returns:
        Package metadata dict or None
    """
    if not name or "/" not in name:
        return None

    cache_version = version or "latest"

    try:
        # Packagist API v2 endpoint
        api_url = f"{config.PACKAGIST_API}/p2/{name}.json"
        
        response = requests.get(api_url, timeout=TIMEOUT)
        
        if response.status_code == 429:
            # Rate limited - fallback to cache
            logger.warning(f"[RATE LIMITED] Packagist: {name}@{version} - falling back to cache")
            cached = get_packagist_cache(name, cache_version)
            if cached is not None:
                return cached
            return None
        
        response.raise_for_status()
        
        data = response.json()
        
        # Extract package data
        packages = data.get("packages", {}).get(name, [])
        if not packages:
            return None

        # If version specified, find that version
        if version:
            for pkg in packages:
                pkg_version = pkg.get("version", "").lstrip("v")
                if pkg_version == version or pkg_version == version.lstrip("v"):
                    # Cache for future fallback
                    set_packagist_cache(name, version, pkg)
                    return pkg
            logger.debug(f"Version {version} not found for {name}, returning latest")

        # Return first (latest) version
        result = packages[0] if packages else None
        if result:
            # Cache for future fallback
            set_packagist_cache(name, cache_version, result)
        return result

    except requests.exceptions.RequestException as e:
        logger.warning(f"Error fetching Packagist metadata for {name}: {e} - falling back to cache")
        # Fallback to cache on error
        cached = get_packagist_cache(name, cache_version)
        if cached is not None:
            return cached
        return None
    except Exception as e:
        logger.warning(f"Unexpected error fetching Packagist metadata: {e} - falling back to cache")
        # Fallback to cache on error
        cached = get_packagist_cache(name, cache_version)
        if cached is not None:
            return cached
        return None


def extract_license_from_packagist_meta(meta: Dict[str, Any]) -> str:
    """Extract license from Packagist metadata."""
    if not meta:
        return "NOASSERTION"

    licenses = meta.get("license", [])
    
    if isinstance(licenses, list) and licenses:
        return licenses[0]
    elif isinstance(licenses, str):
        return licenses
    
    return "NOASSERTION"


def extract_release_date_from_packagist(meta: Dict[str, Any]) -> str:
    """Extract release date from Packagist metadata."""
    if not meta:
        return ""
    return meta.get("time", "")


def extract_sha256_from_packagist(meta: Dict[str, Any]) -> str:
    """Extract SHA hash from Packagist metadata."""
    if not meta:
        return ""
    dist = meta.get("dist", {})
    return dist.get("shasum", "")


def extract_authors_from_packagist(meta: Dict[str, Any]) -> str:
    """Extract authors from Packagist metadata."""
    if not meta:
        return ""

    authors = meta.get("authors", [])
    if not authors:
        return ""

    author_names = []
    for author in authors:
        if isinstance(author, dict):
            name = author.get("name", "")
            if name:
                author_names.append(name)
        elif isinstance(author, str):
            author_names.append(author)

    return ", ".join(author_names)


def extract_dependencies_from_packagist(meta: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract dependencies from Packagist metadata."""
    if not meta:
        return []

    deps = []
    require = meta.get("require", {})
    
    for name, constraint in require.items():
        if name.startswith("php") or name.startswith("ext-"):
            continue
        
        deps.append({
            "name": name,
            "version_constraint": constraint,
            "purl": f"pkg:composer/{name}",
        })

    return deps


def infer_license_type(license_str: str) -> str:
    """Infer component origin based on license."""
    if not license_str or license_str.upper() == "NOASSERTION":
        return "unknown"

    license_lower = license_str.lower()

    open_source_indicators = [
        "mit", "apache", "gpl", "lgpl", "bsd", "isc", "mpl", "cc0",
        "unlicense", "wtfpl", "artistic", "zlib", "boost", "public domain",
        "agpl", "eupl", "osl", "cddl", "epl", "cecill"
    ]

    for indicator in open_source_indicators:
        if indicator in license_lower:
            return "open-source"

    proprietary_indicators = ["proprietary", "commercial", "closed"]
    for indicator in proprietary_indicators:
        if indicator in license_lower:
            return "commercial"

    return "unknown"
