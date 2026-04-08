"""
deps.dev API Client

Fetches package metadata and from Google's deps.dev API.
This is the PRIMARY source for metadata in the hybrid detection system.
With local file-based caching support.
"""

from __future__ import annotations
import requests
from typing import Dict, Any, List, Optional
from functools import lru_cache
import time
from urllib.parse import quote

# Import rate limiter with exponential backoff
from sbom.src.utils.rate_limiter import rate_limited_with_backoff

# Import API URL from centralized config
from sbom.src.config.config import DEPS_DEV_API

# Enable local file cache for deps.dev results
# Cache stores results in .cache/depsdev/ with 7-day TTL
# This reduces API calls and improves performance
try:
    from sbom.src.utils.cache_manager import get_depsdev_cache, set_depsdev_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

# Ecosystem mapping
from sbom.src.registry.language_registry import get_ecosystem

# deps.dev supports these 7 ecosystems — all others get 404.
# Skip unsupported ones (Packagist, CocoaPods, Conda, Conan) to avoid wasted HTTP round-trips.
DEPSDEV_SUPPORTED_ECOSYSTEMS = {"PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "RubyGems"}

# Common SPDX license identifiers for normalization
SPDX_LICENSE_IDS = {
    "mit", "apache-2.0", "apache-1.0", "apache-1.1", "bsd-2-clause", "bsd-3-clause",
    "gpl-2.0", "gpl-3.0", "lgpl-2.0", "lgpl-2.1", "lgpl-3.0", "mpl-2.0", "isc",
    "cc0-1.0", "unlicense", "wtfpl", "zlib", "agpl-3.0", "artistic-2.0",
    "bsl-1.0", "cc-by-4.0", "cc-by-sa-4.0", "epl-2.0", "eupl-1.2", "ofl-1.1",
    "postgresql", "python-2.0", "0bsd", "afl-3.0", "artistic-1.0", "gpl-2.0-only",
    "gpl-3.0-only", "lgpl-2.1-only", "lgpl-3.0-only", "mit-0", "osl-3.0", "sspl-1.0"
}

def normalize_license(license_str: str) -> str:
    """
    Normalize license string to a clean SPDX identifier.
    If deps.dev returns full license text, extract the SPDX ID.
    
    Args:
        license_str: License string from deps.dev (could be full text or SPDX ID)
        
    Returns:
        Clean SPDX identifier or original if short enough
    """
    if not license_str:
        return "NOASSERTION"
    
    license_str = str(license_str).strip()
    
    if not license_str or license_str.lower() in ("none", "unknown", "noassertion", ""):
        return "NOASSERTION"
    
    # If it's already a short SPDX-like identifier (≤80 chars, no "Copyright"/"Redistribution" keywords), return as-is
    if len(license_str) <= 80:
        lower_short = license_str.lower()
        # Make sure it's not a truncated full-text that starts with copyright etc.
        if not any(kw in lower_short for kw in ["copyright", "redistribution", "permission is hereby", "terms and conditions"]):
            return license_str
    
    # ---- It's likely full license text from here ----
    lower_text = license_str.lower()
    
    # ----- Pattern matching on the FULL text to identify the license -----
    
    # BSD detection (numpy, scipy, scikit-learn, pandas all have BSD full text)
    if "bsd 3-clause" in lower_text or "bsd-3-clause" in lower_text:
        return "BSD-3-Clause"
    if "bsd 2-clause" in lower_text or "bsd-2-clause" in lower_text:
        return "BSD-2-Clause"
    # BSD text that starts with "Copyright (c)" and has "Redistribution and use"
    if "redistribution and use in source and binary forms" in lower_text:
        # Count the number of conditions to distinguish BSD-2 vs BSD-3
        if "neither the name" in lower_text or "the names of" in lower_text:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    
    # Apache detection (replicate, ml-dtypes have full Apache text)
    if "apache license" in lower_text:
        if "version 2" in lower_text or "2.0" in lower_text:
            return "Apache-2.0"
        if "version 1.1" in lower_text:
            return "Apache-1.1"
        return "Apache-2.0"  # Default Apache to 2.0
    if "http://www.apache.org/licenses/" in lower_text:
        return "Apache-2.0"
    
    # MIT detection
    if "permission is hereby granted, free of charge" in lower_text:
        return "MIT"
    if "mit license" in lower_text[:100]:
        return "MIT"
    
    # GPL detection
    if "gnu general public license" in lower_text:
        if "version 3" in lower_text or "gpl-3" in lower_text:
            return "GPL-3.0"
        if "version 2" in lower_text or "gpl-2" in lower_text:
            return "GPL-2.0"
        return "GPL-3.0"
    
    # LGPL detection
    if "gnu lesser general public" in lower_text or "gnu library general public" in lower_text:
        if "2.1" in lower_text:
            return "LGPL-2.1"
        return "LGPL-3.0"
    
    # MPL detection
    if "mozilla public license" in lower_text:
        if "2.0" in lower_text:
            return "MPL-2.0"
        return "MPL-2.0"
    
    # ISC detection
    if "isc license" in lower_text[:100]:
        return "ISC"
    
    # Unlicense / CC0
    if "this is free and unencumbered software" in lower_text:
        return "Unlicense"
    if "cc0" in lower_text[:100]:
        return "CC0-1.0"
    
    # If text is very long (>100 chars) but we couldn't identify it, it's unrecognized full text
    if len(license_str) > 100:
        return "NOASSERTION"
    
    # For medium-length strings (80-100), return as-is (could be compound SPDX expressions)
    return license_str



class DepsDevClient:
    """Client for interacting with deps.dev API with local file caching and connection pooling"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        
        # Connection pooling for performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=requests.adapters.Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
    
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_package_info(self, ecosystem: str, name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Fetch complete package information from deps.dev.
        ALWAYS calls the live API first. Cache is ONLY used as fallback on
        rate-limit, timeout, or network error.
        
        Args:
            ecosystem: Package ecosystem (npm, pypi, etc.)
            name: Package name
            version: Package version
            
        Returns:
            Dict containing package metadata, dependencies, and vulnerabilities
        """
        if not name or not version:
            return None
        
        # Normalize ecosystem (using centralized mapping)
        norm_ecosystem = get_ecosystem(ecosystem) if ecosystem else ecosystem
        
        # Short-circuit for ecosystems not supported by deps.dev
        if norm_ecosystem not in DEPSDEV_SUPPORTED_ECOSYSTEMS:
            return None
        
        # URL-encode package name and version (handles special chars like Flask-CORS)
        encoded_name = quote(name, safe='')
        encoded_version = quote(version, safe='')
        
        # Go modules require 'v' prefix for versions in deps.dev API
        if norm_ecosystem == "Go" and encoded_version and not encoded_version.startswith("v"):
            encoded_version = f"v{encoded_version}"
        
        # Build URL
        url = f"{DEPS_DEV_API}/systems/{norm_ecosystem}/packages/{encoded_name}/versions/{encoded_version}"
        
        try:
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                # Cache the result for future fallback
                if CACHE_AVAILABLE:
                    set_depsdev_cache(norm_ecosystem, name, version, result)
                return result
            elif response.status_code == 404:
                # Package not found in deps.dev (might be too new)
                return None
            elif response.status_code == 429:
                # Rate limited - fallback to cache
                print(f"[RATE LIMITED] deps.dev: {norm_ecosystem}:{name}@{version} - falling back to cache")
                if CACHE_AVAILABLE:
                    cached = get_depsdev_cache(norm_ecosystem, name, version)
                    if cached is not None:
                        return cached
                # Wait and retry once if no cache
                time.sleep(2)
                response = self.session.get(url, timeout=15)
                if response.status_code == 200:
                    result = response.json()
                    if CACHE_AVAILABLE:
                        set_depsdev_cache(norm_ecosystem, name, version, result)
                    return result
            
        except requests.exceptions.Timeout:
            print(f"[WARN] deps.dev timeout for {norm_ecosystem}:{name}@{version} - falling back to cache")
            # Fallback to cache on timeout
            if CACHE_AVAILABLE:
                cached = get_depsdev_cache(norm_ecosystem, name, version)
                if cached is not None:
                    return cached
        except Exception as e:
            print(f"[WARN] deps.dev error for {norm_ecosystem}:{name}@{version}: {e} - falling back to cache")
            # Fallback to cache on error
            if CACHE_AVAILABLE:
                cached = get_depsdev_cache(norm_ecosystem, name, version)
                if cached is not None:
                    return cached
        
        return None
    
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_dependency_graph(self, ecosystem: str, name: str, version: str) -> Dict[str, Any]:
        """
        Fetch dependency graph from deps.dev using the :dependencies endpoint.
        
        Fallback chain:
        1. deps.dev API → parse nodes
        2. On 429/timeout → cache fallback
        3. Caller should check total_dependencies == 0 and fallback to registry
        
        Returns:
            {
                "direct": [{"name": "pkg1", "version": "1.0.0"}, ...],
                "transitive": [{"name": "pkg2", "version": "2.0.0"}, ...],
                "graph": {...},
                "total_dependencies": 5,
                "source": "deps.dev" | "cache"
            }
        """
        empty_result = {"direct": [], "transitive": [], "graph": {}, "total_dependencies": 0, "source": "none"}
        
        # Normalize ecosystem
        norm_ecosystem = get_ecosystem(ecosystem) if ecosystem else ecosystem
        
        # Short-circuit for ecosystems not supported by deps.dev
        if norm_ecosystem not in DEPSDEV_SUPPORTED_ECOSYSTEMS:
            return empty_result
        
        # URL-encode package name and version (handles special chars like Flask-CORS)
        encoded_name = quote(name, safe='')
        encoded_version = quote(version, safe='')
        
        # Go modules require 'v' prefix for versions in deps.dev API
        if norm_ecosystem == "Go" and encoded_version and not encoded_version.startswith("v"):
            encoded_version = f"v{encoded_version}"
        
        # Use the correct :dependencies endpoint (v3 stable API)
        url = f"https://api.deps.dev/v3/systems/{norm_ecosystem}/packages/{encoded_name}/versions/{encoded_version}:dependencies"
        
        def _parse_dep_graph(data: Dict) -> Dict[str, Any]:
            """Parse raw deps.dev dependency response into structured format."""
            nodes = data.get("nodes", [])
            direct_deps = []
            transitive_deps = []
            graph = {}
            
            for node in nodes:
                version_key = node.get("versionKey", {})
                dep_name = version_key.get("name")
                dep_version = version_key.get("version")
                relation = node.get("relation", "UNKNOWN")
                
                if not dep_name or relation == "SELF":
                    continue
                
                dep_info = {"name": dep_name, "version": dep_version or "unknown"}
                
                if relation == "DIRECT":
                    direct_deps.append(dep_info)
                elif relation in ["INDIRECT", "TRANSITIVE"]:
                    transitive_deps.append(dep_info)
                
                graph[dep_name] = {"version": dep_version or "unknown", "relation": relation}
            
            total = len(direct_deps) + len(transitive_deps)
            return {
                "direct": direct_deps,
                "transitive": transitive_deps,
                "graph": graph,
                "total_dependencies": total
            }
        
        try:
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                result = _parse_dep_graph(data)
                result["source"] = "deps.dev"
                # Cache successful result for future fallback
                if CACHE_AVAILABLE:
                    try:
                        from sbom.src.utils.cache_manager import set_depsdev_depgraph_cache
                        set_depsdev_depgraph_cache(norm_ecosystem, name, version, result)
                    except Exception:
                        pass
                return result
            
            elif response.status_code == 429:
                # Rate limited — fallback to cache
                print(f"[RATE LIMITED] deps.dev dep graph: {norm_ecosystem}/{name}@{version} - falling back to cache")
                if CACHE_AVAILABLE:
                    try:
                        from sbom.src.utils.cache_manager import get_depsdev_depgraph_cache
                        cached = get_depsdev_depgraph_cache(norm_ecosystem, name, version)
                        if cached:
                            cached["source"] = "cache"
                            return cached
                    except Exception:
                        pass
                # Wait and retry once if no cache
                time.sleep(2)
                response = self.session.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    result = _parse_dep_graph(data)
                    result["source"] = "deps.dev"
                    return result
            
            elif response.status_code == 404:
                print(f"[DEBUG] deps.dev dep graph: {norm_ecosystem}/{name}@{version} -> 404 (not found)")
            else:
                print(f"[DEBUG] deps.dev dep graph: {norm_ecosystem}/{name}@{version} -> HTTP {response.status_code}")
            
            return empty_result
            
        except requests.exceptions.Timeout:
            print(f"[WARN] deps.dev dep graph timeout: {norm_ecosystem}/{name}@{version} - falling back to cache")
            if CACHE_AVAILABLE:
                try:
                    from sbom.src.utils.cache_manager import get_depsdev_depgraph_cache
                    cached = get_depsdev_depgraph_cache(norm_ecosystem, name, version)
                    if cached:
                        cached["source"] = "cache"
                        return cached
                except Exception:
                    pass
            return empty_result
            
        except Exception as e:
            print(f"[WARN] Failed to fetch dependency graph for {name}@{version}: {e}")
            if CACHE_AVAILABLE:
                try:
                    from sbom.src.utils.cache_manager import get_depsdev_depgraph_cache
                    cached = get_depsdev_depgraph_cache(norm_ecosystem, name, version)
                    if cached:
                        cached["source"] = "cache"
                        return cached
                except Exception:
                    pass
            return empty_result
    
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_metadata(self, ecosystem: str, name: str, version: str) -> Dict[str, Any]:
        """
        Extract package metadata from deps.dev.
        
        Returns:
            Dict with description, license, supplier, homepage, published_at
        """
        package_info = self.get_package_info(ecosystem, name, version)
        if not package_info:
            # Return empty strings — NOT "NOASSERTION"
            # Callers should check for empty and fallback to registry APIs
            return {
                "description": "",
                "license": "",
                "supplier": "",
                "homepage": "",
                "published_at": "",
                "source": "none"
            }
        
        # Extract license from deps.dev
        # If deps.dev has no license data, return "" (empty) so callers can fallback to registries
        # Do NOT return "NOASSERTION" here — that should only be set as an absolute last resort
        licenses = package_info.get("licenses", [])
        raw_license = licenses[0] if licenses else ""
        # Also check singular 'license' key (cache format uses this)
        if (not raw_license or raw_license in ("NOASSERTION", "non-standard")) and package_info.get("license"):
            raw_license = package_info.get("license")
        
        # If deps.dev returned "non-standard" or empty, keep as empty so caller falls back
        if not raw_license or raw_license.lower() in ("non-standard", "noassertion", "unknown", ""):
            license_str = ""
        else:
            # Normalize full license text from deps.dev to SPDX
            license_str = normalize_license(raw_license)
            # If normalize couldn't identify it (returned NOASSERTION), leave empty for registry fallback
            if license_str.lower() in ("noassertion", "non-standard", "unknown"):
                license_str = ""
            # Final safeguard: if still too long after normalization, leave empty for fallback
            if len(str(license_str)) > 80:
                license_str = ""
        
        # Extract links (homepage, repository, etc.)
        links = package_info.get("links", [])
        homepage = ""
        source_repo = ""
        for link in links:
            label = link.get("label", "")
            url = link.get("url", "")
            if label == "HOMEPAGE":
                homepage = url
            elif label == "SOURCE_REPO":
                source_repo = url
        
        # Use source repo as homepage if no homepage found
        if not homepage and source_repo:
            homepage = source_repo
        
        # Extract published date
        published_at = package_info.get("publishedAt", "")
        
        # Note: deps.dev doesn't provide description or author/supplier
        # These would need to come from the package's project metadata
        
        return {
            "description": "",  # Not in deps.dev API response
            "license": license_str,
            "supplier": "",  # Not in deps.dev API response
            "homepage": homepage,
            "published_at": published_at,
            "source": "deps.dev"
        }
    
    def batch_fetch_packages(self, packages: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Fetch multiple packages efficiently.
        
        Args:
            packages: List of dicts with keys: ecosystem, name, version
            
        Returns:
            Dict mapping "ecosystem:name:version" to package info
        """
        results = {}
        for pkg in packages:
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            
            if not all([ecosystem, name, version]):
                continue
            
            key = f"{ecosystem}:{name}:{version}"
            info = self.get_package_info(ecosystem, name, version)
            if info:
                results[key] = info
        
        return results


# Global instance (can be configured with API key)
_client_instance = None

def get_client(api_key: Optional[str] = None) -> DepsDevClient:
    """Get or create the global deps.dev client instance"""
    global _client_instance
    if _client_instance is None:
        _client_instance = DepsDevClient(api_key=api_key)
    return _client_instance


# Convenience function for backward compatibility
def get_package_metadata(ecosystem: str, name: str, version: str) -> Optional[Dict[str, Any]]:
    """Fetch complete metadata for a single package"""
    client = get_client()
    return client.get_package_info(ecosystem, name, version)
