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

# Import rate limiter with exponential backoff
from src.utils.rate_limiter import rate_limited_with_backoff

# Import API URL from centralized config
from src.config.config import DEPS_DEV_API

# Enable local file cache for deps.dev results
# Cache stores results in .cache/depsdev/ with 7-day TTL
# This reduces API calls and improves performance
try:
    from src.utils.cache_manager import get_depsdev_cache, set_depsdev_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

# Ecosystem mapping
from src.registry.language_registry import get_ecosystem



class DepsDevClient:
    """Client for interacting with deps.dev API with local file caching"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
    
    @lru_cache(maxsize=2048)
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_package_info(self, ecosystem: str, name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Fetch complete package information from deps.dev.
        Uses API first, falls back to local file cache on rate limit/error.
        
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
        
        # Build URL
        url = f"{DEPS_DEV_API}/systems/{norm_ecosystem}/packages/{name}/versions/{version}"
        
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
    
    @lru_cache(maxsize=1024)
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_dependency_graph(self, ecosystem: str, name: str, version: str) -> Dict[str, Any]:
        """
        Fetch dependency graph from deps.dev using the :dependencies endpoint.
        
        Returns:
            {
                "direct": [{"name": "pkg1", "version": "1.0.0"}, ...],
                "transitive": [{"name": "pkg2", "version": "2.0.0"}, ...],
                "graph": {...},
                "total_dependencies": 5
            }
        """
        # Use the correct :dependencies endpoint (v3 stable API)
        url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{name}/versions/{version}:dependencies"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return {"direct": [], "transitive": [], "graph": {}, "total_dependencies": 0}
            
            data = response.json()
            nodes = data.get("nodes", [])
            edges = data.get("edges", [])
            
            direct_deps = []
            transitive_deps = []
            graph = {}
            
            # Parse nodes
            for node in nodes:
                version_key = node.get("versionKey", {})
                dep_name = version_key.get("name")
                dep_version = version_key.get("version")
                relation = node.get("relation", "UNKNOWN")
                
                if not dep_name or relation == "SELF":
                    continue
                
                dep_info = {
                    "name": dep_name,
                    "version": dep_version or "unknown"
                }
                
                # DIRECT and INDIRECT (transitive) dependencies
                if relation == "DIRECT":
                    direct_deps.append(dep_info)
                elif relation in ["INDIRECT", "TRANSITIVE"]:
                    transitive_deps.append(dep_info)
                
                # Build graph
                graph[dep_name] = {
                    "version": dep_version or "unknown",
                    "relation": relation
                }
            
            return {
                "direct": direct_deps,
                "transitive": transitive_deps,
                "graph": graph,
                "total_dependencies": len(nodes) - 1  # Exclude SELF
            }
            
        except Exception as e:
            print(f"[WARN] Failed to fetch dependency graph: {e}")
            return {"direct": [], "transitive": [], "graph": {}, "total_dependencies": 0}
    
    @rate_limited_with_backoff("depsdev", calls_per_minute=100)
    def get_metadata(self, ecosystem: str, name: str, version: str) -> Dict[str, Any]:
        """
        Extract package metadata from deps.dev.
        
        Returns:
            Dict with description, license, supplier, homepage, published_at
        """
        package_info = self.get_package_info(ecosystem, name, version)
        if not package_info:
            return {
                "description": "",
                "license": "NOASSERTION",
                "supplier": "",
                "homepage": "",
                "published_at": ""
            }
        
        # Extract license (deps.dev DOES provide this!)
        licenses = package_info.get("licenses", [])
        license_str = licenses[0] if licenses else "NOASSERTION"
        
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
            "published_at": published_at
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
