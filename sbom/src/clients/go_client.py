"""
Go Module Registry Client

Fetches package metadata from:
1. Go Module Proxy (proxy.golang.org) - version info, mod files
2. Go Checksum Database (sum.golang.org) - checksums
3. pkg.go.dev - documentation and metadata (via deps.dev)

Note: Go Proxy doesn't provide license info directly.
License info comes from deps.dev enrichment in the pipeline.
"""

from __future__ import annotations
import requests
from typing import Dict, Any, List, Optional
import time
import re

# Import rate limiter
from sbom.src.utils.rate_limiter import rate_limited_with_backoff

# Import API URLs from centralized config
from sbom.src.config.config import GO_PROXY_API, GO_SUM_API

# Enable local file cache
try:
    from sbom.src.utils.cache_manager import get_cache, set_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False


class GoClient:
    """Client for interacting with Go Module Proxy and related services."""
    
    # Cache TTL in hours
    CACHE_TTL = 168  # 7 days
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json, text/plain",
            "User-Agent": "StackSQScanner/1.0"
        })
    
    @rate_limited_with_backoff("go_proxy", calls_per_minute=100)
    def get_module_info(self, module: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Fetch module information from Go Proxy.
        ALWAYS calls the live API first. Cache is ONLY used as fallback on
        rate-limit, timeout, or network error.
        
        Args:
            module: Module path (e.g., "github.com/gin-gonic/gin")
            version: Version string (e.g., "1.9.1" or "v1.9.1")
            
        Returns:
            Dict with module info or None if not found
        """
        if not module or not version:
            return None
        
        # Normalize version to have 'v' prefix
        if not version.startswith("v"):
            version = f"v{version}"
        
        # Cache key for fallback
        cache_key = f"go_{module}_{version}".replace("/", "_")
        
        # URL-encode the module path (case-sensitive encoding for Go)
        encoded_module = self._encode_module_path(module)
        
        # Fetch version info: GET /{module}/@v/{version}.info
        url = f"{GO_PROXY_API}/{encoded_module}/@v/{version}.info"
        
        try:
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                # Add module name for reference
                result["module"] = module
                result["version"] = version.lstrip("v")
                
                # Cache the result for future fallback
                if CACHE_AVAILABLE:
                    set_cache("go", cache_key, result)
                
                return result
            elif response.status_code == 404:
                return None
            elif response.status_code == 410:
                # Module has been removed/retracted
                return {"module": module, "version": version.lstrip("v"), "retracted": True}
            elif response.status_code == 429:
                # Rate limited - fallback to cache
                print(f"[RATE LIMITED] Go Proxy: {module}@{version} - falling back to cache")
                if CACHE_AVAILABLE:
                    cached = get_cache("go", cache_key, self.CACHE_TTL * 2)
                    if cached is not None:
                        return cached
            
        except requests.exceptions.Timeout:
            print(f"[WARN] Go Proxy timeout for {module}@{version} - falling back to cache")
            if CACHE_AVAILABLE:
                cached = get_cache("go", cache_key, self.CACHE_TTL * 2)
                if cached is not None:
                    return cached
        except Exception as e:
            print(f"[WARN] Go Proxy error for {module}@{version}: {e} - falling back to cache")
            if CACHE_AVAILABLE:
                cached = get_cache("go", cache_key, self.CACHE_TTL * 2)
                if cached is not None:
                    return cached
        
        return None
    
    @rate_limited_with_backoff("go_proxy", calls_per_minute=100)
    def get_module_versions(self, module: str) -> List[str]:
        """Get all available versions for a module."""
        if not module:
            return []
        
        encoded_module = self._encode_module_path(module)
        url = f"{GO_PROXY_API}/{encoded_module}/@v/list"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                versions = [v.strip() for v in response.text.splitlines() if v.strip()]
                return versions
        except Exception as e:
            print(f"[WARN] Failed to get versions for {module}: {e}")
        
        return []
    
    @rate_limited_with_backoff("go_proxy", calls_per_minute=100)
    def get_latest_version(self, module: str) -> Optional[str]:
        """Get the latest version of a module."""
        if not module:
            return None
        
        encoded_module = self._encode_module_path(module)
        url = f"{GO_PROXY_API}/{encoded_module}/@latest"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return data.get("Version", "").lstrip("v")
        except Exception as e:
            print(f"[WARN] Failed to get latest version for {module}: {e}")
        
        return None
    
    @rate_limited_with_backoff("go_proxy", calls_per_minute=50)
    def get_go_mod(self, module: str, version: str) -> Optional[str]:
        """Fetch the go.mod file for a specific module version."""
        if not module or not version:
            return None
        
        if not version.startswith("v"):
            version = f"v{version}"
        
        encoded_module = self._encode_module_path(module)
        url = f"{GO_PROXY_API}/{encoded_module}/@v/{version}.mod"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(f"[WARN] Failed to get go.mod for {module}@{version}: {e}")
        
        return None
    
    def get_dependencies_from_mod(self, module: str, version: str) -> List[Dict[str, str]]:
        """Parse dependencies from a module's go.mod file."""
        mod_content = self.get_go_mod(module, version)
        if not mod_content:
            return []
        
        dependencies = []
        in_require_block = False
        
        for line in mod_content.splitlines():
            line = line.strip()
            
            if line.startswith("require ("):
                in_require_block = True
                continue
            
            if line == ")" and in_require_block:
                in_require_block = False
                continue
            
            if line.startswith("require ") and "(" not in line:
                match = re.match(r'require\s+([\w./-]+)\s+(v[\w.\-+]+)', line)
                if match:
                    dependencies.append({
                        "name": match.group(1),
                        "version": match.group(2).lstrip("v")
                    })
                continue
            
            if in_require_block and line and not line.startswith("//"):
                match = re.match(r'([\w./-]+)\s+(v[\w.\-+]+)', line)
                if match:
                    dependencies.append({
                        "name": match.group(1),
                        "version": match.group(2).lstrip("v")
                    })
        
        return dependencies
    
    def _encode_module_path(self, module: str) -> str:
        """
        Encode module path for Go Proxy URL.
        Go uses a special encoding where uppercase letters become !lowercase.
        """
        result = []
        for char in module:
            if char.isupper():
                result.append("!")
                result.append(char.lower())
            else:
                result.append(char)
        return "".join(result)


# Module-level convenience functions
_client: Optional[GoClient] = None


def get_go_client() -> GoClient:
    """Get or create the singleton Go client instance."""
    global _client
    if _client is None:
        _client = GoClient()
    return _client


def fetch_go_meta(module: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch Go module metadata."""
    client = get_go_client()
    
    if not version:
        version = client.get_latest_version(module)
        if not version:
            return None
    
    return client.get_module_info(module, version)


def get_go_module_versions(module: str) -> List[str]:
    """Get all available versions for a Go module."""
    return get_go_client().get_module_versions(module)


def get_go_dependencies(module: str, version: str) -> List[Dict[str, str]]:
    """Get dependencies for a specific module version."""
    return get_go_client().get_dependencies_from_mod(module, version)
