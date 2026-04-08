"""
PyPI API Client

Fetches package metadata from Python Package Index (PyPI).
Provides description, supplier, and hashes that deps.dev doesn't provide.
With local file-based caching support.
"""

from __future__ import annotations
import requests
from typing import Dict, Any, List, Optional
import logging
import time

# Import rate limiter
from src.utils.rate_limiter import get_rate_limiter

# Import API URL from centralized config
from src.config.config import PYPI_API

# Enable local file cache for PyPI results
try:
    from src.utils.cache_manager import get_pypi_cache, set_pypi_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiter
_rate_limiter = get_rate_limiter()


class PyPIClient:
    """
    Client for PyPI REST API.
    
    Fetches package metadata that deps.dev doesn't provide:
    - Description (from summary field)
    - Supplier (from author/maintainer fields)
    - Hashes (SHA-256 from digests)
    
    Includes rate limiting and caching support.
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize PyPI client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = PYPI_API
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """
        Make a rate-limited HTTP request.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response object or None if rate limited/failed
        """
        # Check rate limit
        usage = _rate_limiter.get_current_usage("pypi")
        if usage['remaining'] <= 0:
            logger.warning("[RATE LIMIT] PyPI: Rate limit exceeded, skipping request")
            return None
        
        # Record the call
        _rate_limiter.record_call("pypi")
        
        # Add small delay between requests (100ms) to avoid bursts
        time.sleep(0.1)
        
        try:
            return requests.get(url, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"[PyPI] Request failed: {e}")
            return None
    
    def get_package_info(self, name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Get package metadata from PyPI.
        
        Fetches description, supplier, and hashes.
        
        Args:
            name: Package name
            version: Optional version (uses latest if not provided)
            
        Returns:
            Dict with description, supplier, hashes, and success status
            {
                "success": bool,
                "description": str,
                "supplier": str,
                "hashes": List[Dict],
                "raw_data": Dict (optional, only on success)
            }
        """
        result = {
            "success": False,
            "description": "No description available",
            "supplier": "Unknown",
            "hashes": [],
            "rate_limited": False
        }
        
        # Try API first - use versioned URL when version is provided for complete metadata
        logger.debug(f"[API CALL] PyPI: {name}@{version}")
        if version:
            url = f"{self.base_url}/{name}/{version}/json"
        else:
            url = f"{self.base_url}/{name}/json"
        resp = self._make_request(url)
        
        if resp and resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            result["success"] = True
            result["raw_data"] = data
            
            # Extract description
            result["description"] = info.get("summary") or "No description available"
            
            # Extract supplier (author/maintainer or their email fields)
            supplier = info.get("author") or info.get("maintainer")
            if not supplier:
                # Try to extract from email fields
                email_field = info.get("author_email") or info.get("maintainer_email") or ""
                if email_field:
                    if "<" in email_field:
                        supplier = email_field.split("<")[0].strip()
                    else:
                        supplier = email_field.split("@")[0] if "@" in email_field else email_field
            if supplier:
                supplier = supplier.strip().strip('"').strip("'")
            result["supplier"] = supplier or "Unknown"
            
            # Extract hashes (SHA-256 from digests)
            hashes = []
            for url_info in data.get("urls", []) or []:
                digests = url_info.get("digests", {}) or {}
                sha256 = digests.get("sha256", "")
                if sha256:
                    hashes.append({"alg": "SHA-256", "content": sha256})
                    break  # Only first one
            result["hashes"] = hashes
            
            # Cache the response for future fallback
            if CACHE_AVAILABLE:
                set_pypi_cache(name, data, version)
                
        elif resp and resp.status_code == 429:
            # Rate limited - mark for cache fallback
            logger.warning(f"[RATE LIMITED] PyPI: {name}@{version}")
            result["rate_limited"] = True
        else:
            # Package not found or other error
            logger.debug(f"[API ERROR] PyPI: {name}@{version} - status {resp.status_code if resp else 'None'}")
        
        # Fallback to cache if API failed
        if not result["success"] and CACHE_AVAILABLE:
            cached_data = get_pypi_cache(name, version)
            if cached_data:
                logger.debug(f"[CACHE FALLBACK] PyPI: {name}@{version}")
                result = self._extract_from_cached_data(cached_data)
                result["from_cache"] = True
        
        return result
    
    def _extract_from_cached_data(self, cached: Dict) -> Dict[str, Any]:
        """
        Extract metadata from cached PyPI data.
        
        Args:
            cached: Cached PyPI response data
            
        Returns:
            Dict with description, supplier, hashes
        """
        result = {
            "success": True,
            "description": "No description available",
            "supplier": "Unknown",
            "hashes": [],
            "rate_limited": False
        }
        
        # These may already be extracted in cache
        if "description" in cached:
            result["description"] = cached.get("description") or "No description available"
        elif "info" in cached:
            result["description"] = cached.get("info", {}).get("summary") or "No description available"
        
        if "supplier" in cached:
            result["supplier"] = cached.get("supplier") or "Unknown"
        elif "info" in cached:
            info = cached.get("info", {})
            supplier = info.get("author") or info.get("maintainer")
            if supplier:
                supplier = supplier.strip().strip('"').strip("'")
            result["supplier"] = supplier or "Unknown"
        
        result["hashes"] = cached.get("hashes") or []
        
        return result


# Convenience function for direct calls
def get_pypi_package_info(name: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Get package info from PyPI.
    
    Args:
        name: Package name
        version: Optional version
        
    Returns:
        Dict with description, supplier, hashes
    """
    client = PyPIClient()
    return client.get_package_info(name, version)


# ============================================================
# Extraction helpers (for parsing raw PyPI API responses)
# ============================================================

def fetch_pypi_meta(pkg: str, ver: Optional[str] = None, timeout: float = 5.0) -> Optional[Dict]:
    """
    Fetch raw metadata from PyPI API.
    
    Args:
        pkg: Package name
        ver: Optional version
        timeout: Request timeout
        
    Returns:
        Raw PyPI API response or None
    """
    import urllib.parse
    if not pkg:
        return None
    
    client = PyPIClient(timeout=int(timeout))
    result = client.get_package_info(pkg, ver)
    return result.get("raw_data") if result.get("success") else None


def extract_license_from_pypi_meta(meta: Dict) -> str:
    """Extract license from PyPI metadata.
    
    Checks in order:
    1. license_expression field (PEP 639)
    2. license field (if not empty/None)
    3. License classifiers
    """
    if not meta:
        return "NOASSERTION"
    info = meta.get("info", {}) or {}
    
    # Check license_expression first (PEP 639 - new standard)
    license_expr = info.get("license_expression")
    if license_expr and license_expr.strip() and license_expr.lower() != "none":
        return license_expr.strip()
    
    # Check license field
    lic = info.get("license")
    if lic and str(lic).strip() and str(lic).lower() not in ["none", "unknown", ""]:
        return str(lic).strip()
    
    # Fall back to classifiers
    for c in info.get("classifiers", []) or []:
        if "License ::" in c:
            # Return the last part after :: (e.g., "BSD License" from "License :: OSI Approved :: BSD License")
            return c.split("::")[-1].strip()
    return "NOASSERTION"


def extract_hashes_from_pypi_meta(meta: Dict, ver: Optional[str] = None) -> List[Dict]:
    """Extract SHA-256 hashes from PyPI metadata."""
    if not meta:
        return []
    for u in meta.get("urls", []) or []:
        sha = (u.get("digests", {}) or {}).get("sha256", "")
        if sha:
            return [{"alg": "SHA-256", "content": sha}]
    return []


def extract_release_date_from_pypi(meta: Dict, ver: Optional[str] = None) -> str:
    """Extract release date from PyPI metadata."""
    if not meta:
        return ""
    if ver:
        for r in meta.get("releases", {}).get(ver, []):
            t = r.get("upload_time_iso_8601") or r.get("upload_time")
            if t:
                return t
    urls = meta.get("urls", [])
    if urls:
        t = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time")
        if t:
            return t
    return ""
