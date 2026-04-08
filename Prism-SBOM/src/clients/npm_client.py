"""
npm Registry API Client

Fetches package metadata from npm registry.
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
from src.config.config import NPM_API

# Enable local file cache for npm results
try:
    from src.utils.cache_manager import get_npm_cache, set_npm_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiter
_rate_limiter = get_rate_limiter()


class NpmClient:
    """
    Client for npm Registry API.
    
    Fetches package metadata that deps.dev doesn't provide:
    - Description
    - Supplier (from author field)
    - Hashes (SHA-512 integrity or SHA-1 shasum)
    
    Includes rate limiting and caching support.
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize npm client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = NPM_API
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """
        Make a rate-limited HTTP request.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response object or None if rate limited/failed
        """
        # Check rate limit
        usage = _rate_limiter.get_current_usage("npm")
        if usage['remaining'] <= 0:
            logger.warning("[RATE LIMIT] npm: Rate limit exceeded, skipping request")
            return None
        
        # Record the call
        _rate_limiter.record_call("npm")
        
        # Add small delay between requests (100ms) to avoid bursts
        time.sleep(0.1)
        
        try:
            return requests.get(url, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"[npm] Request failed: {e}")
            return None
    
    def get_package_info(self, name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Get package metadata from npm registry.
        
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
        
        # Try API first
        logger.debug(f"[API CALL] npm: {name}@{version}")
        url = f"{self.base_url}/{name}"
        resp = self._make_request(url)
        
        if resp and resp.status_code == 200:
            data = resp.json()
            latest_version = data.get("dist-tags", {}).get("latest", version)
            version_data = data.get("versions", {}).get(version) or data.get("versions", {}).get(latest_version, {})
            result["success"] = True
            result["raw_data"] = data
            
            # Extract description
            result["description"] = version_data.get("description") or data.get("description") or "No description available"
            
            # Extract supplier (author)
            author = version_data.get("author") or data.get("author") or {}
            if isinstance(author, dict):
                supplier_name = author.get("name") or "Unknown"
                supplier_name = str(supplier_name).strip().strip('"').strip("'")
                result["supplier"] = supplier_name or "Unknown"
            else:
                supplier_name = str(author) if author else "Unknown"
                supplier_name = supplier_name.strip().strip('"').strip("'")
                result["supplier"] = supplier_name or "Unknown"
            
            # Extract hashes (SHA-512 integrity or SHA-1 shasum)
            hashes = []
            dist = version_data.get("dist", {})
            if dist.get("integrity"):
                integrity = dist["integrity"]
                if integrity.startswith("sha512-"):
                    hashes.append({"alg": "SHA-512", "content": integrity.replace("sha512-", "")})
                elif integrity.startswith("sha256-"):
                    hashes.append({"alg": "SHA-256", "content": integrity.replace("sha256-", "")})
            elif dist.get("shasum"):
                hashes.append({"alg": "SHA-1", "content": dist["shasum"]})
            result["hashes"] = hashes
            
            # Cache the response for future fallback
            if CACHE_AVAILABLE:
                set_npm_cache(name, data, version)
                
        elif resp and resp.status_code == 429:
            # Rate limited - mark for cache fallback
            logger.warning(f"[RATE LIMITED] npm: {name}@{version}")
            result["rate_limited"] = True
        else:
            # Package not found or other error
            logger.debug(f"[API ERROR] npm: {name}@{version} - status {resp.status_code if resp else 'None'}")
        
        # Fallback to cache if API failed
        if not result["success"] and CACHE_AVAILABLE:
            cached_data = get_npm_cache(name, version)
            if cached_data:
                logger.debug(f"[CACHE FALLBACK] npm: {name}@{version}")
                result = self._extract_from_cached_data(cached_data, version)
                result["from_cache"] = True
        
        return result
    
    def _extract_from_cached_data(self, cached: Dict, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract metadata from cached npm data.
        
        Args:
            cached: Cached npm response data
            version: Version to extract data for
            
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
        if "description" in cached and not isinstance(cached.get("description"), dict):
            result["description"] = cached.get("description") or "No description available"
        else:
            # Try to get from versions
            latest_version = cached.get("dist-tags", {}).get("latest", version)
            version_data = cached.get("versions", {}).get(version) or cached.get("versions", {}).get(latest_version, {})
            result["description"] = version_data.get("description") or cached.get("description") or "No description available"
        
        if "supplier" in cached and not isinstance(cached.get("supplier"), dict):
            result["supplier"] = cached.get("supplier") or "Unknown"
        else:
            # Try to get author
            author = cached.get("author") or {}
            if isinstance(author, dict):
                supplier_name = author.get("name") or "Unknown"
            else:
                supplier_name = str(author) if author else "Unknown"
            result["supplier"] = supplier_name.strip().strip('"').strip("'") if supplier_name else "Unknown"
        
        result["hashes"] = cached.get("hashes") or []
        
        return result


# Convenience function for direct calls
def get_npm_package_info(name: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Get package info from npm registry.
    
    Args:
        name: Package name
        version: Optional version
        
    Returns:
        Dict with description, supplier, hashes
    """
    client = NpmClient()
    return client.get_package_info(name, version)


# ============================================================
# Extraction helpers (for parsing raw npm API responses)
# ============================================================

def fetch_npm_meta(pkg: str, ver: Optional[str] = None, timeout: float = 5.0) -> Optional[Dict]:
    """
    Fetch raw metadata from npm registry API.
    
    Args:
        pkg: Package name
        ver: Optional version
        timeout: Request timeout
        
    Returns:
        Raw npm API response or None
    """
    if not pkg:
        return None
    
    client = NpmClient(timeout=int(timeout))
    result = client.get_package_info(pkg, ver)
    return result.get("raw_data") if result.get("success") else None


def extract_license_from_npm_meta(meta: Dict) -> str:
    """Extract license from npm metadata."""
    if not meta:
        return "NOASSERTION"
    lic = meta.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict):
        return lic.get("type", "NOASSERTION")
    return "NOASSERTION"


def extract_hashes_from_npm_meta(meta: Dict, ver: Optional[str] = None) -> List[Dict]:
    """Extract hashes from npm metadata."""
    if not meta:
        return []
    dist = meta.get("dist", {})
    if dist.get("integrity"):
        i = dist["integrity"]
        if i.startswith("sha512-"):
            return [{"alg": "SHA-512", "content": i.replace("sha512-", "")}]
    if dist.get("shasum"):
        return [{"alg": "SHA-1", "content": dist["shasum"]}]
    return []


def extract_release_date_from_npm(meta: Dict, ver: Optional[str] = None) -> str:
    """Extract release date from npm metadata."""
    if not meta:
        return ""
    td = meta.get("time", {})
    if ver and ver in td:
        return td[ver]
    lt = meta.get("dist-tags", {}).get("latest")
    if lt and lt in td:
        return td[lt]
    return ""


def infer_license_type(license_str: str) -> str:
    """Infer license type from license string."""
    if not license_str or license_str == "NOASSERTION":
        return "Unknown"
    ll = license_str.lower()
    if any(x in ll for x in ["proprietary", "commercial", "private"]):
        return "Proprietary"
    if any(x in ll for x in ["mit", "bsd", "apache", "isc", "gpl", "lgpl", "mpl", "eclipse", "unlicense", "cc0"]):
        return "Open Source"
    return "Unknown"
