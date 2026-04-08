"""
End-of-Life (EOL) API Client

Fetches end-of-life/support lifecycle data from endoflife.date API.
Used to determine if runtimes/languages are still supported.

NOTE: The endoflife.date API is for RUNTIMES (Python, Node.js, Java),
not for individual libraries (Flask, Express, Spring).
"""

from __future__ import annotations
import requests
from typing import Dict, Any, Optional, List
import logging
import time
from datetime import datetime
from functools import lru_cache

# Import rate limiter
from src.utils.rate_limiter import get_rate_limiter

# Import API URL from centralized config
from src.config.config import EOL_API

# Configure logging
logger = logging.getLogger(__name__)

# Map package ecosystems to endoflife.date product names
ECOSYSTEM_TO_PRODUCT = {
    "pypi": "python",
    "npm": "nodejs",
    "maven": "java",
    "nuget": "dotnet",
    "rubygems": "ruby",
    "go": "go",
    "rust": "rust",
    "php": "php",
}

# Initialize rate limiter
_rate_limiter = get_rate_limiter()


class EOLClient:
    """
    Client for endoflife.date API.
    
    Fetches end-of-life information for runtimes and languages:
    - EOL date
    - Support status
    - Release cycle information
    
    NOTE: This API is for RUNTIMES only, not individual packages.
    Most libraries don't have official EOL dates.
    
    Includes rate limiting and in-memory caching.
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize EOL client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = EOL_API
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """
        Make a rate-limited HTTP request.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response object or None if rate limited/failed
        """
        # Check rate limit (using pypi bucket as EOL is low-volume)
        usage = _rate_limiter.get_current_usage("pypi")
        if usage['remaining'] <= 0:
            logger.warning("[RATE LIMIT] EOL: Rate limit exceeded, skipping request")
            return None
        
        # Record the call
        _rate_limiter.record_call("pypi")
        
        # Add small delay between requests
        time.sleep(0.05)
        
        try:
            return requests.get(url, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"[EOL] Request failed: {e}")
            return None
    
    @lru_cache(maxsize=512)
    def get_product_cycles(self, product: str) -> Dict[str, Any]:
        """
        Get all release cycles for a product.
        
        Args:
            product: Product name (e.g., "python", "nodejs")
            
        Returns:
            Dict with cycles and success status
        """
        result = {
            "success": False,
            "cycles": [],
            "product": product
        }
        
        logger.debug(f"[API CALL] EOL: {product}")
        url = f"{self.base_url}/{product}.json"
        resp = self._make_request(url)
        
        if resp and resp.status_code == 200:
            result["success"] = True
            result["cycles"] = resp.json()
        else:
            logger.debug(f"[API ERROR] EOL: {product} - status {resp.status_code if resp else 'None'}")
        
        return result
    
    def get_eol_status(self, product: str, version: str) -> Dict[str, Any]:
        """
        Get EOL status for a specific product version.
        
        Args:
            product: Product name (e.g., "python", "nodejs")
            version: Version string (e.g., "3.9.0", "16.0.0")
            
        Returns:
            Dict with EOL status
            {
                "success": bool,
                "eol_date": str or None,
                "is_eol": bool,
                "status": "Active" | "Expired" | "Unknown",
                "cycle": str (matched cycle, e.g., "3.9")
            }
        """
        result = {
            "success": False,
            "eol_date": None,
            "is_eol": False,
            "status": "Unknown",
            "cycle": None
        }
        
        # Get all cycles for the product
        cycles_result = self.get_product_cycles(product)
        if not cycles_result["success"]:
            return result
        
        cycles = cycles_result["cycles"]
        
        # Parse version to get major.minor
        target_major, target_minor = self._parse_version(version)
        
        # Find matching release cycle
        for release in cycles:
            cycle = release.get("cycle", "")
            cycle_major, cycle_minor = self._parse_version(str(cycle))
            
            # Match major.minor
            if cycle_major == target_major:
                # If cycle is just major (e.g., "16") or matches minor too
                if cycle_minor is None or cycle_minor == target_minor:
                    result["success"] = True
                    result["cycle"] = str(cycle)
                    
                    eol = release.get("eol")
                    
                    if isinstance(eol, bool):
                        result["is_eol"] = eol
                        result["status"] = "Expired" if eol else "Active"
                    elif isinstance(eol, str):
                        result["eol_date"] = eol
                        # Check if date is in the past
                        try:
                            eol_date = datetime.fromisoformat(eol)
                            if eol_date < datetime.now():
                                result["is_eol"] = True
                                result["status"] = f"Expired ({eol})"
                            else:
                                result["is_eol"] = False
                                result["status"] = f"Supported until {eol}"
                        except Exception:
                            result["status"] = eol
                    
                    return result
        
        return result
    
    def get_eol_for_ecosystem(self, ecosystem: str, version: str) -> Dict[str, Any]:
        """
        Get EOL status for an ecosystem's runtime.
        
        Args:
            ecosystem: Package ecosystem (pypi, npm, etc.)
            version: Runtime version
            
        Returns:
            Dict with EOL status
        """
        # Map ecosystem to product name
        product = ECOSYSTEM_TO_PRODUCT.get(ecosystem.lower())
        if not product:
            return {
                "success": False,
                "status": "Unknown",
                "message": f"No EOL mapping for ecosystem: {ecosystem}"
            }
        
        return self.get_eol_status(product, version)
    
    def _parse_version(self, version: str) -> tuple:
        """
        Parse version string to extract major and minor.
        
        Args:
            version: Version string (e.g., "3.9.0", "16", "11.0")
            
        Returns:
            Tuple of (major, minor) where minor may be None
        """
        try:
            # Try using packaging library first
            from packaging import version as pkg_version
            parsed = pkg_version.parse(version)
            return (parsed.major, getattr(parsed, 'minor', None))
        except Exception:
            pass
        
        # Fallback to string parsing
        try:
            parts = version.split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else None
            return (major, minor)
        except (ValueError, TypeError):
            return (0, None)
    
    def is_eol_expired(self, eol_date_str: str) -> bool:
        """
        Check if an EOL date indicates the product is expired.
        
        Args:
            eol_date_str: EOL date string
            
        Returns:
            True if expired, False otherwise
        """
        if not eol_date_str:
            return False
        
        if "Expired" in eol_date_str:
            return True
        
        if eol_date_str == "Active":
            return False
        
        # Try to parse as ISO date
        try:
            eol_date = datetime.fromisoformat(eol_date_str)
            return eol_date < datetime.now()
        except Exception:
            return False


# Convenience functions for direct calls
def get_eol_status(product: str, version: str) -> Dict[str, Any]:
    """
    Get EOL status for a product version.
    
    Args:
        product: Product name
        version: Version string
        
    Returns:
        Dict with EOL status
    """
    client = EOLClient()
    return client.get_eol_status(product, version)


def get_eol_for_ecosystem(ecosystem: str, version: str) -> Dict[str, Any]:
    """
    Get EOL status for an ecosystem's runtime.
    
    Args:
        ecosystem: Package ecosystem
        version: Runtime version
        
    Returns:
        Dict with EOL status
    """
    client = EOLClient()
    return client.get_eol_for_ecosystem(ecosystem, version)


def is_runtime_eol(ecosystem: str, version: str) -> bool:
    """
    Check if a runtime version is end-of-life.
    
    Args:
        ecosystem: Package ecosystem
        version: Runtime version
        
    Returns:
        True if EOL, False otherwise
    """
    client = EOLClient()
    result = client.get_eol_for_ecosystem(ecosystem, version)
    return result.get("is_eol", False)
