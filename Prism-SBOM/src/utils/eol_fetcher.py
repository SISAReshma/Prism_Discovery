"""
End-of-Life (EOL) Date Fetcher

Fetches EOL dates for packages using:
1. deps.dev API (primary) - provides package lifecycle metadata
2. Static fallback database (secondary)

NOTE: The endoflife.date API is for runtimes (Python, Node.js, Java),
not for individual libraries. This module uses deps.dev for package EOL.
"""

import requests
from typing import Dict, Any, Optional
from functools import lru_cache
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# deps.dev API base URL
DEPS_DEV_API = "https://api.deps.dev/v3alpha"


@lru_cache(maxsize=1024)
def get_eol_date_from_depsdev(name: str, version: str, ecosystem: str = "npm") -> Optional[str]:
    """
    Fetch EOL/deprecation status from deps.dev API.
    
    Args:
        name: Package name
        version: Package version
        ecosystem: Package ecosystem (npm, pypi, maven, etc.)
    
    Returns:
        EOL date string, deprecation status, or None if not available
    """
    try:
        # Map ecosystem names
        ecosystem_map = {
            "pypi": "pypi",
            "pip": "pypi",
            "npm": "npm",
            "maven": "maven",
            "go": "go",
            "cargo": "cargo",
            "nuget": "nuget"
        }
        
        system = ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
        
        # Get package version info from deps.dev
        url = f"{DEPS_DEV_API}/systems/{system}/packages/{name}/versions/{version}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        # Check for deprecation
        is_deprecated = data.get("isDeprecated", False)
        
        if is_deprecated:
            # Get deprecation reason/date if available
            deprecation_message = data.get("deprecationMessage", "")
            if deprecation_message:
                return f"Deprecated: {deprecation_message[:100]}"
            return "Deprecated"
        
        # Check advisories count (could indicate end-of-support)
        advisories = data.get("advisoryKeyCount", 0)
        
        # Get published date to estimate age
        published_at = data.get("publishedAt", "")
        
        if published_at:
            try:
                pub_date = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
                age_years = (datetime.now(pub_date.tzinfo) - pub_date).days / 365
                
                # Very old packages (>5 years) with no updates might be abandoned
                if age_years > 5:
                    # Check if this is the latest version
                    pkg_url = f"{DEPS_DEV_API}/systems/{system}/packages/{name}"
                    pkg_response = requests.get(pkg_url, timeout=10)
                    
                    if pkg_response.status_code == 200:
                        pkg_data = pkg_response.json()
                        versions = pkg_data.get("versions", [])
                        
                        if versions:
                            latest_version = versions[-1].get("versionKey", {}).get("version", "")
                            
                            if version == latest_version and age_years > 5:
                                return f"Potentially abandoned (last update: {pub_date.strftime('%Y-%m-%d')})"
            except Exception:
                pass
        
        # Package is active
        return "Active"
        
    except requests.RequestException:
        return None
    except Exception as e:
        logger.debug(f"Error fetching EOL for {name}@{version}: {e}")
        return None


def get_eol_date_with_fallback(
    name: str,
    version: str,
    known_eol_dates: Dict[str, str] = None,  # Deprecated, kept for API compatibility
    ecosystem: str = "npm"
) -> str:
    """
    Get EOL date from deps.dev API only.
    
    Args:
        name: Package name
        version: Package version
        known_eol_dates: DEPRECATED - not used, kept for backwards compatibility
        ecosystem: Package ecosystem
    
    Returns:
        EOL date string from deps.dev or "Unknown" if not found
    """
    # Try deps.dev only
    eol_result = get_eol_date_from_depsdev(name, version, ecosystem)
    
    if eol_result:
        return eol_result
    
    # If deps.dev doesn't have it, return Unknown
    return "Unknown"


def get_deprecation_status(name: str, version: str, ecosystem: str = "npm") -> Dict[str, Any]:
    """
    Get detailed deprecation status for a package.
    
    Returns:
        Dict with deprecation info
    """
    try:
        ecosystem_map = {
            "pypi": "pypi",
            "pip": "pypi",
            "npm": "npm"
        }
        
        system = ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
        url = f"{DEPS_DEV_API}/systems/{system}/packages/{name}/versions/{version}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return {"deprecated": False, "message": None}
        
        data = response.json()
        
        return {
            "deprecated": data.get("isDeprecated", False),
            "message": data.get("deprecationMessage"),
            "published_at": data.get("publishedAt"),
            "is_default": data.get("isDefault", False)
        }
        
    except Exception:
        return {"deprecated": False, "message": None}
