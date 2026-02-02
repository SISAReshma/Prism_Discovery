"""
End-of-Life (EOL) date detection for packages.
Integrates with endoflife.date API to determine support lifecycle.
"""

from typing import Optional, Dict, Any
import requests
from functools import lru_cache
from datetime import datetime


EOL_API_BASE = "https://endoflife.date/api"

# Map package ecosystems to endoflife.date product names
ECOSYSTEM_TO_PRODUCT = {
    "pypi": "python",
    "npm": "nodejs",
    # Add more mappings as needed
}


@lru_cache(maxsize=512)
def query_eol_date(product_name: str, version: str) -> Optional[str]:
    """
    Query endoflife.date API for EOL information.
    
    Args:
        product_name: Product name (e.g., "python", "nodejs")
        version: Version string (e.g., "3.9.0", "16.0.0")
    
    Returns:
        EOL date as ISO string, "Active" if not EOL, "Expired" if past EOL, or None if unknown
    """
    try:
        url = f"{EOL_API_BASE}/{product_name}.json"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        # Parse version to get major.minor
        from packaging import version as pkg_version
        try:
            target_version = pkg_version.parse(version)
            target_major = target_version.major
            target_minor = getattr(target_version, 'minor', 0)
        except Exception:
            # If parsing fails, try string matching
            version_parts = version.split(".")
            target_major = int(version_parts[0]) if len(version_parts) > 0 else 0
            target_minor = int(version_parts[1]) if len(version_parts) > 1 else 0
        
        # Find matching release cycle
        for release in data:
            cycle = release.get("cycle", "")
            
            # Try to match cycle to version
            try:
                # Cycle might be "3.9", "16", "11.0", etc.
                cycle_parts = str(cycle).split(".")
                cycle_major = int(cycle_parts[0])
                cycle_minor = int(cycle_parts[1]) if len(cycle_parts) > 1 else 0
                
                # Match major.minor
                if cycle_major == target_major:
                    if len(cycle_parts) == 1 or cycle_minor == target_minor:
                        eol = release.get("eol")
                        
                        if isinstance(eol, bool):
                            return "Expired" if eol else "Active"
                        elif isinstance(eol, str):
                            # Check if date is in the past
                            try:
                                eol_date = datetime.fromisoformat(eol)
                                if eol_date < datetime.now():
                                    return f"Expired ({eol})"
                                else:
                                    return eol
                            except Exception:
                                return eol
                        
            except (ValueError, TypeError):
                continue
        
        return None
        
    except Exception as e:
        # Silently fail - EOL is optional metadata
        return None


def get_eol_for_package(ecosystem: str, name: str, version: str) -> str:
    """
    Get EOL date for a package.
    
    NOTE: This checks runtime/language EOL (Python, Node.js, etc.),
    NOT individual package/library EOL (Flask, Express, etc.)
    
    Most libraries don't have official EOL dates, only the runtime does.
    
    Args:
        ecosystem: Package ecosystem (pypi, npm, etc.)
        name: Package name
        version: Package version
    
    Returns:
        EOL date string, "Active", "Expired", or empty string if unknown
    """
    # Only check EOL for runtime/language packages, not libraries
    # Libraries don't have official EOL dates like runtimes do
    
    # Skip EOL check for individual packages - it's misleading
    # The endoflife.date API is for runtimes (Python, Node, Java),
    # not for individual libraries (Flask, Express, Spring)
    
    # TODO: In the future, add explicit EOL checking only for:
    # - Python runtime (python package itself)
    # - Node.js runtime (nodejs package itself)
    # But skip for all application libraries
    
    return ""  # Disabled for now - was causing wrong EOL dates for libraries


def is_eol_expired(eol_date_str: str) -> bool:
    """
    Check if an EOL date indicates the package is expired.
    
    Args:
        eol_date_str: EOL date string (ISO format, "Expired", "Active", etc.)
    
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
