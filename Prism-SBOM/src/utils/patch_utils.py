"""
Patch status calculator.
Determines if packages have available patches for known vulnerabilities.
"""

from typing import List, Dict, Any, Optional
from packaging import version


def determine_patch_status(pkg_version: str, vulnerabilities: List[Dict[str, Any]]) -> str:
    """
    Determine patch status for a package.
    
    Compares current version against fixed versions from vulnerabilities.
    
    Args:
        pkg_version: Current package version
        vulnerabilities: List of vulnerability dictionaries with 'fixed_in' field
    
    Returns:
        Patch status: "Up to date", "Patched", "Patch Available", "No patch available", or "Unknown"
    """
    if not vulnerabilities:
        return "Up to date - No known vulnerabilities"
    
    if not pkg_version or pkg_version == "UNKNOWN":
        return "Unknown - Version information unavailable"
    
    try:
        current = version.parse(pkg_version)
    except Exception:
        return "Unknown - Invalid version format"
    
    # Track patch availability
    all_patched = True
    patches_available = False
    no_fixes = 0
    
    for vuln in vulnerabilities:
        fixed_versions = vuln.get("fixed_in", [])
        
        if not fixed_versions:
            # No fix available for this vulnerability
            no_fixes += 1
            all_patched = False
            continue
        
        # Check if current version >= any fixed version
        is_patched = False
        for fixed_ver in fixed_versions:
            try:
                fixed = version.parse(str(fixed_ver))
                if current >= fixed:
                    is_patched = True
                    break
            except Exception:
                continue
        
        if is_patched:
            patches_available = True
        else:
            all_patched = False
            patches_available = True  # Fix exists but not applied
    
    # Determine status
    if all_patched:
        return "Patched - All known vulnerabilities fixed in current version"
    elif patches_available:
        vuln_count = len(vulnerabilities)
        fixed_count = sum(1 for v in vulnerabilities if v.get("fixed_in"))
        return f"Patch Available - {fixed_count}/{vuln_count} vulnerabilities have patches. Upgrade recommended."
    elif no_fixes == len(vulnerabilities):
        return f"No patch available - {no_fixes} vulnerabilities have no known fixes"
    else:
        return "Unknown - Unable to determine patch status"


def get_recommended_version(pkg_version: str, vulnerabilities: List[Dict[str, Any]]) -> Optional[str]:
    """
    Get recommended version to fix vulnerabilities.
    
    Args:
        pkg_version: Current package version
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        Recommended version string, or None if no recommendation
    """
    if not vulnerabilities or not pkg_version or pkg_version == "UNKNOWN":
        return None
    
    try:
        current = version.parse(pkg_version)
    except Exception:
        return None
    
    # Collect all fixed versions
    fixed_versions = []
    for vuln in vulnerabilities:
        for fixed_ver in vuln.get("fixed_in", []):
            try:
                fixed_versions.append(version.parse(str(fixed_ver)))
            except Exception:
                continue
    
    if not fixed_versions:
        return None
    
    # Find the minimum version that fixes all vulnerabilities
    # This is the smallest version >= current that appears in all fixed_in lists
    
    # Get unique fixed versions greater than current
    candidates = sorted(set(v for v in fixed_versions if v > current))
    
    if not candidates:
        # Already at or above all fixed versions
        return None
    
    # Return the minimum recommended version
    return str(candidates[0])


def count_vulnerable_packages(packages: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count packages by patch status.
    
    Args:
        packages: List of package dictionaries
    
    Returns:
        Dictionary with counts: {
            "up_to_date": int,
            "patched": int,
            "patch_available": int,
            "no_patch": int,
            "unknown": int
        }
    """
    counts = {
        "up_to_date": 0,
        "patched": 0,
        "patch_available": 0,
        "no_patch": 0,
        "unknown": 0
    }
    
    for pkg in packages:
        patch_status = pkg.get("patch_status", "Unknown")
        
        if "Up to date" in patch_status:
            counts["up_to_date"] += 1
        elif "Patched" in patch_status:
            counts["patched"] += 1
        elif "Patch Available" in patch_status:
            counts["patch_available"] += 1
        elif "No patch" in patch_status:
            counts["no_patch"] += 1
        else:
            counts["unknown"] += 1
    
    return counts
