"""
License-based usage restriction analyzer.
Maps license types to their usage restrictions and compliance requirements.
"""

from typing import Dict, Any


# License categories and their restrictions
LICENSE_RESTRICTIONS = {
    # GPL Family - Strong Copyleft
    "GPL": {
        "restriction": "Copyleft: Derivative works must be open-sourced under GPL. Commercial use requires compliance review.",
        "risk": "High",
        "category": "Copyleft"
    },
    "AGPL": {
        "restriction": "Strong Copyleft: Network use = distribution. Derivative works must be open-sourced under AGPL. SaaS deployments require source disclosure.",
        "risk": "Critical",
        "category": "Copyleft"
    },
    "LGPL": {
        "restriction": "Weak Copyleft: Dynamic linking permitted. Modifications to LGPL code must be open-sourced. Static linking requires full source disclosure.",
        "risk": "Medium",
        "category": "Copyleft"
    },
    
    # Permissive Licenses
    "MIT": {
        "restriction": "Permissive: Minimal restrictions. Attribution required. No warranty. Commercial use permitted.",
        "risk": "Low",
        "category": "Permissive"
    },
    "BSD": {
        "restriction": "Permissive: Attribution required. No warranty. No endorsement without permission. Commercial use permitted.",
        "risk": "Low",
        "category": "Permissive"
    },
    "APACHE": {
        "restriction": "Permissive: Attribution required. Patent grant included. Trademark restrictions apply. Commercial use permitted.",
        "risk": "Low",
        "category": "Permissive"
    },
    "ISC": {
        "restriction": "Permissive: Minimal restrictions. Attribution required. No warranty. Commercial use permitted.",
        "risk": "Low",
        "category": "Permissive"
    },
    "0BSD": {
        "restriction": "Public Domain: No restrictions. No attribution required. Commercial use permitted.",
        "risk": "Minimal",
        "category": "Public Domain"
    },
    
    # Proprietary/Commercial
    "PROPRIETARY": {
        "restriction": "Proprietary: All rights reserved. Redistribution prohibited. Commercial use subject to license agreement. Review contract terms.",
        "risk": "High",
        "category": "Proprietary"
    },
    "COMMERCIAL": {
        "restriction": "Commercial: Usage subject to paid license agreement. Redistribution prohibited. Review contract terms for restrictions.",
        "risk": "High",
        "category": "Proprietary"
    },
    
    # Creative Commons (Not recommended for software)
    "CC-BY": {
        "restriction": "Attribution required. Suitable for documentation and media, NOT recommended for software. Commercial use permitted.",
        "risk": "Medium",
        "category": "Creative Commons"
    },
    "CC-BY-SA": {
        "restriction": "Attribution + ShareAlike required. Suitable for documentation, NOT for software. Derivative works must use same license.",
        "risk": "Medium",
        "category": "Creative Commons"
    },
    "CC0": {
        "restriction": "Public Domain: No restrictions. No attribution required. Suitable for documentation and data.",
        "risk": "Minimal",
        "category": "Public Domain"
    },
    
    # Other Common Licenses
    "MOZILLA": {
        "restriction": "Weak Copyleft: File-level copyleft. Modified MPL files must remain open-source. Can be combined with proprietary code.",
        "risk": "Medium",
        "category": "Copyleft"
    },
    "MPL": {
        "restriction": "Weak Copyleft: File-level copyleft. Modified MPL files must remain open-source. Can be combined with proprietary code.",
        "risk": "Medium",
        "category": "Copyleft"
    },
    "UNLICENSE": {
        "restriction": "Public Domain: No restrictions. No attribution required. Commercial use permitted.",
        "risk": "Minimal",
        "category": "Public Domain"
    },
    "WTFPL": {
        "restriction": "Public Domain: No restrictions. Do What The F*** You Want. Commercial use permitted.",
        "risk": "Minimal",
        "category": "Public Domain"
    },
}


def determine_usage_restrictions(license_str: str) -> str:
    """
    Determine usage restrictions based on license type.
    
    Args:
        license_str: License identifier (e.g., "MIT", "GPL-3.0", "Apache-2.0")
    
    Returns:
        Human-readable usage restriction description
    """
    if not license_str or license_str in ["NOASSERTION", "NONE"]:
        return "Unknown License: Manual review required. Cannot determine usage restrictions without license information. ⚠️ COMPLIANCE RISK"
    
    license_upper = license_str.upper()
    
    # Check for multiple licenses (dual/multi-licensing)
    if " OR " in license_upper or " AND " in license_upper or "/" in license_upper:
        return f"Multiple Licenses: {license_str}. Review each license individually. Choose most permissive option if dual-licensed."
    
    # Try exact matches first
    for key, info in LICENSE_RESTRICTIONS.items():
        if key in license_upper:
            restriction = info["restriction"]
            risk = info["risk"]
            return f"{restriction} [Risk Level: {risk}]"
    
    # Fallback for unknown licenses
    return f"Unknown License Type: {license_str}. Manual compliance review required. Consult legal team before use."


def get_license_risk_level(license_str: str) -> str:
    """
    Get risk level for a license.
    
    Args:
        license_str: License identifier
    
    Returns:
        Risk level: "Critical", "High", "Medium", "Low", "Minimal", or "Unknown"
    """
    if not license_str or license_str in ["NOASSERTION", "NONE"]:
        return "Unknown"
    
    license_upper = license_str.upper()
    
    for key, info in LICENSE_RESTRICTIONS.items():
        if key in license_upper:
            return info["risk"]
    
    return "Unknown"


def get_license_category(license_str: str) -> str:
    """
    Get license category.
    
    Args:
        license_str: License identifier
    
    Returns:
        Category: "Copyleft", "Permissive", "Proprietary", "Public Domain", "Creative Commons", or "Unknown"
    """
    if not license_str or license_str in ["NOASSERTION", "NONE"]:
        return "Unknown"
    
    license_upper = license_str.upper()
    
    for key, info in LICENSE_RESTRICTIONS.items():
        if key in license_upper:
            return info["category"]
    
    return "Unknown"


def is_copyleft_license(license_str: str) -> bool:
    """
    Check if license is copyleft (GPL family).
    
    Args:
        license_str: License identifier
    
    Returns:
        True if copyleft, False otherwise
    """
    if not license_str:
        return False
    
    license_upper = license_str.upper()
    copyleft_indicators = ["GPL", "AGPL", "LGPL", "MPL", "MOZILLA", "EUPL"]
    
    return any(indicator in license_upper for indicator in copyleft_indicators)


def is_permissive_license(license_str: str) -> bool:
    """
    Check if license is permissive (MIT, BSD, Apache).
    
    Args:
        license_str: License identifier
    
    Returns:
        True if permissive, False otherwise
    """
    if not license_str:
        return False
    
    license_upper = license_str.upper()
    permissive_indicators = ["MIT", "BSD", "APACHE", "ISC", "UNLICENSE", "0BSD"]
    
    return any(indicator in license_upper for indicator in permissive_indicators)


def requires_attribution(license_str: str) -> bool:
    """
    Check if license requires attribution.
    
    Args:
        license_str: License identifier
    
    Returns:
        True if attribution required, False otherwise
    """
    if not license_str:
        return False
    
    license_upper = license_str.upper()
    
    # Most licenses require attribution except public domain
    no_attribution = ["UNLICENSE", "0BSD", "WTFPL", "CC0"]
    
    for indicator in no_attribution:
        if indicator in license_upper:
            return False
    
    # If it's a known license, assume attribution required
    for key in LICENSE_RESTRICTIONS.keys():
        if key in license_upper and key not in ["UNLICENSE", "0BSD", "WTFPL"]:
            return True
    
    return True  # Conservative default
