"""
DEPRECATED: Package-specific property detection helpers.

NOTE: As of CERT-IN compliance update, executable/archive/structured_properties
are now detected via CODEBASE SCANNING (see file_analysis.py), not per-package
from registry APIs.

These functions are kept for backward compatibility but should not be used.
Use src.utils.file_analysis.scan_codebase_properties() instead.
"""

from typing import Dict, Any


def detect_executable_for_package(pkg: Dict[str, Any]) -> str:
    """
    DEPRECATED: Use scan_codebase_properties() from file_analysis.py instead.
    
    Per CERT-IN guidelines, executable property now describes what the CODEBASE
    contains, not individual packages from registries.
    """
    return "Pending - Use codebase scanning"


def detect_archive_for_package(pkg: Dict[str, Any]) -> str:
    """
    DEPRECATED: Use scan_codebase_properties() from file_analysis.py instead.
    
    Per CERT-IN guidelines, archive property now describes what the CODEBASE
    contains, not individual packages from registries.
    """
    return "Pending - Use codebase scanning"


def detect_structured_for_package(pkg: Dict[str, Any]) -> str:
    """
    DEPRECATED: Use scan_codebase_properties() from file_analysis.py instead.
    
    Per CERT-IN guidelines, structured_properties now describes what the CODEBASE
    contains, not individual packages from registries.
    """
    return "Pending - Use codebase scanning"
