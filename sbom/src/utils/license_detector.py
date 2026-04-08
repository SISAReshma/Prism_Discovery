"""
License File Detector

Detects LICENSE files and third-party license information in repositories.
Supports:
1. LICENSE, LICENSE.txt, LICENSE.md, LICENSE.rst files in repo root
2. NOTICE files (Apache projects)
3. Third-party licenses in common directories
4. License detection from file content patterns
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Common license file names (case-insensitive)
LICENSE_FILE_PATTERNS = [
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "LICENSE.MIT",
    "LICENSE.APACHE",
    "LICENCE",
    "LICENCE.txt",
    "LICENCE.md",
    "COPYING",
    "COPYING.txt",
    "COPYING.LESSER",
    "UNLICENSE",
    "UNLICENSE.txt",
]

# NOTICE file patterns (often contains third-party attributions)
NOTICE_FILE_PATTERNS = [
    "NOTICE",
    "NOTICE.txt",
    "NOTICE.md",
    "NOTICES",
    "THIRD-PARTY-NOTICES.txt",
    "THIRD_PARTY_NOTICES.txt",
    "ThirdPartyNotices.txt",
    "3RD-PARTY-LICENSES.txt",
    "ATTRIBUTION",
    "ATTRIBUTION.txt",
    "CREDITS",
    "CREDITS.txt",
    "AUTHORS",
    "AUTHORS.txt",
]

# Directories that commonly contain third-party licenses
THIRD_PARTY_DIRS = [
    "licenses",
    "LICENSES",
    "third-party",
    "third_party",
    "thirdparty",
    "vendor",
    "external",
    "deps",
    "dependencies",
]

# License identification patterns (regex -> license name)
LICENSE_PATTERNS = {
    r"MIT License": "MIT",
    r"Permission is hereby granted, free of charge": "MIT",
    r"Apache License.*Version 2\.0": "Apache-2.0",
    r"Licensed under the Apache License": "Apache-2.0",
    r"GNU GENERAL PUBLIC LICENSE.*Version 3": "GPL-3.0",
    r"GNU GENERAL PUBLIC LICENSE.*Version 2": "GPL-2.0",
    r"GNU LESSER GENERAL PUBLIC LICENSE": "LGPL",
    r"GNU AFFERO GENERAL PUBLIC LICENSE": "AGPL-3.0",
    r"BSD 3-Clause License": "BSD-3-Clause",
    r"BSD 2-Clause License": "BSD-2-Clause",
    r"Redistribution and use in source and binary forms": "BSD",
    r"ISC License": "ISC",
    r"Mozilla Public License.*2\.0": "MPL-2.0",
    r"Eclipse Public License": "EPL",
    r"Creative Commons.*CC0": "CC0-1.0",
    r"The Unlicense": "Unlicense",
    r"DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE": "WTFPL",
    r"Boost Software License": "BSL-1.0",
    r"zlib License": "Zlib",
    r"Public Domain": "Public-Domain",
}


def detect_license_files(workspace: Path) -> Dict[str, Any]:
    """
    Detect all license-related files in a workspace.
    
    Args:
        workspace: Path to the repository/workspace root
        
    Returns:
        Dictionary containing:
        - project_license: Main project license info
        - license_files: List of license files found
        - notice_files: List of NOTICE/attribution files found
        - third_party_licenses: List of third-party license files
    """
    workspace = Path(workspace)
    result = {
        "project_license": None,
        "license_files": [],
        "notice_files": [],
        "third_party_licenses": [],
        "license_summary": []
    }
    
    if not workspace.exists():
        return result
    
    # 1. Find main LICENSE file in root
    for pattern in LICENSE_FILE_PATTERNS:
        for variant in [pattern, pattern.upper(), pattern.lower()]:
            license_path = workspace / variant
            if license_path.exists() and license_path.is_file():
                license_info = _parse_license_file(license_path)
                result["license_files"].append(license_info)
                
                # First license file found in root is the main project license
                if not result["project_license"]:
                    result["project_license"] = license_info
                break
    
    # 2. Find NOTICE/attribution files
    for pattern in NOTICE_FILE_PATTERNS:
        for variant in [pattern, pattern.upper(), pattern.lower()]:
            notice_path = workspace / variant
            if notice_path.exists() and notice_path.is_file():
                notice_info = _parse_notice_file(notice_path)
                result["notice_files"].append(notice_info)
    
    # 3. Find third-party license directories and files
    for dir_name in THIRD_PARTY_DIRS:
        for variant in [dir_name, dir_name.upper(), dir_name.lower()]:
            third_party_dir = workspace / variant
            if third_party_dir.exists() and third_party_dir.is_dir():
                third_party_licenses = _scan_third_party_dir(third_party_dir)
                result["third_party_licenses"].extend(third_party_licenses)
    
    # 4. Build license summary
    all_licenses = set()
    if result["project_license"]:
        all_licenses.add(result["project_license"].get("detected_license", "Unknown"))
    
    for lic_file in result["license_files"]:
        all_licenses.add(lic_file.get("detected_license", "Unknown"))
    
    for third_party in result["third_party_licenses"]:
        all_licenses.add(third_party.get("detected_license", "Unknown"))
    
    result["license_summary"] = list(all_licenses - {"Unknown"})
    
    return result


def _parse_license_file(file_path: Path) -> Dict[str, Any]:
    """Parse a license file and detect its type."""
    result = {
        "file": file_path.name,
        "path": str(file_path),
        "relative_path": file_path.name,
        "detected_license": "Unknown",
        "content_preview": ""
    }
    
    try:
        # Read file content (first 5000 chars for detection)
        content = file_path.read_text(encoding="utf-8", errors="ignore")[:5000]
        result["content_preview"] = content[:500] + "..." if len(content) > 500 else content
        
        # Detect license type from content
        result["detected_license"] = _identify_license_from_content(content)
        
    except Exception as e:
        logger.warning(f"Failed to parse license file {file_path}: {e}")
        result["error"] = str(e)
    
    return result


def _parse_notice_file(file_path: Path) -> Dict[str, Any]:
    """Parse a NOTICE/attribution file."""
    result = {
        "file": file_path.name,
        "path": str(file_path),
        "type": "notice",
        "libraries_mentioned": []
    }
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # Try to extract library names from NOTICE file
        # Common patterns: "This product includes software developed by..."
        # Or line-by-line library attributions
        libraries = _extract_libraries_from_notice(content)
        result["libraries_mentioned"] = libraries
        
    except Exception as e:
        logger.warning(f"Failed to parse notice file {file_path}: {e}")
        result["error"] = str(e)
    
    return result


def _scan_third_party_dir(directory: Path) -> List[Dict[str, Any]]:
    """Scan a third-party directory for license files."""
    third_party_licenses = []
    
    try:
        for item in directory.iterdir():
            if item.is_file():
                # Check if it looks like a license file
                if any(pattern.lower() in item.name.lower() for pattern in ["license", "licence", "copying", "notice"]):
                    license_info = _parse_license_file(item)
                    license_info["third_party"] = True
                    third_party_licenses.append(license_info)
            elif item.is_dir():
                # Check subdirectory for LICENSE file
                for pattern in LICENSE_FILE_PATTERNS[:4]:  # Just check main patterns
                    license_file = item / pattern
                    if license_file.exists():
                        license_info = _parse_license_file(license_file)
                        license_info["library"] = item.name
                        license_info["third_party"] = True
                        third_party_licenses.append(license_info)
                        break
    except Exception as e:
        logger.warning(f"Failed to scan third-party directory {directory}: {e}")
    
    return third_party_licenses


def _identify_license_from_content(content: str) -> str:
    """Identify license type from file content using patterns."""
    content_upper = content.upper()
    
    for pattern, license_name in LICENSE_PATTERNS.items():
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            return license_name
    
    # Fallback heuristics
    if "MIT" in content_upper and "LICENSE" in content_upper:
        return "MIT"
    elif "APACHE" in content_upper and "2.0" in content:
        return "Apache-2.0"
    elif "GPL" in content_upper:
        if "VERSION 3" in content_upper or "V3" in content_upper:
            return "GPL-3.0"
        elif "VERSION 2" in content_upper or "V2" in content_upper:
            return "GPL-2.0"
        return "GPL"
    elif "BSD" in content_upper:
        return "BSD"
    elif "ISC" in content_upper:
        return "ISC"
    
    return "Unknown"


def _extract_libraries_from_notice(content: str) -> List[str]:
    """Extract library names mentioned in NOTICE files."""
    libraries = []
    
    # Common patterns in NOTICE files
    patterns = [
        r"This product includes (?:software developed by|the following).*?:\s*([^\n]+)",
        r"([A-Za-z][A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+)?)\s+(?:Copyright|Licensed under)",
        r"^([A-Za-z][A-Za-z0-9_-]+)\s*(?:-|:)\s*(?:MIT|Apache|BSD|GPL)",
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            lib_name = match.strip() if isinstance(match, str) else match[0].strip()
            if lib_name and len(lib_name) > 2 and lib_name not in libraries:
                libraries.append(lib_name)
    
    return libraries[:50]  # Limit to 50 libraries


def get_license_summary_for_sbom(workspace: Path) -> Dict[str, Any]:
    """
    Get a license summary suitable for including in SBOM.
    
    Returns:
        Dictionary with:
        - declared_license: The main project license
        - license_files: List of license files found
        - third_party_count: Number of third-party licenses found
    """
    detection = detect_license_files(workspace)
    
    summary = {
        "declared_license": "NOASSERTION",
        "license_files_found": len(detection["license_files"]),
        "third_party_licenses_found": len(detection["third_party_licenses"]),
        "notice_files_found": len(detection["notice_files"]),
        "all_licenses": detection["license_summary"]
    }
    
    if detection["project_license"]:
        summary["declared_license"] = detection["project_license"].get("detected_license", "NOASSERTION")
        summary["license_file"] = detection["project_license"].get("file", "")
    
    return summary


# Convenience function for API endpoints
def detect_repo_licenses(workspace_path: str) -> Dict[str, Any]:
    """
    Detect licenses in a repository workspace.
    
    Args:
        workspace_path: Path to the cloned/extracted repository
        
    Returns:
        Complete license detection results
    """
    return detect_license_files(Path(workspace_path))
