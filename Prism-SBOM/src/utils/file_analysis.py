"""
File analysis utilities for detecting package properties.
Includes codebase-level scanning per CERT-IN guidelines.
"""

from pathlib import Path
from typing import Dict, Any, List, Set, NamedTuple
import stat
import json
import os

# Import constants from config (single source of truth)
from src.config.config import (
    EXECUTABLE_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    STRUCTURED_EXTENSIONS
)

# Import package-specific property detection helpers
from src.utils.package_properties import (
    detect_executable_for_package,
    detect_archive_for_package,
    detect_structured_for_package
)


class CodebaseAnalysis(NamedTuple):
    """Results of codebase-level property scanning."""
    executable_files: List[str]
    archive_files: List[str]
    structured_files: List[str]
    executable_summary: str
    archive_summary: str
    structured_summary: str
    has_executable: bool
    has_archive: bool
    has_structured: bool


def scan_codebase_properties(workspace: Path) -> CodebaseAnalysis:
    """
    Scan codebase for CERT-IN required properties.
    
    Per CERT-IN guidelines, these properties describe what the CODEBASE contains:
    1. EXECUTABLE - Does the codebase contain executable files? (.exe, .dll, .sh, .bat, .ps1)
    2. ARCHIVE - Does the codebase contain archive/compressed files? (.zip, .tar.gz, .jar, .whl)
    3. STRUCTURED - Does the codebase contain structured configuration files? (.json, .xml, .yaml)
    
    Args:
        workspace: Path to the codebase/repository
        
    Returns:
        CodebaseAnalysis with detected files and summary strings
    """
    executable_files = []
    archive_files = []
    structured_files = []
    
    # Skip these directories
    skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env', '.env', 
                 '.tox', '.pytest_cache', '.mypy_cache', 'dist', 'build', 'egg-info'}
    
    try:
        for root, dirs, files in os.walk(workspace):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith('.egg-info')]
            
            for filename in files:
                file_path = Path(root) / filename
                rel_path = str(file_path.relative_to(workspace))
                ext = filename.lower().split('.')[-1] if '.' in filename else ''
                full_ext = '.' + ext if ext else ''
                
                # Check for .tar.gz specifically
                if filename.endswith('.tar.gz'):
                    archive_files.append(rel_path)
                    continue
                
                # Check executable extensions
                if full_ext in EXECUTABLE_EXTENSIONS:
                    executable_files.append(rel_path)
                
                # Check archive extensions
                elif full_ext in ARCHIVE_EXTENSIONS:
                    archive_files.append(rel_path)
                
                # Check structured extensions
                elif full_ext in STRUCTURED_EXTENSIONS:
                    structured_files.append(rel_path)
    except Exception as e:
        print(f"[WARNING] Codebase scan error: {e}")
    
    # Build summary strings
    has_executable = len(executable_files) > 0
    has_archive = len(archive_files) > 0
    has_structured = len(structured_files) > 0
    
    if has_executable:
        sample = executable_files[:3]
        executable_summary = f"Yes - {len(executable_files)} file(s): {', '.join(sample)}" + ("..." if len(executable_files) > 3 else "")
    else:
        executable_summary = "No"
    
    if has_archive:
        sample = archive_files[:3]
        archive_summary = f"Yes - {len(archive_files)} file(s): {', '.join(sample)}" + ("..." if len(archive_files) > 3 else "")
    else:
        archive_summary = "No"
    
    if has_structured:
        sample = structured_files[:3]
        structured_summary = f"Yes - {len(structured_files)} file(s): {', '.join(sample)}" + ("..." if len(structured_files) > 3 else "")
    else:
        structured_summary = "No"
    
    return CodebaseAnalysis(
        executable_files=executable_files,
        archive_files=archive_files,
        structured_files=structured_files,
        executable_summary=executable_summary,
        archive_summary=archive_summary,
        structured_summary=structured_summary,
        has_executable=has_executable,
        has_archive=has_archive,
        has_structured=has_structured
    )


def detect_executable_property(pkg: Dict[str, Any], workspace: Path) -> str:
    """
    Detect if package contains executable files.
    
    Delegates to package_properties.py helper for package-specific detection.
    
    Args:
        pkg: Package dictionary with name, version, language
        workspace: Workspace root path (unused, kept for API compatibility)
    
    Returns:
        String describing executable property (Yes/No with details)
    """
    # Use centralized helper from package_properties.py
    return detect_executable_for_package(pkg)


def detect_archive_property(pkg: Dict[str, Any]) -> str:
    """
    Detect if package is distributed as an archive.
    
    Delegates to package_properties.py helper.
    
    Args:
        pkg: Package dictionary with language/ecosystem
    
    Returns:
        String describing archive property
    """
    # Use centralized helper from package_properties.py
    return detect_archive_for_package(pkg)


def detect_structured_property(pkg: Dict[str, Any], workspace: Path) -> str:
    """
    Detect if package contains structured configuration files.
    
    Delegates to package_properties.py helper for package-specific detection.
    
    Args:
        pkg: Package dictionary with name, version, language
        workspace: Workspace root path (unused, kept for API compatibility)
    
    Returns:
        String describing structured property (Yes/No with details)
    """
    # Use centralized helper from package_properties.py
    return detect_structured_for_package(pkg)


def calculate_criticality(pkg: Dict[str, Any]) -> str:
    """
    Calculate package criticality based on multiple factors.
    
    Factors:
    1. Vulnerability count and severity (0-50 points)
    2. Number of dependencies (0-20 points)
    3. License type (0-15 points)
    4. EOL status (0-15 points)
    
    Scoring:
    - 0-25: Low
    - 26-50: Medium
    - 51-75: High
    - 76+: Critical
    
    Args:
        pkg: Package dictionary
    
    Returns:
        Criticality level: "Critical", "High", "Medium", or "Low"
    """
    score = 0
    
    # Factor 1: Vulnerabilities (0-50 points)
    vulns = pkg.get("vulnerabilities", [])
    
    critical_count = 0
    high_count = 0
    medium_count = 0
    
    for v in vulns:
        severity = str(v.get("severity_string", "")).upper()
        
        if "CRITICAL" in severity or "9." in severity or "10." in severity:
            critical_count += 1
        elif "HIGH" in severity or "7." in severity or "8." in severity:
            high_count += 1
        elif "MEDIUM" in severity or "4." in severity or "5." in severity or "6." in severity:
            medium_count += 1
    
    score += critical_count * 15  # 15 points per critical
    score += high_count * 8       # 8 points per high
    score += medium_count * 3     # 3 points per medium
    score = min(score, 50)        # Cap at 50
    
    # Factor 2: Dependencies (0-20 points)
    deps = pkg.get("component_dependencies", [])
    dep_count = len(deps) if isinstance(deps, list) else 0
    
    if dep_count >= 50:
        score += 20
    elif dep_count >= 25:
        score += 15
    elif dep_count >= 10:
        score += 10
    elif dep_count >= 5:
        score += 5
    
    # Factor 3: License risk (0-15 points)
    license_str = pkg.get("component_license", "").upper()
    
    if "GPL" in license_str or "AGPL" in license_str:
        score += 15  # Copyleft = higher legal risk
    elif "PROPRIETARY" in license_str or "COMMERCIAL" in license_str:
        score += 12  # Proprietary = licensing risk
    elif license_str == "NOASSERTION" or not license_str:
        score += 10  # Unknown license = compliance risk
    elif "LGPL" in license_str:
        score += 8   # LGPL = moderate risk
    
    # Factor 4: EOL status (0-15 points)
    eol_date = pkg.get("eol_date", "")
    
    if "Expired" in eol_date:
        score += 15  # Expired = critical risk
    elif eol_date and eol_date != "Active":
        # Check if EOL is soon (within 6 months)
        try:
            from datetime import datetime, timedelta
            eol_dt = datetime.fromisoformat(eol_date.replace(" (", "").replace(")", ""))
            if eol_dt < datetime.now() + timedelta(days=180):
                score += 10  # EOL soon = high risk
            else:
                score += 5   # EOL in future = moderate risk
        except Exception:
            score += 5
    
    # Categorize
    if score >= 76:
        return "Critical"
    elif score >= 51:
        return "High"
    elif score >= 26:
        return "Medium"
    else:
        return "Low"
