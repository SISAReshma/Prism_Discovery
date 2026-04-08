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
