"""Ecosystem detection helpers for API endpoints."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple, List, Dict

from src.registry.language_registry import get_supported_manifest_files, get_all_manifest_files


def detect_ecosystems(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    Detect ecosystems from files in a directory.
    Returns: (ecosystems_list, manifest_files_list)
    """
    supported = get_supported_manifest_files()
    ecosystems = set()
    manifest_files = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ["node_modules", "venv", ".venv", ".git", "__pycache__", ".cache"]]

        for file_name in files:
            file_lower = file_name.lower()
            for ecosystem, supported_files in supported.items():
                if file_lower in [f.lower() for f in supported_files]:
                    ecosystems.add(ecosystem)
                    full_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(full_path, path)
                    manifest_files.append(
                        {
                            "file": file_name,
                            "path": full_path,
                            "relative_path": rel_path,
                            "ecosystem": ecosystem,
                        }
                    )
                    break

    return list(ecosystems), manifest_files


def is_supported_file(filename: str) -> bool:
    """Check if file is a supported manifest file."""
    base_name = os.path.basename(filename).lower()
    for f in get_all_manifest_files():
        if base_name == f.lower():
            return True
    return False
