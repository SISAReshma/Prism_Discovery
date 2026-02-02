"""Workspace cleanup helpers for API step-by-step flow."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional


def cleanup_temp_workspace(temp_path: Optional[Path], temp_root: Path) -> bool:
    """
    Cleanup a temp workspace path if it is under temp_root.

    Returns True if cleanup attempted, False otherwise.
    """
    if not temp_path:
        return False

    try:
        path = Path(temp_path)
        if path.exists() and str(path).startswith(str(temp_root)):
            shutil.rmtree(path, ignore_errors=True)
            return True
    except Exception:
        return False

    return False
