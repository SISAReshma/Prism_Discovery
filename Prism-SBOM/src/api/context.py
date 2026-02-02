"""Shared API context (paths, orchestrator, rate limiter)."""

from __future__ import annotations

from pathlib import Path

from src.config.config import REPORTS_DIR as CONFIG_REPORTS_DIR, TEMP_DIR as CONFIG_TEMP_DIR
from src.api.services.rate_limits import init_rate_limiter
from src.core.orchestrator import ScanOrchestrator

REPORTS_DIR = Path(CONFIG_REPORTS_DIR)
TEMP_DIR = Path(CONFIG_TEMP_DIR)

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# Initialize rate limiter for all external APIs
github_rate_limiter = init_rate_limiter()

# Initialize global orchestrator instance
orchestrator = ScanOrchestrator(
    reports_dir=str(REPORTS_DIR),
    temp_dir=str(TEMP_DIR),
)
