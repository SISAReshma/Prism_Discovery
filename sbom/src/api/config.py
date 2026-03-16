"""
SBOM API Configuration Constants
Centralized constants and mappings for the SBOM API
"""

from typing import Literal

# =============================================================================
# SOURCE TYPES (Deprecated - kept for backward compatibility)
# =============================================================================

# =============================================================================
# FILE/UPLOAD LIMITS
# =============================================================================

MAX_UPLOAD_SIZE_MB: int = 500
MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 500MB

MAX_ZIP_FILE_COUNT: int = 50000
MAX_LOCAL_FILE_COUNT: int = 10000
MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB per file

# =============================================================================
# TEMP DIRECTORY
# =============================================================================

TEMP_DIR_PREFIX: str = "sbom_"

# Directories to skip when counting files
SKIP_DIRECTORIES: set[str] = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git', 'egg-info'}

# =============================================================================
# GITHUB SETTINGS
# =============================================================================

GITHUB_API_TIMEOUT: int = 10  # seconds
GITHUB_CLONE_TIMEOUT: int = 300  # seconds (5 minutes)

# Valid PAT prefixes for GitHub
VALID_PAT_PREFIXES: tuple[str, ...] = ('ghp_', 'github_pat_')

# Supported providers
SUPPORTED_PROVIDERS: list[str] = ['github.com', 'gitlab.com', 'bitbucket.org']

# =============================================================================
# ENDPOINT MAPPING
# =============================================================================

ENDPOINT_MAP: dict[str, str] = {
    'github': '/set_repository',
    'local': '/upload',
    'zip': '/upload_zip',
}

# =============================================================================
# RATE LIMITER SETTINGS
# =============================================================================

RATE_LIMITS: dict[str, dict[str, int]] = {
    'github': {'limit': 60, 'window': 3600},      # 60/hr unauthenticated
    'depsdev': {'limit': 1000, 'window': 3600},   # Google API, generous
    'pypi': {'limit': 3000, 'window': 3600},      # PyPI public API, generous
    'npm': {'limit': 3000, 'window': 3600},       # npm public registry, generous
    'osv': {'limit': 500, 'window': 3600},        # OSV.dev
}

# =============================================================================
# TOOL INFO
# =============================================================================

TOOL_NAME: str = "SBOM"
TOOL_VERSION: str = "1.0.0"
TOOL_VENDOR: str = "StackSQ"

# =============================================================================
# CODE FILE EXTENSIONS (for AIBOM compatibility)
# =============================================================================

CODE_FILE_EXTENSIONS: set[str] = {
    '.py', '.pyx', '.pxd', '.pyi',
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.java', '.kt', '.scala',
    '.c', '.cpp', '.h', '.hpp',
    '.go', '.rs', '.rb', '.php',
}
