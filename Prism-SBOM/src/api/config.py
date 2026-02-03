"""
SBOM API Configuration Constants
Centralized constants and mappings for the SBOM API
"""

from typing import Literal

# =============================================================================
# SOURCE TYPES
# =============================================================================

SOURCE_TYPES = Literal["repo_public", "repo_private", "zip", "local"]

# Mapping of source types to their validate endpoints
ENDPOINT_MAP = {
    "repo_public": "/validate/repo_public",
    "repo_private": "/validate/repo_private",
    "zip": "/validate/zip",
    "local": "/validate/local"
}

# =============================================================================
# FILE/UPLOAD LIMITS
# =============================================================================

MAX_UPLOAD_SIZE_MB = 500
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 500MB

MAX_ZIP_FILE_COUNT = 50000
MAX_LOCAL_FILE_COUNT = 10000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file

# =============================================================================
# TEMP DIRECTORY
# =============================================================================

TEMP_DIR_PREFIX = "sbom_"

# Directories to skip when counting files
SKIP_DIRECTORIES = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git', 'egg-info'}

# =============================================================================
# GITHUB SETTINGS
# =============================================================================

GITHUB_API_TIMEOUT = 10  # seconds
GITHUB_CLONE_TIMEOUT = 300  # seconds (5 minutes)

# Valid PAT prefixes for GitHub
VALID_PAT_PREFIXES = ('ghp_', 'github_pat_')

# Supported providers
SUPPORTED_PROVIDERS = ['github.com', 'gitlab.com', 'bitbucket.org']

# =============================================================================
# RATE LIMITER SETTINGS
# =============================================================================

RATE_LIMITS = {
    'github': {'limit': 60, 'window': 3600},      # 60/hr unauthenticated
    'depsdev': {'limit': 1000, 'window': 3600},   # Google API, generous
    'pypi': {'limit': 600, 'window': 3600},       # ~100/min
    'npm': {'limit': 600, 'window': 3600},        # ~100/min
    'osv': {'limit': 500, 'window': 3600},        # OSV.dev
}

# =============================================================================
# TOOL INFO
# =============================================================================

TOOL_NAME = "SBOM"
TOOL_VERSION = "1.0.0"
TOOL_VENDOR = "StackSQ"

# =============================================================================
# CODE FILE EXTENSIONS (for AIBOM compatibility)
# =============================================================================

CODE_FILE_EXTENSIONS = {
    '.py', '.pyx', '.pxd', '.pyi',
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.java', '.kt', '.scala',
    '.c', '.cpp', '.h', '.hpp',
    '.go', '.rs', '.rb', '.php',
}
