"""
Configuration file for StackSQScanner

Contains tool metadata, settings, and constants.
All values can be overridden via environment variables or .env file.
"""
import os
from pathlib import Path

# Load .env file if it exists (from project root)
try:
    from dotenv import load_dotenv
    # Find the project root (where .env should be)
    project_root = Path(__file__).parent.parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    # python-dotenv not installed, rely on system environment variables
    pass

# Tool Information (used in SBOM generation)
# Override via: STACKSQ_TOOL_NAME, STACKSQ_TOOL_VENDOR, etc.
TOOL_NAME = os.environ.get("STACKSQ_TOOL_NAME", "SBOM")
TOOL_VENDOR = os.environ.get("STACKSQ_TOOL_VENDOR", "SISA Information Security Pvt. Ltd")
TOOL_VERSION = os.environ.get("STACKSQ_TOOL_VERSION", "1.0.0")
TOOL_AUTHOR = os.environ.get("STACKSQ_TOOL_AUTHOR", "SISA Security Team")
TOOL_URL = os.environ.get("STACKSQ_TOOL_URL", "https://github.com/SISA-Security/StackSQScanner")

# Directory Settings
# Override via: STACKSQ_TEMP_DIR, STACKSQ_REPORTS_DIR
PROJECT_ROOT = Path(__file__).parent.parent.parent
TEMP_DIR = Path(os.environ.get("STACKSQ_TEMP_DIR", str(PROJECT_ROOT / "temp")))
REPORTS_DIR = Path(os.environ.get("STACKSQ_REPORTS_DIR", str(PROJECT_ROOT / "reports")))

# Upload/API Settings
# Override via: STACKSQ_MAX_FOLDER_SIZE
MAX_FOLDER_SIZE = int(os.environ.get("STACKSQ_MAX_FOLDER_SIZE", str(500 * 1024 * 1024)))  # 500 MB default

# Supported Git Providers
SUPPORTED_PROVIDERS = ["github.com", "gitlab.com", "bitbucket.org"]

# SBOM Generation Settings
DEFAULT_SBOM_FORMAT = os.environ.get("STACKSQ_SBOM_FORMAT", "cyclonedx")  # cyclonedx, spdx, json
SBOM_SPEC_VERSION = {
    "cyclonedx": "1.5",
    "spdx": "2.3"
}

# Package Registry URLs (override for private registries)
PYPI_BASE_URL = os.environ.get("STACKSQ_PYPI_URL", "https://pypi.org/project")
NPM_BASE_URL = os.environ.get("STACKSQ_NPM_URL", "https://www.npmjs.com/package")

# External API Endpoints
DEPS_DEV_API = os.environ.get("STACKSQ_DEPS_DEV_API", "https://api.deps.dev/v3")
PYPI_API = os.environ.get("STACKSQ_PYPI_API", "https://pypi.org/pypi")
NPM_API = os.environ.get("STACKSQ_NPM_API", "https://registry.npmjs.org")
OSV_API = os.environ.get("STACKSQ_OSV_API", "https://api.osv.dev/v1")
NVD_CVE_API = os.environ.get("STACKSQ_NVD_CVE_API", "https://services.nvd.nist.gov/rest/json/cve/1.0")
NVD_SEARCH_API = os.environ.get("STACKSQ_NVD_SEARCH_API", "https://services.nvd.nist.gov/rest/json/cves/2.0")
GITHUB_API = os.environ.get("STACKSQ_GITHUB_API", "https://api.github.com")
GITLAB_API = os.environ.get("STACKSQ_GITLAB_API", "https://gitlab.com/api/v4")
ANACONDA_API = os.environ.get("STACKSQ_ANACONDA_API", "https://api.anaconda.org")
EOL_API = os.environ.get("STACKSQ_EOL_API", "https://endoflife.date/api")

# API Rate Limiting
API_RATE_LIMIT_DELAY = float(os.environ.get("STACKSQ_RATE_LIMIT_DELAY", "0.1"))
API_MAX_RETRIES = int(os.environ.get("STACKSQ_MAX_RETRIES", "3"))
API_TIMEOUT = int(os.environ.get("STACKSQ_API_TIMEOUT", "30"))

# Caching
ENABLE_CACHING = os.environ.get("STACKSQ_ENABLE_CACHING", "true").lower() == "true"
CACHE_SIZE = int(os.environ.get("STACKSQ_CACHE_SIZE", "2048"))
CACHE_TTL = int(os.environ.get("STACKSQ_CACHE_TTL", "3600"))

# Database Configuration (MySQL)
# Override via: STACKSQ_DB_HOST, STACKSQ_DB_PORT, STACKSQ_DB_USER, STACKSQ_DB_PASSWORD, STACKSQ_DB_NAME
DB_HOST = os.environ.get("STACKSQ_DB_HOST", "localhost")
DB_PORT = int(os.environ.get("STACKSQ_DB_PORT", "3306"))
DB_USER = os.environ.get("STACKSQ_DB_USER", "root")
DB_PASSWORD = os.environ.get("STACKSQ_DB_PASSWORD", "")
DB_NAME = os.environ.get("STACKSQ_DB_NAME", "stacksq_scanner")

# Cache Strategy: "api_first" (API first, DB fallback) or "cache_first" (DB first, API fallback)
CACHE_STRATEGY = os.environ.get("STACKSQ_CACHE_STRATEGY", "api_first")

# Vulnerability Scanning
DEFAULT_VULN_SOURCE = os.environ.get("STACKSQ_VULN_SOURCE", "osv")
INCLUDE_TRANSITIVE_VULNS = os.environ.get("STACKSQ_INCLUDE_TRANSITIVE", "true").lower() == "true"

# CERT-IN Compliance
CERT_IN_MANDATORY_FIELDS = [
    "component_name",
    "component_version",
    "component_description",
    "component_supplier",
    "component_license",
    "component_origin",
    "component_dependencies",
    "vulnerabilities",
    "patch_status",
    "release_date",
    "eol_date",
    "criticality",
    "hashes",
    "comments",
    "author_of_sbom_data",
    "timestamp",
    "executable",
    "archive",
    "structured_properties",
    "unique_identifier"
]

# Default Value Suffix - appended to values that are hardcoded defaults (not fetched from API)
DEFAULT_SUFFIX = " [default]"

# Default values for SBOM fields when data is not available from APIs
# These use the DEFAULT_SUFFIX to indicate they are not from external sources
DEFAULT_VALUES = {
    "component_description": f"No description available{DEFAULT_SUFFIX}",
    "component_supplier": f"Unknown{DEFAULT_SUFFIX}",
    "component_license": "NOASSERTION",  # SPDX standard, no suffix
    "component_origin": f"Unknown{DEFAULT_SUFFIX}",
    "eol_date": f"Unknown{DEFAULT_SUFFIX}",
    "criticality": f"Low{DEFAULT_SUFFIX}",
    "patch_status": f"Unknown{DEFAULT_SUFFIX}",
    "release_date": f"Unknown{DEFAULT_SUFFIX}",
    "executable": f"Unknown{DEFAULT_SUFFIX}",
    "archive": f"Unknown{DEFAULT_SUFFIX}",
    "structured_properties": f"Unknown{DEFAULT_SUFFIX}",
    "comments": "",
}

# Criticality Scoring
CRITICALITY_WEIGHTS = {
    "has_critical_vuln": "High",
    "has_high_vuln": "High",
    "is_direct_dependency": "Medium",
    "has_medium_vuln": "Medium",
    "is_transitive_dependency": "Low",
    "no_vulnerabilities": "Low"
}

# License Categories
LICENSE_RISK_LEVELS = {
    "permissive": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    "weak_copyleft": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0"],
    "strong_copyleft": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
    "proprietary": ["Commercial", "Proprietary"],
    "public_domain": ["CC0-1.0", "Public Domain"]
}

# # Excluded Directories (for source code scanning)
# EXCLUDED_DIRECTORIES = {
#     # Virtual environments
#     "venv", "env", ".venv", ".env", "virtualenv",
#     # Build/dist
#     "build", "dist", "*.egg-info", ".eggs",
#     # Package managers
#     "node_modules", "bower_components",
#     # Version control
#     ".git", ".svn", ".hg",
#     # IDE
#     ".vscode", ".idea", ".vs",
#     # Testing
#     ".tox", ".pytest_cache", "__pycache__", ".coverage",
#     # Documentation
#     "docs", "_build", "site",
#     # CI/CD
#     ".github", ".gitlab", ".circleci",
#     # Temporary
#     "temp", "tmp", ".tmp"
# }

# License Types Mapping (for component_origin field per CERT-IN)
LICENSE_ORIGIN_MAP = {
    "MIT": "Open-source (MIT License)",
    "Apache-2.0": "Apache License 2.0",
    "Apache Software License": "Apache License 2.0",
    "BSD": "Open-source (BSD License)",
    "BSD-3-Clause": "Open-source (BSD License)",
    "BSD-2-Clause": "Open-source (BSD License)",
    "BSD License": "Open-source (BSD License)",
    "GPL-2.0": "Open-source (GPL 2.0)",
    "GPL-3.0": "Open-source (GPL 3.0)",
    "LGPL": "Open-source (LGPL)",
    "MPL-2.0": "Open-source (MPL 2.0)",
    "ISC": "Open-source (ISC License)",
    "Unlicense": "Public Domain",
    "CC0-1.0": "Public Domain",
    "Commercial": "Vendor",
    "Proprietary": "Vendor"
}

# ============================================================================
# CODEBASE FILE TYPE DETECTION (CERT-IN Compliance)
# ============================================================================
# These extensions are used to scan the CODEBASE (repository) for specific file types.
# Per CERT-IN guidelines, we detect:
#   1. Executable files - Binary files, scripts that can be run
#   2. Archive files - Compressed files, bundled dependencies
#   3. Structured files - Configuration and data files

# EXECUTABLE: Files that can be executed/run
EXECUTABLE_EXTENSIONS = {
    # Windows executables
    ".exe", ".dll", ".msi", ".com", ".scr",
    # Unix/Linux binaries
    ".bin", ".so", ".dylib", ".a", ".o",
    # Scripts
    ".sh", ".bash", ".zsh", ".ksh", ".csh",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    # macOS
    ".app", ".command",
    # Other executables
    ".elf", ".out",
}

# ARCHIVE: Compressed and packaged files (including bundled dependencies)
ARCHIVE_EXTENSIONS = {
    # Standard archives
    ".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".bz2", ".xz", ".7z", ".rar",
    # Python archives
    ".whl", ".egg", ".pyz",
    # Java archives
    ".jar", ".war", ".ear", ".aar",
    # JavaScript/Node bundles
    ".tgz", ".nupkg",
    # Other
    ".deb", ".rpm", ".dmg", ".iso", ".cab",
}

# STRUCTURED: Configuration and data files
STRUCTURED_EXTENSIONS = {
    # Data formats
    ".json", ".xml", ".yaml", ".yml", ".toml",
    # Config files
    ".ini", ".cfg", ".conf", ".config", ".properties",
    # Database schemas
    ".sql", ".sqlite", ".db",
    # Other structured formats
    ".csv", ".tsv", ".env", ".htaccess",
}

# Directories that typically contain bundled/vendored dependencies
BUNDLED_DIRECTORIES = {
    # Python vendor directories
    "_vendor", "vendor", "vendored", "third_party", "thirdparty",
    # JavaScript bundle outputs
    "dist", "build", "bundle", "bundles",
    # Node modules (if checked in)
    "node_modules",
}

# Logging
LOG_LEVEL = os.environ.get("STACKSQ_LOG_LEVEL", "INFO")  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = os.environ.get("STACKSQ_LOG_FORMAT", "[%(levelname)s] %(message)s")
LOG_FILE = os.environ.get("STACKSQ_LOG_FILE", None)  # None for stdout only, or path to log file

# Report Generation (REPORTS_DIR and TEMP_DIR defined at top of file)
GENERATE_ALL_FORMATS = os.environ.get("STACKSQ_GENERATE_ALL_FORMATS", "true").lower() == "true"

# Scan Settings
DEFAULT_MAX_WORKERS = int(os.environ.get("STACKSQ_MAX_WORKERS", "10"))
DEFAULT_RECENT_PUBLISH_DAYS = int(os.environ.get("STACKSQ_RECENT_DAYS", "7"))
SKIP_EXAMPLES = os.environ.get("STACKSQ_SKIP_EXAMPLES", "true").lower() == "true"
SKIP_TESTS = os.environ.get("STACKSQ_SKIP_TESTS", "true").lower() == "true"

# Component Origin Detection (CERT-IN format: should reflect license/distribution model)
def get_component_origin(license_name: str, ecosystem: str = None) -> str:
    """
    Determine component origin based on license type (CERT-IN format).
    
    Per CERT-IN guidelines:
    - Origin = License type or distribution model
    - Examples: "Apache License 2.0", "Open-source community", "Vendor"
    
    Args:
        license_name: License string from package metadata
        ecosystem: Optional ecosystem for fallback
        
    Returns:
        Origin description string (e.g., "Apache License 2.0", "Open-source community")
    """
    if not license_name or license_name.upper() in ["NOASSERTION", "UNKNOWN", ""]:
        # Fallback based on ecosystem
        if ecosystem and ecosystem.lower() in ["pypi", "npm", "conda"]:
            return "Open-source community"
        return "Unknown"
    
    # Direct mapping for known licenses
    if license_name in LICENSE_ORIGIN_MAP:
        return LICENSE_ORIGIN_MAP[license_name]
    
    # Pattern matching for variations
    license_upper = license_name.upper()
    
    if "APACHE" in license_upper:
        if "2" in license_upper or "2.0" in license_upper:
            return "Apache License 2.0"
        return "Apache Software License"
    
    if "BSD" in license_upper:
        return "Open-source (BSD License)"
    
    if "MIT" in license_upper:
        return "Open-source (MIT License)"
    
    if "GPL" in license_upper:
        if "LGPL" in license_upper:
            return "Open-source (LGPL)"
        return "Open-source (GPL)"
    
    if any(word in license_upper for word in ["PROPRIETARY", "COMMERCIAL", "VENDOR"]):
        return "Vendor"
    
    if any(word in license_upper for word in ["PUBLIC", "CC0", "UNLICENSE"]):
        return "Public Domain"
    
    # Default for unrecognized licenses from open-source registries
    if ecosystem and ecosystem.lower() in ["pypi", "npm", "conda"]:
        return "Open-source community"
    
    return license_name  # Return as-is if can't categorize


# Download Location Builder
def get_download_location(ecosystem: str, package_name: str) -> str:
    """
    Build download location URL for a package.
    
    Args:
        ecosystem: Package ecosystem
        package_name: Package name
        
    Returns:
        Download URL string
    """
    locations = {
        "pypi": f"{PYPI_BASE_URL}/{package_name}",
        "npm": f"{NPM_BASE_URL}/{package_name}"
    }
    return locations.get(ecosystem.lower(), "NOASSERTION")


# CERT-IN Unique Identifier Generator
# Note: calculate_patch_status moved to src/utils/patch_utils.py
# Note: calculate_criticality moved to src/core/vulnerability_provider.py
def generate_cert_in_identifier(ecosystem: str, name: str, version: str, supplier: str = None) -> str:
    """
    Generate CERT-IN compliant unique identifier with supplier prefix.
    
    Per CERT-IN example:
    pkg:supplier/ApacheSoftwareFoundation/ApacheTomcat@9.0.71?arch=x86_64&os=linux#server/webapps
    
    Our format:
    pkg:supplier/{SupplierClean}/{PackageName}@{version}?arch=x86_64&os=linux
    
    Args:
        ecosystem: Package ecosystem (pypi, npm, conda)
        name: Package name
        version: Package version
        supplier: Optional supplier name (will be sanitized)
        
    Returns:
        CERT-IN compliant PURL string
    """
    import re
    import platform
    from email.header import decode_header
    
    # Sanitize supplier name (remove spaces, special chars, email)
    if supplier:
        # Decode MIME-encoded strings (e.g., =?utf-8?q?Sebasti=C3=A1n?=)
        try:
            decoded_parts = decode_header(supplier)
            supplier = ''.join(
                part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part
                for part, encoding in decoded_parts
            )
        except Exception:
            pass  # If decoding fails, use original string
        
        # Take only the first author if multiple (separated by comma)
        if ',' in supplier:
            supplier = supplier.split(',')[0].strip()
        
        # Remove email addresses
        supplier_clean = re.sub(r'<[^>]+>', '', supplier).strip()
        # Remove special characters, keep only alphanumeric and spaces
        supplier_clean = re.sub(r'[^a-zA-Z0-9\s]', '', supplier_clean)
        # Replace spaces with empty string for PURL
        supplier_clean = supplier_clean.replace(' ', '')
        # Capitalize first letter of each word
        supplier_clean = ''.join(word.capitalize() for word in re.findall(r'\w+', supplier_clean))
        
        # Limit length to avoid overly long PURLs
        if len(supplier_clean) > 50:
            supplier_clean = supplier_clean[:50]
    else:
        # Use ecosystem as fallback
        supplier_clean = ecosystem.upper() if ecosystem else "Unknown"
    
    # Sanitize package name
    name_clean = name.replace('-', '').replace('_', '').replace('.', '')
    
    # Get system info
    arch = platform.machine().lower()
    if arch == 'amd64':
        arch = 'x86_64'
    os_name = platform.system().lower()
    
    # Build CERT-IN PURL
    purl = f"pkg:supplier/{supplier_clean}/{name_clean}@{version}?arch={arch}&os={os_name}"
    
    return purl
