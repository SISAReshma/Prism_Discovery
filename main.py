"""
Unified AIBOM & SBOM API - FastAPI Application
Combines all endpoints from AIBOM and SBOM modules

Run with: uvicorn main:app --reload --port 8000
Test with: http://localhost:8000/docs
"""

# Configure logging FIRST before any imports
import logging
import time as _time
from datetime import datetime
import pytz

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',
    force=True
)
logger = logging.getLogger("prismaibom")

# Install transparent decryption hooks before anything reads data files
try:
    import _file_vault
    _file_vault.install()
    logger.info("[VAULT] In-memory decryption hooks installed")
except ImportError:
    pass

# Enforce runtime security (anti-debug, anti-ptrace, disable core dumps)
try:
    import _runtime_guard
    _runtime_guard.enforce()
    logger.info("[GUARD] Runtime security protections active")
except ImportError:
    pass

import os
import json
import base64
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Set
from collections import defaultdict
from fastapi import FastAPI, File, UploadFile, Depends, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =============================================================================
# AIBOM IMPORTS
# =============================================================================

from aibom.config import CODE_FILE_EXTENSIONS, SKIP_DIRECTORIES, AI_CATEGORIES, AWS
from aibom.src.models import (
    SetRepositoryRequest as AIBOMSetRepositoryRequest, 
    SetRepositoryResponse as AIBOMSetRepositoryResponse, 
    FilesResponse, CodeTokensResponse,
    PackagesResponse as AIBOMPackagesResponse, 
    SemgrepScanResponse, FilteredImportsResponse, LLMValidationResponse,
    CategorizationResponse, CategorizedLibrary, CategoryGroup,
    DependencyGraphResponse, AIBranchTraceResponse, BranchSummaryItem, BranchTraceSummary,
    ManifestsFound as AIBOMManifestsFound, 
    DependenciesFound, PackagesSummary as AIBOMPackagesSummary,
    LanguageItems,
    LanguageImports, ImportInfo, SemgrepScanSummary,
    ImportPackage, ImportPackages, FilteredImportsSummary,
    GraphNode, GraphEdge, GraphMetadata, LanguageStats as AIBOMLanguageStats,
    AILibrary, APILibrary, LLMValidationSummary,
    CategoryStats, BranchLanguageStats,
    AITargetedScanResponse, LibraryScanResult, ScanFinding, ScanSummary,
    ModelDetection,
    APILibraryScanResult, APIScanSummary,
    ModelCardHandlerResponse, ModelCardResult, SuffixInfo,
    ModelDeprecationResponse, ModelDeprecationResult, DeprecationInfo, DeprecationSummary,
    CategoryAPIFindings, APICallSegregationSummary, APICallSegregationResponse,
    FrameworksDetectedResponse, DetectedFramework, SubImport, FrameworksSummary
)
from core.session import (
    SessionData,
    create_session,
    get_session,
    update_session,
    clear_session,
    rotate_session,
    get_session_stats,
    clear_all_sessions,
    get_session_count,
    start_cleanup_task,
    stop_cleanup_task,
    cleanup_expired_sessions,
    mark_step_complete,
    create_session_with_token,
    require_validated_session,
    require_scan_initialized,
    require_step,
)
from aibom.src.validate import (
    validate_github_repo as aibom_validate_github_repo,
    validate_zip_upload as aibom_validate_zip_upload,
    validate_local_upload as aibom_validate_local_upload,
    cleanup_temp_dir as aibom_cleanup_temp_dir,
)
from aibom.src.errors import raise_error

# Import AIBOM scanner/resolver modules
from aibom.src.manifest_parser import analyze_packages as do_analyze_packages
from aibom.src.semgrep_scanner import scan_and_dedupe, filter_local_imports, extract_packages_with_sources
from aibom.src.package_resolver import resolve_and_compare
from aibom.src.dependency_graph import build_dependency_graph
from aibom.src.llm_validator import validate_libraries
from aibom.src.llm_categorizer import run_categorization
from aibom.src.framework_detector import detect_frameworks
from aibom.src.ai_branch_tracer import trace_ai_branches, format_branch_summary
from aibom.src.ai_targeted_scanner import scan_ai_branches, scan_api_branches
from aibom.src.model_card_handler import process_models_for_cards
from aibom.src.model_deprecation_checker import check_models_deprecation

# =============================================================================
# SBOM IMPORTS
# =============================================================================

from sbom.src.api.config import TOOL_NAME, TOOL_VERSION, TOOL_VENDOR, RATE_LIMITS
from sbom.src.config.config import (
    SBOM_LANG_TO_RESOLVER,
    SEMGREP_SUPPORTED_LANGS,
    classify_unused_package,
)
from sbom.src.api.models import (
    StartScanResponse
)
# Session management is unified in core.session (imported above)
from sbom.src.api.validate import (
    validate_zip_upload as sbom_validate_zip_upload,
    validate_local_upload as sbom_validate_local_upload,
    cleanup_temp_dir as sbom_cleanup_temp_dir,
    get_temp_dir as sbom_get_temp_dir
)

# Import SBOM orchestrator and rate limiter
from sbom.src.core.orchestrator import ScanOrchestrator
from sbom.src.utils.rate_limiter import get_rate_limiter

# Log sanitization utilities
from core.log_sanitizer import sanitize_url, extract_repo_identifier, sanitize_sensitive, mask_session_token

# Orchestrator UI router
from orchestrator import router as orchestrator_router

# =============================================================================
# ENCRYPTION KEY MANAGEMENT
# =============================================================================

_encryption_key_cache = None


def get_secret_key_from_secretmanager():
    """Fetch encryption key from AWS Secrets Manager with caching."""
    global _encryption_key_cache
    if _encryption_key_cache is not None:
        logger.debug("Using cached encryption key")
        return _encryption_key_cache
    
    # Create a Secrets Manager client with role credentials
    client = boto3.client(
        service_name='secretsmanager',
        region_name=AWS.REGION,
        aws_access_key_id=AWS.ACCESS_KEY_ID,
        aws_secret_access_key=AWS.SECRET_ACCESS_KEY
    )
    
    logger.debug("AWS Secrets Manager client created successfully")

    # Fetch the secret
    response = client.get_secret_value(SecretId=AWS.SECRET_NAME)
        
    # Parse the secret
    if 'SecretString' in response:
        secret = json.loads(response['SecretString'])
        # Assuming the secret is stored as {"key": "base64_encoded_key"}
        key_base64 = secret.get('API_ENCRYPTION_KEY') or secret.get('key')
        
        if not key_base64:
            raise ValueError("Encryption key not found in secret")
        # Decode the base64 key
        encryption_key = base64.b64decode(key_base64)
    else:
        # Binary secret
        encryption_key = base64.b64decode(response['SecretBinary'])
    
    # Validate key length (must be 32 bytes for AES-256)
    if len(encryption_key) != 32:
        raise ValueError(f"Invalid encryption key length: {len(encryption_key)} bytes (expected 32 bytes)")
    
    # Cache the key
    _encryption_key_cache = encryption_key
   
    return encryption_key


def decrypt_data(encrypted_base64: str) -> str:
    """
    Decrypt data using AES-GCM algorithm.
    
    Args:
        encrypted_base64: Base64-encoded encrypted data (format: nonce||ciphertext)
        
    Returns:
        str: Decrypted plaintext
    
    Raises:
        Exception: If decryption fails
    """
    try:
        if not encrypted_base64:
            return encrypted_base64
        
        # Get encryption key from Secrets Manager
        key = get_secret_key_from_secretmanager()

        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_base64)
        
        # Extract nonce (first 12 bytes) and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Decrypt the data
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
        
    except Exception as e:
        logger.error(f"Decryption operation failed: {str(e)}")
        raise Exception("Decryption failed. Please check your encryption key and data format.")


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

log_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(log_directory, exist_ok=True)


class UTCFormatter(logging.Formatter):
    """Custom formatter for UTC timezone"""
    def formatTime(self, record, datefmt=None):
        utc = pytz.UTC
        dt = datetime.fromtimestamp(record.created, tz=utc)
        if datefmt:
            s = dt.strftime(datefmt)
        else:
            s = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        return s


def initialize_scan_logging(scan_id: str):
    """Initialize logging for a specific scan"""
    global logger
    
    # Clear existing handlers if logger exists
    if logger:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
    
    # Remove old log files for this scan_id
    try:
        for filename in os.listdir(log_directory):
            if filename.startswith(f"{scan_id}_") and filename.endswith(".log"):
                old_log_path = os.path.join(log_directory, filename)
                try:
                    os.remove(old_log_path)
                    print(f"Removed old log file: {old_log_path}")
                except PermissionError as e:
                    print(f"Warning: Permission denied removing log file {old_log_path}: {e}")
                except OSError as e:
                    print(f"Warning: OS error removing log file {old_log_path}: {e}")
    except FileNotFoundError:
        print(f"Warning: Log directory '{log_directory}' not found during cleanup")
    except PermissionError as e:
        print(f"Warning: Permission denied accessing log directory: {e}")
    
    # Create timestamp for filename
    utc = pytz.UTC
    current_time = datetime.now(utc)
    timestamp = current_time.strftime('%d%m%H%M')
    
    # Create log filename
    log_filename = f"{scan_id}_{timestamp}.log"
    log_file_path = os.path.join(log_directory, log_filename)
    
    # Setup formatters
    file_formatter = UTCFormatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s"
    )
    # Console formatter without timestamp (Docker adds timestamps)
    console_formatter = logging.Formatter(fmt="%(message)s")
    
    # Create handlers
    file_handler = logging.FileHandler(log_file_path, mode='a')
    file_handler.setFormatter(file_formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    
    # Configure logger
    logger = logging.getLogger("prismaibom")
    logger.setLevel(logging.INFO)
    logger.handlers = []  # Clear any existing handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Initialized logging for scan_id: {scan_id}")
    logger.info("Log file created successfully")
    
    return log_file_path


class InitializeLogRequest(BaseModel):
    """Request model for initialize-log endpoint"""
    scan_id: str


# =============================================================================
# CONSTANTS & HELPERS - AIBOM
# =============================================================================

AIBOM_BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aibom", "src")


def get_source_path_aibom(session: SessionData):
    """Get absolute source path from AIBOM session. Raises if not found."""
    from aibom.src.validate import _SYSTEM_TEMP_ROOT
    lp = session.local_path
    if os.path.isabs(lp):
        source_path = lp
    else:
        # local_path is relative to _SYSTEM_TEMP_ROOT (new format)
        temp_path = os.path.join(_SYSTEM_TEMP_ROOT, lp)
        if os.path.exists(temp_path):
            source_path = temp_path
        else:
            # Legacy: relative to AIBOM_BASE_DIR
            source_path = os.path.join(AIBOM_BASE_DIR, lp)
    if not os.path.exists(source_path):
        raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404,
                    hint="The source may have been cleaned up. Please validate again.")
    return source_path


def collect_files_aibom(source_path: str) -> List[str]:
    """Walk directory and collect all non-hidden files, skipping common dirs."""
    files_list = []
    for root, dirs, files in os.walk(source_path):
        dirs[:] = [d for d in dirs if d[0] != '.' and d not in SKIP_DIRECTORIES]
        for file in files:
            if file[0] != '.':
                rel_path = os.path.relpath(os.path.join(root, file), source_path)
                files_list.append(rel_path.replace("\\", "/"))
    return files_list


def get_files_list_aibom(session: SessionData) -> List[str]:
    """Get files list from AIBOM session cache or collect from disk."""
    files_list = session.extra.get("files_list")
    if files_list:
        return files_list
    return collect_files_aibom(get_source_path_aibom(session))


def _clean_description(text: str, max_len: int = 300) -> str:
    """Clean description text: strip markdown/HTML, collapse whitespace, truncate."""
    if not text:
        return ""
    import re as _re
    # Strip HTML tags
    text = _re.sub(r'<[^>]+>', '', text)
    # Strip markdown headers (# ## ###)
    text = _re.sub(r'^#+\s*', '', text, flags=_re.MULTILINE)
    # Strip markdown links [text](url) → text
    text = _re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Collapse multiple newlines/whitespace into single space
    text = _re.sub(r'\s*\n\s*', ' ', text)
    text = _re.sub(r'\s{2,}', ' ', text)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(' ', 1)[0] + '...'
    return text


def build_component_preview_with_vulns(packages: list) -> list:
    """
    Build components preview listing ALL packages.
    If a package has vulnerabilities, include severity counts.
    If not, vuln is an empty dict.
    For direct packages, includes transitive_count.
    """
    # Build lookup: for each direct package, count its transitives
    direct_names = set()
    transitive_names = set()
    for p in packages:
        name = (p.get("name") or p.get("component_name") or "").lower()
        if p.get("is_direct_dependency", True):
            direct_names.add(name)
        else:
            transitive_names.add(name)
    
    # Count transitives per direct package using component_dependencies
    # component_dependencies can be PURLs (pkg:maven/group:artifact@ver) or plain names
    def _extract_dep_name(dep) -> str:
        """Extract comparable name from a dependency entry (PURL string or dict)."""
        raw = dep if isinstance(dep, str) else dep.get("name", "") if isinstance(dep, dict) else str(dep)
        raw = raw.lower()
        # Strip PURL prefix: "pkg:maven/com.x:y@1.0" → "com.x:y"
        if raw.startswith("pkg:"):
            raw = raw.split("/", 1)[-1] if "/" in raw else raw
            raw = raw.split("@")[0]  # strip version
        return raw

    transitive_counts: dict = {}
    # Track which direct deps pull in each transitive: transitive_lower -> [(display_name, lower_name)]
    transitive_parents: dict[str, list[tuple[str, str]]] = {}
    for p in packages:
        if not p.get("is_direct_dependency", True):
            continue
        display_name = p.get("name") or p.get("component_name") or ""
        name = display_name.lower()
        deps = p.get("component_dependencies", [])
        # Count how many of this package's dependencies are transitive
        count = 0
        for d in deps:
            dep_name = _extract_dep_name(d)
            if dep_name in transitive_names:
                count += 1
                # Record parent relationship
                transitive_parents.setdefault(dep_name, [])
                if (display_name, name) not in transitive_parents[dep_name]:
                    transitive_parents[dep_name].append((display_name, name))
        # If component_dependencies is empty but there ARE transitives, use total_dependencies
        if count == 0 and deps:
            count = len(deps)
        transitive_counts[name] = count
    
    # Build direct-dep lookup maps: name_lower -> usage / classification
    direct_usage: dict[str, str] = {}
    direct_classification: dict[str, str | None] = {}
    for p in packages:
        if p.get("is_direct_dependency", True):
            n = (p.get("name") or p.get("component_name") or "").lower()
            direct_usage[n] = p.get("is_used_in_code", "not_scanned")
            direct_classification[n] = p.get("unused_classification")
    
    components_preview = []
    for p in packages:
        vulnerabilities = p.get("vulnerabilities", [])
        
        highest_cvss: float | None = None
        if vulnerabilities:
            vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for v in vulnerabilities:
                severity = v.get("severity_level", "").upper()
                if severity == "NONE":
                    severity = "LOW"
                elif severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = "HIGH"
                vuln_counts[severity.lower()] += 1
                score = v.get("cvss_score")
                if score is not None and (highest_cvss is None or score > highest_cvss):
                    highest_cvss = score
        else:
            vuln_counts = {}
        
        is_direct = p.get("is_direct_dependency", True)
        name = (p.get("name") or p.get("component_name") or "").lower()
        
        # ── Derive is_used_in_code + unused_classification for transitives ──
        if is_direct:
            used_status = p.get("is_used_in_code", "not_scanned")
            classification = p.get("unused_classification")
        else:
            parents = transitive_parents.get(name, [])
            required_by = [display for display, _ in parents]
            if not parents:
                used_status = p.get("is_used_in_code", "not_scanned")
                classification = None
            else:
                parent_statuses = [direct_usage.get(low, "not_scanned") for _, low in parents]
                if "yes" in parent_statuses:
                    used_status = "inherited_used"
                    classification = None
                elif all(s == "no" for s in parent_statuses):
                    used_status = "inherited_unused"
                    # Derive classification from the first unused parent that has one
                    classification = None
                    for _, low in parents:
                        parent_cls = direct_classification.get(low)
                        if parent_cls:
                            classification = parent_cls
                            break
                    if not classification:
                        classification = "transitive_unused"
                else:
                    used_status = "not_scanned"
                    classification = None
        
        entry = {
            "name": p.get("name") or p.get("component_name"),
            "version": p.get("version") or p.get("component_version"),
            "language": p.get("language"),
            "is_direct": is_direct,
            "vuln": vuln_counts,
            "cvss_score": highest_cvss,
            "transitive_count": transitive_counts.get(name, 0) if is_direct else 0,
            "is_used_in_code": used_status,
            "unused_classification": classification,
        }
        
        if is_direct:
            # import_evidence: only for direct deps (transitives are never scanned)
            entry["import_evidence"] = p.get("import_evidence", [])
        else:
            # required_by: only for transitives (direct deps have no parent)
            entry["required_by"] = required_by
        
        components_preview.append(entry)
    return components_preview


# =============================================================================
# INITIALIZE GLOBALS - SBOM
# =============================================================================

def init_rate_limiter():
    """Initialize and configure the shared rate limiter."""
    limiter = get_rate_limiter()
    for api_name, config in RATE_LIMITS.items():
        limiter.set_limit(api_name, limit=config['limit'], window=config['window'])
    return limiter


rate_limiter = init_rate_limiter()

SBOM_TEMP_DIR = Path("temp")
SBOM_TEMP_DIR.mkdir(parents=True, exist_ok=True)

orchestrator = ScanOrchestrator(
    temp_dir=str(SBOM_TEMP_DIR),
)


# =============================================================================
# APP LIFECYCLE
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    _boot_start = _time.monotonic()
    logger.info("="*60)
    logger.info("  PrismAIBOM API — Starting up")
    logger.info("="*60)

    # Log app metadata
    logger.info(f"[BOOT] Version        : {app.version}")
    logger.info(f"[BOOT] Python          : {os.sys.version.split()[0]}")
    logger.info(f"[BOOT] PID             : {os.getpid()}")
    logger.info(f"[BOOT] Working dir     : {os.getcwd()}")

    # Session config
    from core.session import SESSION_TTL_HOURS, SESSION_IDLE_TIMEOUT_MINUTES, MAX_SESSIONS
    logger.info(f"[BOOT] Session TTL     : {SESSION_TTL_HOURS}h")
    logger.info(f"[BOOT] Session idle    : {SESSION_IDLE_TIMEOUT_MINUTES}m")
    logger.info(f"[BOOT] Max sessions    : {MAX_SESSIONS}")

    # CORS config
    logger.info(f"[BOOT] CORS origins    : {ALLOWED_ORIGINS}")
    logger.info(f"[BOOT] CORS credentials: {_cors_allow_credentials}")

    # SBOM config summary
    logger.info(f"[BOOT] SBOM temp dir   : {SBOM_TEMP_DIR.resolve()}")
    logger.info(f"[BOOT] SBOM tool       : {TOOL_NAME} v{TOOL_VERSION} ({TOOL_VENDOR})")
    _rl_summary = ", ".join(f"{k}={v['limit']}/h" for k, v in RATE_LIMITS.items())
    logger.info(f"[BOOT] Rate limits     : {_rl_summary}")

    # AIBOM config
    logger.info(f"[BOOT] AIBOM base dir  : {AIBOM_BASE_DIR}")
    logger.info(f"[BOOT] Log directory   : {log_directory}")

    # Start background session cleanup
    start_cleanup_task()
    logger.info("[BOOT] Session cleanup task started")

    _boot_elapsed = (_time.monotonic() - _boot_start) * 1000
    logger.info(f"[BOOT] Startup completed in {_boot_elapsed:.0f}ms")
    logger.info("="*60)
    logger.info("  PrismAIBOM API is ready — accepting requests")
    logger.info("="*60)
    yield
    # Shutdown — stop cleanup task and clean temp directories
    logger.info("")
    logger.info("="*60)
    logger.info("  PrismAIBOM API — Shutting down")
    logger.info("="*60)
    stop_cleanup_task()
    logger.info("[SHUTDOWN] Session cleanup task stopped")
    try:
        aibom_cleanup_temp_dir()
        logger.info("[SHUTDOWN] AIBOM temp dir cleaned")
    except Exception as e:
        logging.error(f"[SHUTDOWN] Error cleaning AIBOM temp dir: {e}")
    try:
        sbom_cleanup_temp_dir()
        logger.info("[SHUTDOWN] SBOM temp dir cleaned")
    except Exception as e:
        logging.error(f"[SHUTDOWN] Error cleaning SBOM temp dir: {e}")
    logger.info("[SHUTDOWN] PrismAIBOM API shutdown complete")
    logger.info("="*60)


app = FastAPI(
    title="PrismAIBOM API",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan
)

# ── Global exception handlers (prevent stack trace leaks) ──
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(StarletteHTTPException)
async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def _generic_exc_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# Register orchestrator UI & API routes
app.include_router(orchestrator_router)

# CORS middleware
# SECURITY: Do not use allow_origins=["*"] with allow_credentials=True.
# Restrict to known origins or disable credentials with wildcard.
ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",")
_cors_allow_credentials = "*" not in ALLOWED_ORIGINS  # Disable credentials if wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["session-token", "Content-Type", "Authorization"],
    expose_headers=["session-token"],
)


# =============================================================================
# PURE ASGI MIDDLEWARE (avoids Starlette BaseHTTPMiddleware body-stream bug)
# =============================================================================
MAX_REQUEST_BODY_SIZE = 500 * 1024 * 1024  # 500 MB

# Airflow network subnet (Docker network airflow-docker_default)
ALLOWED_NETWORK_PREFIXES = ("172.18.,172.19.,172.20.,172.21.,172.22.,127.0.0.1,10.0.").split(",")

# Paths accessible without network restriction
UNRESTRICTED_PATHS = {"/", "/health", "/api/jobs"}

_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"x-xss-protection", b"1; mode=block"),
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
    (b"content-security-policy", b"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"),
]


class SecurityMiddleware:
    """Pure ASGI middleware: body-size limit, network restriction, security headers."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        headers = dict(scope.get("headers", []))

        # --- Body size limit ---
        cl = headers.get(b"content-length")
        if cl and int(cl) > MAX_REQUEST_BODY_SIZE:
            return await self._send_json(send, 413,
                {"detail": f"Request body too large. Maximum size is {MAX_REQUEST_BODY_SIZE // (1024 * 1024)} MB."})

        # --- Network restriction ---
        is_unrestricted = (
            path in UNRESTRICTED_PATHS
            or path.startswith("/api/jobs")
            or path.startswith("/api/browse")
        )
        if not is_unrestricted:
            client_ip = self._get_client_ip(scope, headers)
            if not any(p.strip() and client_ip.startswith(p.strip())
                       for p in ALLOWED_NETWORK_PREFIXES):
                logger.warning(f"Blocked request from unauthorized IP: {client_ip} to path: {path}")
                return await self._send_json(send, 403,
                    {"detail": "Access denied. Requests are only accepted from the Airflow network.",
                     "client_ip": client_ip})

        # --- Wrap send to inject security headers ---
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = list(message.get("headers", []))
                existing.extend(_SECURITY_HEADERS)
                message = {**message, "headers": existing}
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    def _get_client_ip(scope, headers):
        trusted = {b"172.18.0.1", b"127.0.0.1", b"10.0.0.1"}
        client = scope.get("client")
        direct_ip = (client[0] if client else "").encode() if client else b""
        if direct_ip in trusted:
            xff = headers.get(b"x-forwarded-for")
            if xff:
                return xff.split(b",")[0].strip().decode()
            xri = headers.get(b"x-real-ip")
            if xri:
                return xri.decode()
        return direct_ip.decode() if direct_ip else ""

    @staticmethod
    async def _send_json(send, status, body):
        import json as _json
        payload = _json.dumps(body).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ] + _SECURITY_HEADERS,
        })
        await send({"type": "http.response.body", "body": payload})


app.add_middleware(SecurityMiddleware)


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker HEALTHCHECK and load balancers."""
    return {"status": "healthy"}


@app.post("/initialize-log")
async def initialize_log(request: InitializeLogRequest):
    """
    Initialize logging for a specific scan.
    
    **Body (JSON):**
    ```json
    {
        "scan_id": "unique-scan-id"
    }
    ```
    
    **Returns:** Log file path and initialization status.
    """
    logger.info(f"=== /initialize-log endpoint called ===")
    logger.debug(f"Request payload - scan_id: {request.scan_id}")
    
    # Initialize scan-specific logging
    log_file_path = initialize_scan_logging(request.scan_id)
    
    logger.info(f"Successfully initialized logging for scan_id: {request.scan_id}")
    logger.info("Log output initialized")
    
    logger.info(f"=== /initialize-log completed successfully ===")
    
    return {
        "message": f"Logging initialized for scan_id: {request.scan_id}",
        "scan_id": request.scan_id,
        "log_file": log_file_path,
        "status": "success"
    }


@app.post("/cleanresources")
async def clean_resources():
    """
    Clean all temporary resources, session data, and generated files for both AIBOM and SBOM.
    
    This endpoint:
    - Removes AIBOM temporary directories and generated files
    - Removes SBOM temporary directories and reports
    - Clears all session data and variables
    - Resets application state
    
    **Returns:** Detailed summary of cleaned resources
    """
    logger.info("[CLEAN] Starting resource cleanup...")
    _t0 = _time.monotonic()
    import shutil
    from datetime import datetime
    
    results = {
        "aibom_cleanup": {"status": "unknown", "message": "", "items_cleaned": []},
        "sbom_cleanup": {"status": "unknown", "message": "", "items_cleaned": []},
        "session_cleanup": {"status": "unknown", "message": "", "sessions_cleared": 0},
        "overall_status": "success"
    }
    
    # Clean AIBOM resources
    try:
        aibom_items = []
        
        # Clean AIBOM temporary directories
        aibom_cleanup_temp_dir()
        aibom_items.append("Temporary directories")
        
        # Clean AIBOM base directory checkouts
        aibom_temp_base = os.path.join(AIBOM_BASE_DIR, "temp")
        if os.path.exists(aibom_temp_base):
            shutil.rmtree(aibom_temp_base)
            os.makedirs(aibom_temp_base, exist_ok=True)
            aibom_items.append("Checkout directories")
        
        # Clean any generated AIBOM reports
        aibom_reports = os.path.join(AIBOM_BASE_DIR, "reports")
        if os.path.exists(aibom_reports):
            for file in os.listdir(aibom_reports):
                file_path = os.path.join(aibom_reports, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            aibom_items.append("Generated reports")
        
        results["aibom_cleanup"] = {
            "status": "success",
            "message": "AIBOM resources cleaned successfully",
            "items_cleaned": aibom_items
        }
        logger.info(f"[CLEAN] AIBOM cleanup complete: {aibom_items}")
    except Exception as e:
        results["aibom_cleanup"] = {
            "status": "error",
            "message": f"Error cleaning AIBOM resources: {str(e)}",
            "items_cleaned": []
        }
        results["overall_status"] = "partial"
        logger.error(f"[CLEAN] Error cleaning AIBOM resources: {e}")
    
    # Clean SBOM resources
    try:
        sbom_items = []
        
        # Clean SBOM temporary directories
        sbom_cleanup_temp_dir()
        sbom_items.append("Temporary directories")
        
        # Clean SBOM temp folder
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sbom")
        sbom_temp_base = os.path.join(base_dir, "temp")
        if os.path.exists(sbom_temp_base):
            shutil.rmtree(sbom_temp_base)
            os.makedirs(sbom_temp_base, exist_ok=True)
            sbom_items.append("SBOM temp directory")
        
        # Clean SBOM reports
        sbom_reports = os.path.join(base_dir, "reports")
        if os.path.exists(sbom_reports):
            report_count = 0
            for file in os.listdir(sbom_reports):
                file_path = os.path.join(sbom_reports, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    report_count += 1
            if report_count > 0:
                sbom_items.append(f"Generated reports ({report_count} files)")
        
        results["sbom_cleanup"] = {
            "status": "success",
            "message": "SBOM resources cleaned successfully",
            "items_cleaned": sbom_items
        }
        logger.info(f"[CLEAN] SBOM cleanup complete: {sbom_items}")
    except Exception as e:
        results["sbom_cleanup"] = {
            "status": "error",
            "message": f"Error cleaning SBOM resources: {str(e)}",
            "items_cleaned": []
        }
        results["overall_status"] = "partial"
        logger.error(f"[CLEAN] Error cleaning SBOM resources: {e}")
    
    # Clear session data using unified session management (now async)
    try:
        session_count = await get_session_count()
        cleared = await clear_all_sessions()
        
        results["session_cleanup"] = {
            "status": "success",
            "message": f"Cleared {cleared} session(s)",
            "sessions_cleared": cleared
        }
        logger.info(f"[CLEAN] Session cleanup complete: {cleared} sessions cleared")
    except Exception as e:
        results["session_cleanup"] = {
            "status": "error",
            "message": f"Error clearing sessions: {str(e)}",
            "sessions_cleared": 0
        }
        results["overall_status"] = "partial"
        logger.error(f"[CLEAN] Error clearing sessions: {e}")
    
    # If all failed, mark as failed
    failed_count = sum(1 for k, v in results.items() 
                      if k != "overall_status" and v.get("status") == "error")
    if failed_count == 3:
        results["overall_status"] = "failed"
    elif failed_count > 0:
        results["overall_status"] = "partial"
    
    logger.info(f"[CLEAN] Resource cleanup completed with status: {results['overall_status']} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return {
        "message": "Resource cleanup completed",
        "status": results["overall_status"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "details": {
            "aibom": results["aibom_cleanup"],
            "sbom": results["sbom_cleanup"],
            "sessions": results["session_cleanup"]
        }
    }


# =============================================================================
# SESSION MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/logout")
async def logout_session(session_token: str = Header(..., description="Session token to invalidate")):
    """
    Invalidate a specific session (logout).
    
    **Headers:** `session-token: <token>`
    
    **Returns:** Confirmation of session invalidation.
    """
    cleared = await clear_session(session_token)
    if cleared:
        logger.info("[SESSION] Session invalidated via /logout")
        return {"message": "Session invalidated successfully", "status": "success"}
    else:
        raise HTTPException(
            status_code=404,
            detail={"error": "SESSION_NOT_FOUND", "message": "No active session found for this token."}
        )



# =============================================================================
# AIBOM ENDPOINTS
# =============================================================================

@app.post("/set-repository", response_model=AIBOMSetRepositoryResponse)
async def aibom_set_repository(request: AIBOMSetRepositoryRequest):
    """
    Set and validate a GitHub repository (public or private) for AIBOM.
    
    **Body (JSON):**
    ```json
    {
        "repo_url": "https://github.com/owner/repo",
        "pat": "ghp_xxxxxxxxxxxx"  // Optional, required for private repos (can be encrypted)
    }
    ```
    
    **Returns:** A session token to use in subsequent requests via the `session-token` header.
    """
    # Use extract_repo_identifier to log only owner/repo without any embedded credentials
    safe_repo_id = extract_repo_identifier(request.repo_url)
    logger.info(f"[AIBOM] set-repository: Validating repository '{safe_repo_id}'")
    _t0 = _time.monotonic()
    
    # Decrypt PAT if provided (it may be encrypted)
    decrypted_pat = None
    if request.pat:
        try:
            decrypted_pat = decrypt_data(request.pat)
            logger.debug("[AIBOM] PAT decrypted successfully")
        except Exception as e:
            logger.warning(f"[AIBOM] PAT decryption failed, using as-is: {str(e)}")
            decrypted_pat = request.pat
    
    token = await create_session()
    result = await aibom_validate_github_repo(repo_url=request.repo_url, pat=decrypted_pat)
    
    # Unified session — single update with all AIBOM + SBOM fields
    await update_session(
        token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True,
        repo_name=result["repository"],
        pat=decrypted_pat
    )
    
    # SECURITY: Rotate session token after successful validation (fixation prevention)
    rotated_token = await rotate_session(token)
    if rotated_token:
        token = rotated_token
    
    logger.info(f"[AIBOM] set-repository: Repository '{result['repository']}' validated — {result['file_count']} files ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return AIBOMSetRepositoryResponse(
        message=f"Repository '{result['repository']}' validated successfully.",
        session_token=token,
        valid=result["valid"],
        repository=result["repository"],
        branch=result["branch"],
        file_count=result["file_count"],
        local_path=result["local_path"]
    )


@app.post("/upload-zip")
async def aibom_validate_zip_endpoint(
    file: UploadFile = File(..., description="ZIP file to upload"),
):
    """
    Validate and extract an uploaded **ZIP file** for AIBOM.
    
    **No session token required** — creates and returns a new session token.
    
    **Returns:** Validation result including a `session_token` to use in all subsequent requests.
    """
    logger.info(f"[AIBOM] upload-zip: Processing ZIP file upload '{file.filename}'")
    _t0 = _time.monotonic()
    result = await aibom_validate_zip_upload(file)
    
    # Create a new session (like /set-repository)
    token = await create_session()
    await update_session(
        token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True
    )
    
    # Rotate for session fixation prevention
    rotated = await rotate_session(token)
    if rotated:
        token = rotated
    
    logger.info(f"[AIBOM] upload-zip: ZIP processed — {result['file_count']} files ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return {**result, "session_token": token}


class SetLocalPathRequest(BaseModel):
    """Request model for /set-localpath endpoint."""
    local_path: str


@app.post("/set-localpath")
async def aibom_validate_local_endpoint(request: SetLocalPathRequest):
    """
    Set a local filesystem path as the source for AIBOM/SBOM scanning.

    The path must exist on the same device / container where the API is running.

    **Body (JSON):**
    ```json
    {
        "local_path": "/data/my-repo"
    }
    ```

    **Returns:** Validation result including a `session_token` to use in subsequent requests.
    """
    local_path = request.local_path.strip()
    if not local_path:
        raise HTTPException(status_code=400, detail="local_path is required")

    logger.info("[AIBOM] set-localpath: Validating local path")
    _t0 = _time.monotonic()

    # Resolve host path: if /hostfs mount exists, translate through it
    HOSTFS = os.environ.get("HOSTFS_MOUNT", "/hostfs")
    resolved = os.path.abspath(local_path)
    if not os.path.exists(resolved):
        # Try through hostfs mount (host path → container path)
        hostfs_candidate = os.path.join(HOSTFS, local_path.lstrip("/"))
        if os.path.exists(hostfs_candidate):
            resolved = hostfs_candidate
    if not os.path.exists(resolved):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {local_path}")
    if not os.path.isdir(resolved):
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {local_path}")

    # Count valid files (same logic as collect_files_aibom)
    file_count = 0
    for root, dirs, files in os.walk(resolved):
        dirs[:] = [d for d in dirs if d[0] != '.' and d not in SKIP_DIRECTORIES]
        for f in files:
            if f[0] != '.':
                file_count += 1

    if file_count == 0:
        raise HTTPException(status_code=400, detail="No valid files found at the specified path")

    # Create session with the absolute path
    token = await create_session()
    await update_session(
        token,
        local_path=resolved,
        file_count=file_count,
        validated=True
    )

    # Rotate for session fixation prevention
    rotated = await rotate_session(token)
    if rotated:
        token = rotated

    logger.info(f"[AIBOM] set-localpath: Path validated — {file_count} files ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return {
        "valid": True,
        "message": f"Local path set successfully with {file_count} files",
        "file_count": file_count,
        "local_path": resolved,
        "session_token": token
    }


@app.get("/aibom/files", response_model=FilesResponse)
async def aibom_list_files(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    List all files in the validated source.
    
    **Requires:** Completed validation via /aibom/set_repository.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **Returns:** List of all file paths relative to the source root.
    """
    logger.info("[AIBOM] files: Listing all files in validated source")
    _t0 = _time.monotonic()
    
    # Use cached files list if available, otherwise collect and cache
    cached_files = session.extra.get("files_list")
    if cached_files:
        all_files = cached_files
        logger.info("[AIBOM] files: Using cached files list")
    else:
        source_path = get_source_path_aibom(session)
        all_files = collect_files_aibom(source_path)
        await update_session(session_token, files_list=all_files)
        logger.info("[AIBOM] files: Collected and cached files list")
    
    logger.info(f"[AIBOM] files: Found {len(all_files)} files ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return FilesResponse(
        total_files=len(all_files),
        files=sorted(all_files),
        message="Files list retrieved successfully"
    )


@app.get("/aibom/code-tokens", response_model=CodeTokensResponse)
async def aibom_extract_code_tokens(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Extract code tokens (folder names and file stems) from source code files.
    
    **Requires:** Completed /aibom/files endpoint call.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **Returns:** Unique set of folder names and file stems.
    """
    logger.info("[AIBOM] code-tokens: Extracting code tokens from source files")
    _t0 = _time.monotonic()
    files_list = get_files_list_aibom(session)
    
    tokens: Set[str] = set()
    code_files_processed = 0
    
    for file_path in files_list:
        ext = Path(file_path).suffix.lower()
        if ext in CODE_FILE_EXTENSIONS:
            code_files_processed += 1
            parts = Path(file_path).parts
            for part in parts[:-1]:
                tokens.add(part)
            tokens.add(Path(file_path).stem)
    
    sorted_tokens = sorted(tokens)
    await update_session(session_token, code_tokens=sorted_tokens)
    
    logger.info(f"[AIBOM] code-tokens: Extracted {len(sorted_tokens)} unique tokens from {code_files_processed} code files ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return CodeTokensResponse(
        token_count=len(sorted_tokens),
        tokens=sorted_tokens,
        code_files_processed=code_files_processed
    )


@app.get("/aibom/packages", response_model=AIBOMPackagesResponse)
async def aibom_analyze_packages(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Detect programming languages and extract dependencies from manifest files.
    
    **Requires:** Completed validation via /aibom/set_repository.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **Returns:** Languages detected, manifests found, and dependencies extracted.
    """
    logger.info("[AIBOM] packages: Analyzing manifest files and detecting languages")
    _t0 = _time.monotonic()
    files_list = get_files_list_aibom(session)
    checkout_path = Path(get_source_path_aibom(session))
    
    result = do_analyze_packages(checkout_path, files_list)
    
    logger.info(f"[AIBOM] packages: Languages={result['languages_detected']}, Dependencies={result['summary']['total_dependencies']} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(
        session_token,
        languages_detected=result["languages_detected"],
        manifests_found=result["manifests_found"],
        dependencies=result["dependencies"]
    )
    
    manifests_list = [
        LanguageItems(language="python", items=result["manifests_found"].get("python", [])),
        LanguageItems(language="javascript", items=result["manifests_found"].get("javascript", [])),
        LanguageItems(language="go", items=result["manifests_found"].get("go", [])),
        LanguageItems(language="dotnet", items=result["manifests_found"].get("dotnet", [])),
        LanguageItems(language="java", items=result["manifests_found"].get("java", [])),
    ]
    dependencies_list = [
        LanguageItems(language="python", items=result["dependencies"].get("python", [])),
        LanguageItems(language="javascript", items=result["dependencies"].get("javascript", [])),
        LanguageItems(language="go", items=result["dependencies"].get("go", [])),
        LanguageItems(language="dotnet", items=result["dependencies"].get("dotnet", [])),
        LanguageItems(language="java", items=result["dependencies"].get("java", [])),
    ]
    return AIBOMPackagesResponse(
        languages_detected=result["languages_detected"],
        manifests_found=AIBOMManifestsFound(manifests_list),
        dependencies=DependenciesFound(dependencies_list),
        summary=AIBOMPackagesSummary(
            total_languages=result["summary"]["total_languages"],
            total_manifests=result["summary"]["total_manifests"],
            total_dependencies=result["summary"]["total_dependencies"]
        )
    )


@app.get("/aibom/semgrep-imports-scan", response_model=SemgrepScanResponse)
async def aibom_semgrep_imports_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Run Semgrep import detection on the validated source.
    
    **Requires:** Completed /aibom/packages endpoint.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **Returns:** Scan results with detected imports.
    """
    logger.info("[AIBOM] semgrep-imports-scan: Running Semgrep import detection")
    _t0 = _time.monotonic()
    languages_detected = session.extra.get("languages_detected")
    if not languages_detected:
        logger.warning("[AIBOM] semgrep-imports-scan: Languages not detected - packages endpoint not called")
        raise HTTPException(
            status_code=400,
            detail="Languages not detected. Run /aibom/packages first."
        )
    
    checkout_path = get_source_path_aibom(session)
    try:
        result = scan_and_dedupe(checkout_path, set(languages_detected))
    except FileNotFoundError:
        logger.warning("[AIBOM] semgrep-imports-scan: Semgrep not installed — returning empty scan results")
        result = {
            "scan_results": {},
            "summary": {"total_third_party": 0, "total_builtin": 0, "total_relative": 0}
        }
    
    logger.info(f"[AIBOM] semgrep-imports-scan: {result['summary']['total_third_party']} third-party, {result['summary']['total_builtin']} builtin, {result['summary']['total_relative']} relative imports ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(
        session_token,
        semgrep_scan_results=result["scan_results"],
        imports_files_scanned_count=result["summary"].get("files_scanned_count", 0),
        imports_files_scanned=result["summary"].get("files_scanned", [])
    )
    
    scan_results_model = {
        lang: LanguageImports(
            third_party=[ImportInfo(**imp) for imp in lang_data.get("third_party", [])],
            builtin=[ImportInfo(**imp) for imp in lang_data.get("builtin", [])],
            relative=[ImportInfo(**imp) for imp in lang_data.get("relative", [])]
        )
        for lang, lang_data in result["scan_results"].items()
    }
    
    return SemgrepScanResponse(
        scan_results=scan_results_model,
        summary=SemgrepScanSummary(
            total_third_party=result["summary"]["total_third_party"],
            total_builtin=result["summary"]["total_builtin"],
            total_relative=result["summary"]["total_relative"],
            files_scanned_count=result["summary"].get("files_scanned_count", 0),
            files_scanned=result["summary"].get("files_scanned", [])
        )
    )


@app.get("/aibom/resolve-packages")
async def aibom_resolve_packages(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Resolve manifest packages to import names and detect unused libraries.
    
    **Requires:** /aibom/packages and /aibom/semgrep-imports-scan must be called first.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    """
    logger.info("[AIBOM] resolve-packages: Resolving manifest packages to import names")
    _t0 = _time.monotonic()
    languages = session.extra.get("languages_detected", [])
    dependencies = session.extra.get("dependencies", {})
    
    if not languages and not dependencies:
        logger.warning("[AIBOM] resolve-packages: No packages data found")
        raise HTTPException(
            status_code=400,
            detail="No packages data found. Run /aibom/packages first."
        )
    
    scan_results = session.extra.get("semgrep_scan_results")
    if not scan_results:
        raise HTTPException(
            status_code=400,
            detail="No semgrep scan results found. Run /aibom/semgrep-imports-scan first."
        )
    
    import_packages = {
        "python_imports": [],
        "javascript_imports": [],
        "go_imports": [],
        "dotnet_imports": [],
        "java_imports": [],
    }
    
    if "python" in scan_results:
        for imp in scan_results["python"].get("third_party", []):
            import_packages["python_imports"].append({
                "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                "source_files": [imp.get("file", "")]
            })
    
    if "javascript" in scan_results:
        for imp in scan_results["javascript"].get("third_party", []):
            import_packages["javascript_imports"].append({
                "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                "source_files": [imp.get("file", "")]
            })
    
    if "go" in scan_results:
        for imp in scan_results["go"].get("third_party", []):
            import_packages["go_imports"].append({
                "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                "source_files": [imp.get("file", "")]
            })
    
    if "dotnet" in scan_results:
        for imp in scan_results["dotnet"].get("third_party", []):
            import_packages["dotnet_imports"].append({
                "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                "source_files": [imp.get("file", "")]
            })
    
    if "java" in scan_results:
        for imp in scan_results["java"].get("third_party", []):
            import_packages["java_imports"].append({
                "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                "source_files": [imp.get("file", "")]
            })
    
    result = resolve_and_compare(
        manifest_packages=dependencies,
        semgrep_imports=import_packages,
        languages=languages
    )
    
    await update_session(
        session_token,
        resolved_packages=result,
        import_packages=import_packages
    )
    
    logger.info(f"[AIBOM] resolve-packages: {len(result['resolved_packages'])} resolved, {len(result['used_libraries'])} used, {len(result['unused_libraries'])} unused ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    return {
        "resolved_packages": result["resolved_packages"],
        "used_libraries": result["used_libraries"],
        "unused_libraries": result["unused_libraries"],
        "resolution_summary": result["resolution_summary"]
    }


@app.get("/aibom/filtered-imports", response_model=FilteredImportsResponse)
async def aibom_filtered_imports(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Filter local/internal imports and extract unique external packages.
    
    **Requires:** /aibom/semgrep-imports-scan and /aibom/resolve-packages must be called first.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    """
    logger.info("[AIBOM] filtered-imports: Filtering local imports and extracting external packages")
    _t0 = _time.monotonic()
    scan_results = session.extra.get("semgrep_scan_results")
    if not scan_results:
        logger.warning("[AIBOM] filtered-imports: No semgrep scan results found")
        raise HTTPException(
            status_code=400,
            detail="No semgrep scan results found. Run /aibom/semgrep-imports-scan first."
        )
    
    code_tokens_set = session.extra.get("code_tokens_set")
    if code_tokens_set is None:
        code_tokens_set = set(session.extra.get("code_tokens", []))
    
    languages = session.extra.get("languages_detected", [])
    
    total_before = sum(
        len(scan_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    
    filtered_results = filter_local_imports(scan_results, code_tokens_set)
    import_packages = extract_packages_with_sources(filtered_results, set(languages))
    
    total_after = sum(
        len(filtered_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    py_imports = import_packages.get("python_imports", [])
    js_imports = import_packages.get("javascript_imports", [])
    go_imports = import_packages.get("go_imports", [])
    dotnet_imports = import_packages.get("dotnet_imports", [])
    java_imports = import_packages.get("java_imports", [])
    unique_packages = len(py_imports) + len(js_imports) + len(go_imports) + len(dotnet_imports) + len(java_imports)

    logger.info(f"[AIBOM] filtered-imports: {total_before}\u2192{total_after} imports (removed {total_before - total_after} local), {unique_packages} unique packages ({(_time.monotonic()-_t0)*1000:.0f}ms)")

    await update_session(
        session_token,
        filtered_imports=filtered_results,
        import_packages=import_packages
    )
    
    return FilteredImportsResponse(
        import_packages=ImportPackages(
            python_imports=[ImportPackage(**pkg) for pkg in py_imports],
            javascript_imports=[ImportPackage(**pkg) for pkg in js_imports],
            go_imports=[ImportPackage(**pkg) for pkg in go_imports],
            dotnet_imports=[ImportPackage(**pkg) for pkg in dotnet_imports],
            java_imports=[ImportPackage(**pkg) for pkg in java_imports]
        ),
        summary=FilteredImportsSummary(
            total_before_filter=total_before,
            total_after_filter=total_after,
            local_imports_removed=total_before - total_after,
            unique_external_packages=unique_packages
        )
    )


@app.get("/aibom/dependency-graph", response_model=DependencyGraphResponse)
async def aibom_dependency_graph(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Generate import dependency graph showing file-to-file relationships.
    
    **Requires:** /aibom/semgrep-imports-scan and /aibom/code-tokens must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    """
    logger.info("[AIBOM] dependency-graph: Building import dependency graph")
    _t0 = _time.monotonic()
    semgrep_scan = session.extra.get("semgrep_scan_results")
    if not semgrep_scan:
        logger.warning("[AIBOM] dependency-graph: Semgrep scan not found")
        raise_error("SEMGREP_SCAN_NOT_FOUND", "Semgrep scan not found", hint="Call /aibom/semgrep-imports-scan first")
    
    code_tokens = session.extra.get("code_tokens")
    if not code_tokens:
        logger.warning("[AIBOM] dependency-graph: Code tokens not found")
        raise_error("CODE_TOKENS_NOT_FOUND", "Code tokens not found", hint="Call /aibom/code-tokens first")
    
    code_tokens_set = set(code_tokens)
    graph = build_dependency_graph(semgrep_scan, code_tokens_set)
    logger.info(f"[AIBOM] dependency-graph: {graph['metadata']['total_files']} files, {graph['metadata']['total_dependencies']} dependencies ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(session_token, dependency_graph=graph)
    
    return DependencyGraphResponse(
        nodes=[GraphNode(**node) for node in graph["nodes"]],
        edges=[GraphEdge(**edge) for edge in graph["edges"]],
        metadata=GraphMetadata(
            total_files=graph["metadata"]["total_files"],
            total_dependencies=graph["metadata"]["total_dependencies"],
            local_imports=graph["metadata"]["local_imports"],
            external_imports=graph["metadata"]["external_imports"],
            by_language={
                lang: AIBOMLanguageStats(**stats) 
                for lang, stats in graph["metadata"].get("by_language", {}).items()
            }
        )
    )


@app.get("/aibom/llm-validate", response_model=LLMValidationResponse)
async def aibom_llm_validate(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Classify libraries as AI-positive or non-AI using LLM.
    
    **Requires:** Completed /aibom/filtered-imports endpoint.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **Returns:** AI libraries with source files, non-AI library list, and summary.
    """   
    logger.info("[AIBOM] llm-validate: Starting LLM validation of libraries")
    _t0 = _time.monotonic()
    dependencies = session.extra.get("dependencies", {})
    import_packages = session.extra.get("import_packages")
    
    if not import_packages:
        logger.warning("[AIBOM] llm-validate: Import packages not found")
        raise HTTPException(
            status_code=400,
            detail="Import packages not found. Run /aibom/filtered-imports first."
        )
    
    resolved_packages = session.extra.get("resolved_packages")
    manifests_found = session.extra.get("manifests_found", {})
    
    try:
        result = validate_libraries(dependencies, import_packages, resolved_packages, manifests_found)
    except ValueError as e:
        # Sanitize error message to prevent sensitive data leakage
        sanitized_error = sanitize_sensitive(str(e))
        logger.error("[AIBOM] llm-validate: LLM validation failed", extra={"error": sanitized_error})
        raise HTTPException(
            status_code=500,
            detail=f"LLM validation failed: {sanitized_error}"
        )
    
    if result is None:
        logger.error("[AIBOM] llm-validate: LLM validation returned no results")
        raise HTTPException(
            status_code=500,
            detail="LLM validation returned no results"
        )
    
    logger.info(f"[AIBOM] llm-validate: {result['total_classified']} classified, {result['total_ai_positive']} AI-positive, {result['total_api_positive']} API-positive ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(
        session_token,
        llm_validation=result,
        ai_libraries=result["ai_libraries"],
        api_libraries=result["api_libraries"]
    )
    
    return LLMValidationResponse(
        ai_libraries=[AILibrary(**lib) for lib in result["ai_libraries"]],
        api_libraries=[APILibrary(**lib) for lib in result["api_libraries"]],
        non_ai_libraries=result["non_ai_libraries"],
        summary=LLMValidationSummary(
            total_classified=result["total_classified"],
            total_ai_positive=result["total_ai_positive"],
            total_api_positive=result["total_api_positive"],
            total_non_ai=result["total_non_ai"],
            model_used=result["model_used"]
        )
    )


@app.get("/aibom/llm-categorize", response_model=CategorizationResponse)
async def aibom_llm_categorize(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Categorize AI-positive and API-positive libraries into specific types (single LLM call).
    
    **Requires:** /aibom/llm-validate must be called first.
    
    **Headers:** `session-token: <token from /aibom/set_repository>`
    
    **AI Categories:** AI_PROVIDER, ML_ALGORITHM, DL_ALGORITHM, AI_ORCHESTRATION, VECTOR_DB, DATA_PROCESSING
    
    **API Categories:** HTTP_CLIENT, API_FRAMEWORK, GRAPHQL, GRPC, WEBSOCKET, CLOUD_SDK, API_WRAPPER
    """
    logger.info("[AIBOM] llm-categorize: Starting unified library categorization")
    _t0 = _time.monotonic()
    if "llm_validation" not in session.extra:
        logger.warning("[AIBOM] llm-categorize: LLM validation not found")
        raise_error("LLM_VALIDATION_NOT_FOUND", "LLM validation not found", hint="Call /aibom/llm-validate first")
    
    ai_libraries = session.extra["llm_validation"].get("ai_libraries", [])
    api_libraries = session.extra["llm_validation"].get("api_libraries", [])
    
    if not ai_libraries and not api_libraries:
        logger.info("[AIBOM] llm-categorize: No AI or API libraries to categorize")
        empty_result = {
            "ai_categories": {},
            "api_categories": {},
            "total_ai_libraries": 0,
            "total_api_libraries": 0,
            "model_used": "none",
            "by_category": {},
            "total_libraries": 0,
        }
        await update_session(session_token, llm_categorization=empty_result)
        return CategorizationResponse(
            ai_categories={},
            api_categories={},
            total_ai_libraries=0,
            total_api_libraries=0,
            model_used="none"
        )
    
    result = run_categorization(ai_libraries, api_libraries)
    if not result:
        logger.error("[AIBOM] llm-categorize: Categorization failed")
        raise_error("CATEGORIZATION_FAILED", "Categorization failed", status=500, hint="Check LLM API connectivity and configuration")
    
    logger.info(f"[AIBOM] llm-categorize: {result['total_ai_libraries']} AI + {result['total_api_libraries']} API libraries categorized ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(session_token, llm_categorization=result)
    
    return CategorizationResponse(
        ai_categories={
            cat_key: CategoryGroup(
                count=cat_data["count"],
                libraries=[CategorizedLibrary(**lib) for lib in cat_data["libraries"]]
            )
            for cat_key, cat_data in result["ai_categories"].items()
        },
        api_categories={
            cat_key: CategoryGroup(
                count=cat_data["count"],
                libraries=[CategorizedLibrary(**lib) for lib in cat_data["libraries"]]
            )
            for cat_key, cat_data in result["api_categories"].items()
        },
        total_ai_libraries=result["total_ai_libraries"],
        total_api_libraries=result["total_api_libraries"],
        model_used=result["model_used"]
    )


@app.get("/aibom/frameworks-detected", response_model=FrameworksDetectedResponse)
async def aibom_frameworks_detected(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Detect and group all frameworks by type: AI, API, and Agentic.
    
    Each framework includes its base package, category, sub-imports
    (e.g. from openai import OpenAIError → OpenAIError mapped to openai),
    and the source files where it is used.
    
    **Requires:** /aibom/llm-categorize and /aibom/filtered-imports must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    
    **Framework Types:**
    - **ai**: AI_PROVIDER, ML_ALGORITHM, DL_ALGORITHM, AI_ORCHESTRATION, VECTOR_DB, DATA_PROCESSING
    - **api**: HTTP_CLIENT, API_FRAMEWORK, GRAPHQL, GRPC, WEBSOCKET, CLOUD_SDK, API_WRAPPER
    - **agentic**: AGENTIC_FRAMEWORK (crewai, autogen, langgraph, semantic-kernel, etc.)
    """
    logger.info("[AIBOM] frameworks-detected: Detecting framework types")
    _t0 = _time.monotonic()

    if "llm_categorization" not in session.extra:
        logger.warning("[AIBOM] frameworks-detected: LLM categorization not found")
        raise_error(
            "LLM_CATEGORIZATION_NOT_FOUND",
            "LLM categorization not found",
            hint="Call /aibom/llm-categorize first",
        )

    import_packages = session.extra.get("import_packages")
    if not import_packages:
        logger.warning("[AIBOM] frameworks-detected: Import packages not found")
        raise HTTPException(
            status_code=400,
            detail="Import packages not found. Run /aibom/filtered-imports first.",
        )

    result = detect_frameworks(
        categorization_data=session.extra["llm_categorization"],
        import_packages=import_packages,
    )

    logger.info(
        f"[AIBOM] frameworks-detected: "
        f"{result['summary']['total_ai']} AI, "
        f"{result['summary']['total_api']} API, "
        f"{result['summary']['total_agentic']} agentic "
        f"({(_time.monotonic()-_t0)*1000:.0f}ms)"
    )
    await update_session(session_token, frameworks_detected=result)

    return FrameworksDetectedResponse(
        ai_frameworks=[
            DetectedFramework(
                **{**fw, "sub_imports": [SubImport(**si) for si in fw.get("sub_imports", [])]}
            )
            for fw in result["ai_frameworks"]
        ],
        api_frameworks=[
            DetectedFramework(
                **{**fw, "sub_imports": [SubImport(**si) for si in fw.get("sub_imports", [])]}
            )
            for fw in result["api_frameworks"]
        ],
        agentic_frameworks=[
            DetectedFramework(
                **{**fw, "sub_imports": [SubImport(**si) for si in fw.get("sub_imports", [])]}
            )
            for fw in result["agentic_frameworks"]
        ],
        summary=FrameworksSummary(**result["summary"]),
    )


@app.get("/aibom/ai-branch-trace", response_model=AIBranchTraceResponse, response_model_exclude_none=True)
async def aibom_ai_branch_trace(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Trace AI and API library dependencies through the codebase.
    
    **Requires:** /aibom/llm-categorize and /aibom/dependency-graph must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    
    **Returns:** AI branches, API branches, and summary statistics for each.
    """
    logger.info("[AIBOM] ai-branch-trace: Tracing AI + API library dependencies")
    _t0 = _time.monotonic()
    if "llm_categorization" not in session.extra:
        logger.warning("[AIBOM] ai-branch-trace: LLM categorization not found")
        raise_error("LLM_CATEGORIZATION_NOT_FOUND", "LLM categorization not found", hint="Call /aibom/llm-categorize first")
    
    if "dependency_graph" not in session.extra:
        logger.warning("[AIBOM] ai-branch-trace: Dependency graph not found")
        raise_error("DEPENDENCY_GRAPH_NOT_FOUND", "Dependency graph not found", hint="Call /aibom/dependency-graph first")
    
    result = trace_ai_branches(
        checkout_dir=get_source_path_aibom(session),
        dependency_graph=session.extra["dependency_graph"],
        categorization_data=session.extra["llm_categorization"]
    )
    
    ai_count = result.get('summary', {}).get('total_branches', 0)
    api_count = result.get('api_summary', {}).get('total_branches', 0)
    logger.info(f"[AIBOM] ai-branch-trace: {ai_count} AI branches + {api_count} API branches ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(session_token, ai_branch_trace=result)
    
    # Build AI summary
    summary_data = result.get("summary", {})
    ai_summary = BranchTraceSummary(
        total_branches=summary_data.get("total_branches", 0),
        total_source_files=summary_data.get("total_source_files", 0),
        total_traced_files=summary_data.get("total_traced_files", 0),
        by_category={cat: CategoryStats(**stats) for cat, stats in summary_data.get("by_category", {}).items()},
        by_language={lang: BranchLanguageStats(**stats) for lang, stats in summary_data.get("by_language", {}).items()},
        timestamp=summary_data.get("timestamp", "")
    )
    
    # Build API summary
    api_summary_data = result.get("api_summary", {})
    api_summary = BranchTraceSummary(
        total_branches=api_summary_data.get("total_branches", 0),
        total_source_files=api_summary_data.get("total_source_files", 0),
        total_traced_files=api_summary_data.get("total_traced_files", 0),
        by_category={cat: CategoryStats(**stats) for cat, stats in api_summary_data.get("by_category", {}).items()},
        by_language={lang: BranchLanguageStats(**stats) for lang, stats in api_summary_data.get("by_language", {}).items()},
        timestamp=api_summary_data.get("timestamp", "")
    ) if api_summary_data else None
    
    # Build API branch list for sorted display
    api_branch_result = {"branches": result.get("api_branches", {})}
    
    return AIBranchTraceResponse(
        ai_summary=ai_summary,
        ai_branch_list=[BranchSummaryItem(**item) for item in format_branch_summary(result)],
        api_summary=api_summary,
        api_branch_list=[BranchSummaryItem(**item) for item in format_branch_summary(api_branch_result)]
    )


@app.get("/aibom/ai-targeted-scan", response_model=AITargetedScanResponse, response_model_exclude_none=True)
async def aibom_ai_targeted_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Run targeted semgrep scans on AI + API branch traced files.
    
    **AI Scan:** Provider rules → model detection (extracts AI model names)
    **API Scan:** API call rules (extracts endpoints, URLs, routes)
    
    For libraries classified as BOTH, both AI and API rules are used.
    
    **Requires:** /aibom/ai-branch-trace must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    """
    logger.info("[AIBOM] ai-targeted-scan: Running targeted semgrep scans on AI + API branches")
    _t0 = _time.monotonic()

    if "ai_branch_trace" not in session.extra:
        logger.warning("[AIBOM] ai-targeted-scan: AI branch trace not found")
        raise_error("AI_BRANCH_TRACE_NOT_FOUND", "AI branch trace not found", hint="Call /aibom/ai-branch-trace first")
    
    branch_trace = session.extra["ai_branch_trace"]
    source_path = get_source_path_aibom(session)
    languages = session.extra.get("languages_detected")
    
    # ── PASS A: AI scan (provider rules + model detection) ──
    result = scan_ai_branches(
        checkout_dir=source_path,
        branch_trace=branch_trace,
        languages_detected=languages
    )
    
    logger.info(f"[AIBOM] ai-targeted-scan: AI pass done — {result.get('summary', {}).get('libraries_scanned', 0)} libs, "
                f"{result.get('summary', {}).get('total_findings', 0)} findings, "
                f"{result.get('summary', {}).get('unique_models_detected', 0)} models")
    
    # ── PASS B: API scan (api_calls rules on API branches) ──
    api_result = scan_api_branches(
        checkout_dir=source_path,
        branch_trace=branch_trace,
        languages_detected=languages
    )
    
    api_summary_data = api_result.get("api_summary", {})
    logger.info(f"[AIBOM] ai-targeted-scan: API pass done — {api_summary_data.get('libraries_scanned', 0)} libs, "
                f"{api_summary_data.get('total_findings', 0)} findings, "
                f"{api_summary_data.get('unique_endpoints_detected', 0)} endpoints")
    
    logger.info(f"[AIBOM] ai-targeted-scan: Total time: {(_time.monotonic()-_t0)*1000:.0f}ms")
    
    # Store both results in session
    combined_result = {**result, **api_result}
    await update_session(session_token, ai_targeted_scan=combined_result)
    
    # ── Build AI scan results ──
    scan_results = []
    for data in result.get("scan_results", []):
        scan_results.append(LibraryScanResult(
            library=data.get("library", ""),
            category=data.get("category", "unknown"),
            language=data.get("language", "python"),
            scanned=data.get("scanned", True),
            reason=data.get("reason"),
            rules_used=data.get("rules_used", []),
            traced_files_count=data.get("traced_files_count", 0),
            findings_count=data.get("findings_count", 0),
            findings=[ScanFinding(**f) for f in data.get("findings", [])],
            models_detected=data.get("models_detected", []),
            provider_rule_found=data.get("provider_rule_found", False)
        ))
    
    summary_data = result.get("summary", {})
    
    # ── Get files scanned from imports scan (stored in session) ──
    imports_scan_files = session.extra.get("imports_files_scanned", [])
    imports_scan_files_count = session.extra.get("imports_files_scanned_count", len(imports_scan_files))
    
    # Build all_models as list of {model_name, tag} from models_detected
    _models_with_tags = result.get("models_detected", [])
    _seen_model_names = set()
    _all_models_dicts = []
    for m in _models_with_tags:
        mname = m.get("model", "")
        if mname not in _seen_model_names:
            _seen_model_names.add(mname)
            _all_models_dicts.append({"model_name": mname, "tag": m.get("tag", "AI")})
    _all_models_dicts.sort(key=lambda x: x["model_name"])

    # API scan results are NOT included here — they live exclusively
    # in /aibom/api-call-segregation to avoid data duplication.
    return AITargetedScanResponse(
        scan_results=scan_results,
        models_detected=[ModelDetection(**m) for m in result.get("models_detected", [])],
        model_detection_findings=[ScanFinding(**f) for f in result.get("model_detection_findings", [])],
        summary=ScanSummary(
            total_libraries=summary_data.get("total_libraries", 0),
            libraries_scanned=summary_data.get("libraries_scanned", 0),
            total_findings=summary_data.get("total_findings", 0),
            unique_models_detected=summary_data.get("unique_models_detected", 0),
            all_models=_all_models_dicts,
            imports_scan_files_count=imports_scan_files_count,
            imports_scan_files=imports_scan_files,
            errors=summary_data.get("errors", []),
            timestamp=summary_data.get("timestamp", ""),
            language=summary_data.get("language", "python"),
            rules_used=summary_data.get("rules_used", {})
        ),
        api_scan_results=[],
        api_summary=None
    )


@app.get("/aibom/api-call-segregation", response_model=APICallSegregationResponse, response_model_exclude_none=True)
async def aibom_api_call_segregation(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Segregate detected API calls by category and identify AI-related API calls.
    
    Groups all API findings from the targeted scan into their categories
    (HTTP_CLIENT, API_FRAMEWORK, GRAPHQL, GRPC, WEBSOCKET, CLOUD_SDK, API_WRAPPER)
    and separates findings from AI libraries (BOTH type) vs pure API libraries.
    
    **Requires:** /aibom/ai-targeted-scan must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    """
    logger.info("[AIBOM] api-call-segregation: Segregating API calls by category")
    _t0 = _time.monotonic()

    if "ai_targeted_scan" not in session.extra:
        logger.warning("[AIBOM] api-call-segregation: AI targeted scan not found")
        raise_error("AI_TARGETED_SCAN_NOT_FOUND", "AI targeted scan not found", hint="Call /aibom/ai-targeted-scan first")

    targeted_data = session.extra["ai_targeted_scan"]
    api_scan_results = targeted_data.get("api_scan_results", [])
    api_endpoints_detected = targeted_data.get("api_endpoints_detected", [])

    # ── Identify AI libraries (libraries that are also AI-positive / BOTH) ──
    ai_lib_names: set[str] = set()
    llm_validation = session.extra.get("llm_validation", {})
    for lib in llm_validation.get("ai_libraries", []):
        ai_lib_names.add(lib.get("library", "").lower())

    # Only mark AI libraries that are ALSO in api_scan_results as AI-API libs
    # (true BOTH-type libraries). Pure-AI-only libraries should NOT be in ai_lib_names.
    api_lib_names_set = {
        d.get("library", "").lower() for d in api_scan_results
    }
    ai_scan_results = targeted_data.get("scan_results", [])
    for lib_data in ai_scan_results:
        lib_lower = lib_data.get("library", "").lower()
        if lib_lower in api_lib_names_set:
            ai_lib_names.add(lib_lower)

    # ── Group API results by category ──
    categories: dict[str, dict] = {}

    for lib_data in api_scan_results:
        lib_name = lib_data.get("library", "")
        category = (lib_data.get("category") or "unknown").upper()
        is_ai_lib = lib_name.lower() in ai_lib_names

        if category not in categories:
            categories[category] = {
                "libraries": [],
                "ai_api_libraries": [],
                "other_api_libraries": [],
                "ai_api_findings": [],
                "other_api_findings": [],
                "endpoints": set(),
            }

        cat = categories[category]
        cat["libraries"].append(lib_name)

        if is_ai_lib:
            cat["ai_api_libraries"].append(lib_name)
        else:
            cat["other_api_libraries"].append(lib_name)

        # Segregate findings
        for f in lib_data.get("findings", []):
            finding = ScanFinding(**f) if isinstance(f, dict) else f
            if is_ai_lib:
                cat["ai_api_findings"].append(finding)
            else:
                cat["other_api_findings"].append(finding)

        # Collect endpoints
        for ep in lib_data.get("endpoints_detected", []):
            cat["endpoints"].add(ep if isinstance(ep, str) else str(ep))

    # ── Include AI scan findings for BOTH libraries (e.g. chat.completions.create) ──
    # These are captured by AI provider rules (Pass A), not API call rules (Pass B).
    # Map them to the library's API category so they appear as ai_api_findings.
    # Build API category lookup from api_scan_results + llm_categorization
    lib_api_category: dict[str, str] = {}
    for lib_data in api_scan_results:
        ln = lib_data.get("library", "").lower()
        lib_api_category[ln] = (lib_data.get("category") or "unknown").upper()
    llm_cat_data = session.extra.get("llm_categorization", {})
    for cat_name, cat_group in llm_cat_data.get("api_categories", {}).items():
        for lib_entry in cat_group.get("libraries", []):
            ln = (lib_entry.get("library") or "").lower()
            if ln and ln not in lib_api_category:
                lib_api_category[ln] = cat_name.upper()

    for lib_data in ai_scan_results:
        lib_name = lib_data.get("library", "")
        if lib_name.lower() not in ai_lib_names:
            continue
        ai_findings = lib_data.get("findings", [])
        if not ai_findings:
            continue
        # Determine API category for this AI library
        api_cat = lib_api_category.get(lib_name.lower(), (lib_data.get("category") or "AI_PROVIDER").upper())
        if api_cat not in categories:
            categories[api_cat] = {
                "libraries": [],
                "ai_api_libraries": [],
                "other_api_libraries": [],
                "ai_api_findings": [],
                "other_api_findings": [],
                "endpoints": set(),
            }
        cat = categories[api_cat]
        if lib_name not in cat["libraries"]:
            cat["libraries"].append(lib_name)
        if lib_name not in cat["ai_api_libraries"]:
            cat["ai_api_libraries"].append(lib_name)
        # Dedupe: collect existing finding signatures to avoid duplicates with Pass B
        existing_sigs = {
            (f.file if hasattr(f, 'file') else f.get('file', ''),
             f.line if hasattr(f, 'line') else f.get('line', 0))
            for f in cat["ai_api_findings"]
        }
        for f in ai_findings:
            finding = ScanFinding(**f) if isinstance(f, dict) else f
            sig = (finding.file, finding.line)
            if sig not in existing_sigs:
                cat["ai_api_findings"].append(finding)
                existing_sigs.add(sig)

    # Also fold in endpoints from api_endpoints_detected (may carry extra context)
    for ep in api_endpoints_detected:
        ep_category = (ep.get("category") or "unknown").upper() if isinstance(ep, dict) else "UNKNOWN"
        ep_str = ep.get("endpoint", "") if isinstance(ep, dict) else str(ep)
        if ep_category in categories and ep_str:
            categories[ep_category]["endpoints"].add(ep_str)

    # ── Build response models ──
    category_models: dict[str, CategoryAPIFindings] = {}
    total_ai_api = 0
    total_other_api = 0
    total_endpoints = 0
    cats_breakdown: dict[str, int] = {}

    for cat_name, cat_data in sorted(categories.items()):
        ai_count = len(cat_data["ai_api_findings"])
        other_count = len(cat_data["other_api_findings"])
        eps = sorted(cat_data["endpoints"])

        total_ai_api += ai_count
        total_other_api += other_count
        total_endpoints += len(eps)
        cats_breakdown[cat_name] = ai_count + other_count

        category_models[cat_name] = CategoryAPIFindings(
            category=cat_name,
            total_findings=ai_count + other_count,
            ai_api_count=ai_count,
            other_api_count=other_count,
            libraries=cat_data["libraries"],
            ai_api_libraries=cat_data["ai_api_libraries"],
            other_api_libraries=cat_data["other_api_libraries"],
            ai_api_findings=cat_data["ai_api_findings"],
            other_api_findings=cat_data["other_api_findings"],
            endpoints=eps,
        )

    both_libs = sorted({
        lib for cat_data in categories.values()
        for lib in cat_data["ai_api_libraries"]
    })

    total_findings = total_ai_api + total_other_api
    logger.info(
        f"[AIBOM] api-call-segregation: {len(categories)} categories, "
        f"{total_findings} findings ({total_ai_api} AI-API, {total_other_api} other), "
        f"{len(both_libs)} AI-API libs ({(_time.monotonic()-_t0)*1000:.0f}ms)"
    )

    return APICallSegregationResponse(
        categories=category_models,
        ai_api_libraries=both_libs,
        summary=APICallSegregationSummary(
            total_categories_found=len(categories),
            total_api_findings=total_findings,
            total_ai_api_findings=total_ai_api,
            total_other_api_findings=total_other_api,
            total_endpoints=total_endpoints,
            ai_api_libraries=both_libs,
            categories_breakdown=cats_breakdown,
        ),
    )


@app.get("/aibom/model-card-handler", response_model=ModelCardHandlerResponse)
async def aibom_model_card_handler(
    session: SessionData = Depends(require_validated_session())
):
    """
    Fetch model cards for detected models with iterative suffix stripping.
    
    **Requires:** /aibom/ai-targeted-scan must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    """
    logger.info("[AIBOM] model-card-handler: Fetching model cards for detected models")
    _t0 = _time.monotonic()

    if "ai_targeted_scan" not in session.extra:
        logger.warning("[AIBOM] model-card-handler: AI targeted scan not found")
        raise_error("AI_TARGETED_SCAN_NOT_FOUND", "AI targeted scan not found", hint="Call /aibom/ai-targeted-scan first")
    
    distinct_models = session.extra["ai_targeted_scan"].get("distinct_models", [])
    
    if not distinct_models:
        logger.info("[AIBOM] model-card-handler: No models detected to fetch cards for")
        return ModelCardHandlerResponse(
            models_processed=0,
            found_count=0,
            not_found_count=0,
            results=[]
        )
    
    result = process_models_for_cards(
        model_names=distinct_models,
        hf_token=os.environ.get("HF_TOKEN"),
        try_stripping=True,
        try_azure=True
    )
    
    logger.info(f"[AIBOM] model-card-handler: {result.get('models_processed', 0)} processed, {result.get('found_count', 0)} cards found ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    session.extra["model_card_results"] = result
    
    results = [
        ModelCardResult(
            model_card_found=r.get("model_card_found", False),
            original_model_name=r.get("original_model_name", ""),
            base_model_name=r.get("base_model_name", ""),
            stripped_suffixes=r.get("stripped_suffixes", []),
            suffix_info=[
                SuffixInfo(
                    suffix=s.get("suffix", ""), 
                    type=s.get("type", "unknown"),
                    meaning=s.get("meaning", ""), 
                    token_count=s.get("token_count"),
                    parameter_count=s.get("parameter_count")
                ) for s in r.get("suffix_info", [])
            ],
            model_card=r.get("model_card"),
            lookup_source=r.get("lookup_source"),
            iterations_required=r.get("iterations_required", 0)
        )
        for r in result.get("results", [])
    ]
    
    summary_data = result.get("summary", {})
    return ModelCardHandlerResponse(
        models_processed=result.get("models_processed", 0),
        found_count=result.get("found_count", 0),
        not_found_count=result.get("not_found_count", 0),
        results=results
    )


@app.get("/aibom/model-deprecation-check", response_model=ModelDeprecationResponse)
async def aibom_model_deprecation_check(
    session: SessionData = Depends(require_validated_session())
):
    """
    Check models against deprecation databases.
    
    **Requires:** /aibom/ai-targeted-scan must be called first.
    
    **Headers:** `session-token: <token from /aibom/set-repository>`
    """
    logger.info("[AIBOM] model-deprecation-check: Checking models for deprecation status")
    _t0 = _time.monotonic()

    if "ai_targeted_scan" not in session.extra:
        logger.warning("[AIBOM] model-deprecation-check: AI targeted scan not found")
        raise_error("AI_TARGETED_SCAN_NOT_FOUND", "AI targeted scan not found", hint="Call /aibom/ai-targeted-scan first")
    
    distinct_models = session.extra["ai_targeted_scan"].get("distinct_models", [])
    
    if not distinct_models:
        logger.info("[AIBOM] model-deprecation-check: No models to check for deprecation")
        return ModelDeprecationResponse(
            models_checked=0,
            deprecated_count=0,
            active_count=0,
            not_found_count=0,
            results=[],
            summary=DeprecationSummary(
                models_checked=0,
                deprecated_count=0,
                active_count=0,
                not_found_count=0,
                severity_breakdown={}
            )
        )
    
    result = check_models_deprecation(distinct_models)
    
    logger.info(f"[AIBOM] model-deprecation-check: {result.get('models_checked', 0)} checked, {result.get('deprecated_count', 0)} deprecated ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    session.extra["model_deprecation_results"] = result
    
    # Get model card results to check which models have cards
    model_card_results = session.extra.get("model_card_results", {}).get("results", [])
    model_cards_found = {r.get("model_name"): r.get("card_found", False) for r in model_card_results}
    
    results = [
        ModelDeprecationResult(
            model_name=r.get("model_name", ""),
            model_card_found=model_cards_found.get(r.get("model_name", ""), False),
            deprecation_found=r.get("deprecation_found", False),
            deprecation_info=DeprecationInfo(**r["deprecation_info"]) if r.get("deprecation_info") else None,
            message="deprecated" if r.get("deprecation_found") else "active"
        )
        for r in result.get("results", [])
    ]
    
    not_found_count = 0  # check_models_deprecation doesn't track not_found separately
    shutdown_count = result.get("shutdown_count", 0)
    sev_breakdown = result.get("severity_breakdown", {})

    return ModelDeprecationResponse(
        models_checked=result.get("models_checked", 0),
        deprecated_count=result.get("deprecated_count", 0),
        shutdown_count=shutdown_count,
        active_count=result.get("active_count", 0),
        not_found_count=not_found_count,
        results=results,
        summary=DeprecationSummary(
            models_checked=result.get("models_checked", 0),
            deprecated_count=result.get("deprecated_count", 0),
            shutdown_count=shutdown_count,
            active_count=result.get("active_count", 0),
            not_found_count=not_found_count,
            severity_breakdown=sev_breakdown
        )
    )


# =============================================================================
# SBOM ENDPOINTS
# =============================================================================

@app.get("/sbom/start-scan", response_model=StartScanResponse)
async def sbom_start_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Initialize the scan and assign a scan ID.
    
    **Requires:** Completed validation via /sbom/set-repository.
    
    **Headers:** `session-token: <token from /sbom/set-repository>`
    
    **Returns:** Scan ID and workflow steps.
    """
    logger.info("[SBOM] start-scan: Initializing SBOM scan")
    _t0 = _time.monotonic()
    scan_id = orchestrator.get_next_scan_id()
    logger.info(f"[SBOM] start-scan: Assigned scan ID {scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    await update_session(session_token, scan_id=scan_id)
    
    return StartScanResponse(
        message="Scan initialized successfully",
        scan_id=scan_id,
        next_step="GET /sbom/discover_and_parse",
        workflow=[
            "/sbom/discover_and_parse - Find manifests and extract packages",
            "/sbom/detect_unused - Detect unused dependencies (optional)",
            "/sbom/fetch_depsdev - Enrich with deps.dev metadata",
            "/sbom/registry_enrich - Enrich from PyPI/npm registries",
            "/sbom/fetch_osv - Fetch vulnerabilities",
            "/sbom/generate_sbom - Generate all SBOM formats",
            "/sbom/generate_json - Generate detailed JSON report",
            "/sbom/generate_spdx - Generate SPDX SBOM",
            "/sbom/generate_cyclonedx - Generate CycloneDX SBOM",
            "/sbom/generate_remediation - Generate remediation report"
        ]
    )


@app.get("/sbom/discover-and-parse")
async def sbom_discover_and_parse(
    session: SessionData = Depends(require_scan_initialized()),
    session_token: str = Header(...)
):
    """
    Step 1+2 Combined: Discover manifests AND parse them in a single call.
    
    **Requires:** /sbom/start-scan to be called first.
    
    **Headers:** `session-token: <token from /sbom/set-repository>`
    """
    logger.info("[SBOM] discover-and-parse: Discovering manifests and parsing packages")
    _t0 = _time.monotonic()
    from sbom.src.registry.language_registry import get_language_for_manifest
    
    # Use AIBOM base directory since files are validated by unified /set-repository
    workspace = Path(get_source_path_aibom(session))
    
    if not workspace.exists():
        logger.error(f"[SBOM] discover-and-parse: Source not found at {workspace}")
        raise HTTPException(status_code=404, detail={
            "error": "SOURCE_NOT_FOUND",
            "message": "Validated source no longer exists. Please validate again."
        })
    
    packages = session.extra.get("packages")
    if packages:
        logger.info(f"[SBOM] discover-and-parse: Using cached results - {len(packages)} packages already processed")
        manifests = session.extra.get("manifest_files", [])
        by_ecosystem = {}
        for p in packages:
            eco = p.get("language", "unknown")
            by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
        
        return {
            "message": "Manifests and packages already processed",
            "scan_id": session.scan_id,
            "manifests_found": len(manifests),
            "packages_found": len(packages),
            "by_ecosystem": by_ecosystem,
            "next_step": "GET /sbom/detect_unused (optional) or GET /sbom/fetch_depsdev"
        }
    
    # Diagnostic: log workspace path and top-level contents
    logger.info(f"[SBOM] discover-and-parse: Workspace path = {workspace}")
    logger.info(f"[SBOM] discover-and-parse: Workspace exists = {workspace.exists()}, is_dir = {workspace.is_dir()}")
    if workspace.is_dir():
        top_items = list(workspace.iterdir())
        logger.info(f"[SBOM] discover-and-parse: Top-level items ({len(top_items)}): {[str(i.name) for i in top_items[:20]]}")
        # If there's only a single subdirectory, the ZIP likely has a root folder wrapper
        if len(top_items) == 1 and top_items[0].is_dir():
            inner = top_items[0]
            logger.info(f"[SBOM] discover-and-parse: Single subdirectory detected: {inner.name}")
            inner_items = list(inner.iterdir())
            logger.info(f"[SBOM] discover-and-parse: Inner directory items ({len(inner_items)}): {[str(i.name) for i in inner_items[:20]]}")
            # Auto-unwrap: use the inner directory as the actual workspace
            logger.info(f"[SBOM] discover-and-parse: Auto-unwrapping ZIP root folder → using {inner}")
            workspace = inner

    manifests = orchestrator.discover_manifests(workspace)
    packages, cataloger_manifests, lock_data = orchestrator.run_catalogers(workspace)
    packages = orchestrator.scan_codebase_properties(workspace, packages)

    # Detect which ecosystems are fully covered by lock files.
    # Catalogers set version_source="lock_file" on every package read from a lock file,
    # which means the full resolved tree is already in `packages` — no need for deps.dev
    # to add extra transitive packages on top.
    lock_file_ecosystems: set = set()
    for _p in packages:
        if _p.get("version_source") == "lock_file":
            _eco = (_p.get("language") or _p.get("ecosystem") or "").lower()
            if _eco:
                lock_file_ecosystems.add(_eco)
    if lock_file_ecosystems:
        logger.info(f"[SBOM] discover-and-parse: Lock file covers ecosystems: {lock_file_ecosystems} "
                    "— transitive expansion will be skipped for these")

    # Persist lock_data for use by /sbom/fetch-depsdev (transitive resolution)
    if lock_data:
        logger.info(f"[SBOM] discover-and-parse: Storing lock_data ({len(lock_data)} entries) in session")
    
    license_info = None
    try:
        from sbom.src.utils.license_detector import detect_license_files, get_license_summary_for_sbom
        license_info = get_license_summary_for_sbom(workspace)
    except Exception as e:
        license_info = {"declared_license": "NOASSERTION", "error": str(e)}
    
    manifest_details = []
    ecosystems_found = set()
    for m in manifests:
        if isinstance(m, dict):
            filename = m.get("file", "")
            path = m.get("path", "")
        else:
            filename = os.path.basename(m)
            path = m
        
        ecosystem = get_language_for_manifest(filename) or "unknown"
        ecosystems_found.add(ecosystem)
        # Show repo-relative path instead of full temp directory path
        display_path = path
        if display_path:
            # Extract just the repo-relative portion: everything after the repo folder
            # e.g. "...\bytehide_CSharp-ChatBot-GPT\ChatbotGPT.csproj" → "ChatbotGPT.csproj"
            parts = display_path.replace("\\", "/").split("/")
            # Find the temp checkout folder pattern and take path after it
            for i, part in enumerate(parts):
                if part.startswith("stacksq_") or part.startswith("aibom_") or part.startswith("sbom_"):
                    # Next part is the repo folder, take everything after it
                    if i + 2 < len(parts):
                        display_path = "/".join(parts[i + 2:])
                    elif i + 1 < len(parts):
                        display_path = "/".join(parts[i + 1:])
                    break
        manifest_details.append({"file": filename, "ecosystem": ecosystem, "path": display_path})
    
    by_ecosystem = {}
    for p in packages:
        eco = p.get("language", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
    
    codebase_props = {"executable": "No", "archive": "No", "structured_properties": "No"}
    if packages:
        codebase_props = {
            "executable": packages[0].get("executable", "No"),
            "archive": packages[0].get("archive", "No"),
            "structured_properties": packages[0].get("structured_properties", "No")
        }
    
    await update_session(
        session_token,
        packages=packages,
        manifest_files=manifests,
        ecosystems_detected=list(ecosystems_found),
        repo_license=license_info,
        lock_data=lock_data if lock_data else {},
        lock_file_ecosystems=list(lock_file_ecosystems)
    )
    
    packages_summary = orchestrator.format_packages_summary(packages, limit=15)
    await mark_step_complete(session_token, "discover_and_parse")
    
    logger.info(f"[SBOM] discover-and-parse: {len(manifests)} manifests, {len(packages)} packages, {len(ecosystems_found)} ecosystems ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "Manifest discovery and parsing complete",
        "scan_id": session.scan_id,
        "manifests_found": len(manifests),
        "ecosystems_detected": list(ecosystems_found),
        "manifests": manifest_details,
        "packages_found": len(packages),
        "by_ecosystem": by_ecosystem,
        "packages": packages_summary,
        "codebase_properties": codebase_props,
        "license_detection": license_info,
        "next_step": "GET /sbom/detect_unused (optional) or GET /sbom/fetch_depsdev"
    }


def _clean_nuget_version_range(version_str: str) -> str:
    """Convert NuGet version range to minimum version for PURL.
    
    Examples:
      '[2.14.1, )'  -> '2.14.1'
      '[5.0.0]'     -> '5.0.0'
      '(, 3.0.0)'   -> '3.0.0'
      '2.14.1'      -> '2.14.1'  (no-op)
    """
    import re as _re
    if not version_str or version_str == "unknown":
        return version_str
    # Strip brackets and parentheses
    cleaned = version_str.strip("[]() ")
    # Take the first non-empty part (split by comma)
    parts = [p.strip() for p in cleaned.split(",") if p.strip()]
    if parts:
        # Return the first concrete version number
        for p in parts:
            if _re.match(r'^\d', p):
                return p
    return version_str  # fallback to original


@app.get("/sbom/fetch-depsdev")
async def sbom_fetch_depsdev(
    session: SessionData = Depends(require_step("fetch-depsdev")),
    session_token: str = Header(...)
):
    """
    Step 3: Enrich packages with metadata AND transitive dependencies from deps.dev API.
    
    **Requires:** /sbom/discover_and_parse to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] fetch-depsdev: Enriching packages with deps.dev metadata")
    _t0 = _time.monotonic()
    from sbom.src.clients.depsdev_client import get_client
    from sbom.src.registry.language_registry import get_purl_type
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] fetch-depsdev: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /sbom/discover_and_parse first."
        })
    
    # Retrieve lock_data persisted by discover_and_parse (if any)
    lock_data = session.extra.get("lock_data") or {}
    if lock_data:
        logger.info(f"[SBOM] fetch-depsdev: Found lock_data ({len(lock_data)} entries) for transitive resolution")
    lock_file_ecosystems = set(session.extra.get("lock_file_ecosystems") or [])
    if lock_file_ecosystems:
        logger.info(f"[SBOM] fetch-depsdev: Skipping transitive expansion for lock-covered ecosystems: {lock_file_ecosystems}")
    
    client = get_client()
    transitive_packages = []
    seen_packages = set()
    direct_names = set()
    
    for p in packages:
        # Respect is_direct_dependency already set by catalogers (e.g., Rust, .NET, Ruby, etc.)
        # Only default to True if not already set
        if "is_direct_dependency" not in p:
            p["is_direct_dependency"] = True
        # Ensure version_resolved / version_source are set for direct packages
        if "version_resolved" not in p:
            p["version_resolved"] = True  # cataloger parsed from manifest = resolved
        if "version_source" not in p:
            p["version_source"] = "manifest"
        key = f"{p.get('name')}@{p.get('version')}"
        seen_packages.add(key.lower())
        if p.get("is_direct_dependency", True):
            direct_names.add(p.get("name", "").lower())
    
    # ================================================================
    # PRIORITY 0: Use lock_data if available (most accurate — actual
    # installed versions from Pipfile.lock / poetry.lock)
    # ================================================================
    lock_data_used = False
    if lock_data:
        # Build a language lookup from existing direct packages for proper multi-language support
        pkg_language_map: dict[str, str] = {}
        for p in packages:
            pname = (p.get("name") or "").lower()
            plang = (p.get("language") or "").lower()
            if pname and plang:
                pkg_language_map[pname] = plang
        # Determine the most common language as fallback
        if pkg_language_map:
            from collections import Counter
            lang_counts = Counter(pkg_language_map.values())
            default_lang = lang_counts.most_common(1)[0][0]
        else:
            default_lang = ""

        for name_lower, pkg_info in lock_data.items():
            version = pkg_info.get("version", "")
            if not version or version in ("UNKNOWN", ""):
                continue
            key = f"{name_lower}@{version}".lower()
            if key in seen_packages or name_lower in direct_names:
                continue
            seen_packages.add(key)
            # Infer language: check if a direct dependency with same name exists, else use most common
            lang = pkg_language_map.get(name_lower, default_lang)
            purl_type = get_purl_type(lang) if lang else "unknown"
            transitive_packages.append({
                "name": name_lower,
                "version": version,
                "language": lang,
                "ecosystem": purl_type,
                "is_direct_dependency": False,
                "transitive_source": "lock_file",
                "version_resolved": True,
                "version_source": "lock_file",
                "purl": f"pkg:{purl_type}/{name_lower}@{version}" if lang else f"pkg:pypi/{name_lower}@{version}",
                "hashes": pkg_info.get("hashes", []),
                "component_dependencies": pkg_info.get("dependencies", []),
            })
        if transitive_packages:
            lock_data_used = True
            logger.info(f"[TRANSITIVE] Added {len(transitive_packages)} transitive deps from lock_data")
    
    # ================================================================
    # STEP A: Fetch dependency graphs (deps.dev → registry fallback)
    # Only for packages NOT already resolved via lock_data
    # ================================================================
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        lang = (pkg.get("language") or pkg.get("ecosystem") or "").lower()
        
        if not name or not version:
            continue

        # Lock file covers this ecosystem — the cataloger already captured the full
        # resolved dependency tree. Skip deps.dev expansion to avoid adding phantom
        # packages (optional deps, platform deps, etc.) not actually installed.
        if lang in lock_file_ecosystems:
            pkg.setdefault("component_dependencies", [])
            pkg.setdefault("total_dependencies", 0)
            continue

        ecosystem = get_purl_type(lang)
        
        try:
            # 1) Try deps.dev dependency graph first
            dep_graph = client.get_dependency_graph(ecosystem, name, version)
            component_deps = []
            dep_source = dep_graph.get("source", "none") if dep_graph else "none"
            
            if dep_graph and dep_graph.get("total_dependencies", 0) > 0:
                for dep in dep_graph.get("direct", []) + dep_graph.get("transitive", []):
                    dep_name = dep.get("name")
                    dep_version = dep.get("version", "unknown")
                    purl = f"pkg:{ecosystem}/{dep_name}@{dep_version}"
                    component_deps.append(purl)
                    
                    dep_key = f"{dep_name}@{dep_version}"
                    if dep_key.lower() not in seen_packages:
                        transitive_packages.append({
                            "name": dep_name,
                            "version": dep_version,
                            "language": lang,
                            "is_direct_dependency": False,
                            "transitive_source": "deps.dev",
                            "version_resolved": True,
                            "version_source": "deps.dev",
                        })
                        seen_packages.add(dep_key.lower())
                
                pkg["component_dependencies"] = component_deps
                pkg["total_dependencies"] = len(component_deps)
            else:
                # 2) deps.dev returned empty (SELF-only or failed) → fallback to registry
                # NOTE: For Go/Rust/.NET/Ruby/PHP/Swift, the catalogers already embed
                # transitive deps from lock files directly into packages list.
                # This fallback covers cases where NO lock file was present.
                logger.debug(f"[DEP GRAPH] deps.dev empty for {name}@{version}, trying registry fallback")
                registry_deps = []
                
                if lang in ("python", "pip", ""):
                    try:
                        from sbom.src.clients.pypi_client import fetch_pypi_meta, extract_dependencies_from_pypi_meta
                        pypi_meta = fetch_pypi_meta(name, version)
                        if pypi_meta:
                            registry_deps = extract_dependencies_from_pypi_meta(pypi_meta)
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] PyPI fallback failed for {name}@{version}: {e}")

                elif lang in ("javascript", "node", "npm"):
                    try:
                        from sbom.src.clients.npm_client import NpmClient
                        npm_client = NpmClient()
                        npm_result = npm_client.get_package_info(name, version)
                        if npm_result and npm_result.get("success") and npm_result.get("raw_data"):
                            raw_data = npm_result["raw_data"]
                            version_data = raw_data.get("versions", {}).get(version, {})
                            npm_deps = version_data.get("dependencies", {})
                            for dep_name_npm, dep_ver_spec in npm_deps.items():
                                registry_deps.append({"name": dep_name_npm, "version": "unknown"})
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] npm fallback failed for {name}@{version}: {e}")

                elif lang in ("rust", "cargo", "crate", "crates"):
                    try:
                        from sbom.src.clients.cargo_client import fetch_cargo_meta
                        meta = fetch_cargo_meta(name, version)
                        if meta:
                            ver_info = meta.get("version", {})
                            for dep_item in ver_info.get("dependencies", []):
                                dep_crate = dep_item.get("crate_id") or dep_item.get("name", "")
                                if dep_crate:
                                    registry_deps.append({"name": dep_crate, "version": "unknown"})
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] crates.io fallback failed for {name}@{version}: {e}")

                elif lang in ("php", "composer", "packagist"):
                    try:
                        from sbom.src.clients.packagist_client import fetch_packagist_meta
                        meta = fetch_packagist_meta(name, version)
                        if meta:
                            requires = meta.get("require", {})
                            for dep_pkg, _ in requires.items():
                                if not dep_pkg.startswith("php") and "/" in dep_pkg:
                                    registry_deps.append({"name": dep_pkg, "version": "unknown"})
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] Packagist fallback failed for {name}@{version}: {e}")

                elif lang in ("ruby", "gem", "rubygems", "bundler"):
                    try:
                        from sbom.src.clients.rubygems_client import fetch_rubygems_meta
                        meta = fetch_rubygems_meta(name, version)
                        if meta:
                            for dep_item in meta.get("dependencies", {}).get("runtime", []):
                                dep_gem = dep_item.get("name", "")
                                if dep_gem:
                                    registry_deps.append({"name": dep_gem, "version": "unknown"})
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] RubyGems fallback failed for {name}@{version}: {e}")

                elif lang in ("dotnet", "nuget", "csharp", "cs"):
                    try:
                        import requests as _req
                        name_lower = name.lower()
                        reg_url = f"https://api.nuget.org/v3/registration5-semver1/{name_lower}/{version}.json"
                        reg_r = _req.get(reg_url, timeout=15)
                        if reg_r.status_code == 200:
                            reg_data = reg_r.json()
                            cat = reg_data.get("catalogEntry", {})
                            # catalogEntry may be a URL string — resolve it
                            if isinstance(cat, str):
                                cat_r = _req.get(cat, timeout=15)
                                cat = cat_r.json() if cat_r.status_code == 200 else {}
                            # Collect deps across all target frameworks (deduplicate)
                            seen_nuget = set()
                            for dep_group in cat.get("dependencyGroups", []):
                                for dep_item in dep_group.get("dependencies", []):
                                    dep_id = dep_item.get("id", "")
                                    dep_range = dep_item.get("range", "unknown")
                                    # Convert NuGet version range to minimum version
                                    # e.g. "[2.14.1, )" -> "2.14.1"
                                    dep_ver = _clean_nuget_version_range(dep_range)
                                    if dep_id and dep_id not in seen_nuget:
                                        seen_nuget.add(dep_id)
                                        registry_deps.append({"name": dep_id, "version": dep_ver})
                    except Exception as e:
                        logger.debug(f"[DEP GRAPH] NuGet fallback failed for {name}@{version}: {e}")

                # Go, Java, Swift, Conda, C/C++: deps.dev is the primary source
                # (for Go/Java/Maven); C/C++ not supported by deps.dev at all
                # — registry fallback not available for dep-graph extraction.
                # If lock file was parsed, transitive deps are already inline.
                
                if registry_deps:
                    logger.info(f"[DEP GRAPH] Registry fallback found {len(registry_deps)} deps for {name}@{version}")
                    for dep in registry_deps:
                        dep_name = dep.get("name")
                        dep_version = dep.get("version", "unknown")
                        purl = f"pkg:{ecosystem}/{dep_name}@{dep_version}"
                        component_deps.append(purl)
                        
                        dep_key = f"{dep_name}@{dep_version}"
                        if dep_key.lower() not in seen_packages:
                            transitive_packages.append({
                                "name": dep_name,
                                "version": dep_version,
                                "language": lang,
                                "is_direct_dependency": False,
                                "transitive_source": "registry",
                                "version_resolved": dep_version != "unknown",
                                "version_source": "registry" if dep_version != "unknown" else "unknown",
                            })
                            seen_packages.add(dep_key.lower())
                
                pkg["component_dependencies"] = component_deps
                pkg["total_dependencies"] = len(component_deps)
                
        except Exception as e:
            logging.error(f"Error fetching deps for {name}@{version}: {e}")
            pkg["component_dependencies"] = []
            pkg["total_dependencies"] = 0
    
    packages.extend(transitive_packages)
    packages = orchestrator.enrich_metadata(packages)
    
    # ================================================================
    # STEP B: Registry fallback for ALL fields still missing
    # Fallback chain: deps.dev → registry → cache → NOASSERTION
    # Supports: Python(PyPI), JS(npm), .NET(NuGet), Ruby(RubyGems),
    #           PHP(Packagist), Go(proxy), Java(Maven), Rust(crates.io),
    #           Swift(CocoaPods), Conda(Anaconda)
    # ================================================================
    from sbom.src.clients.pypi_client import (
        fetch_pypi_meta, extract_license_from_pypi_meta,
        extract_homepage_from_pypi_meta, extract_release_date_from_pypi
    )
    from sbom.src.clients.depsdev_client import normalize_license
    
    _bad_vals = {"", "noassertion", "non-standard", "unknown", "n/a", "none"}
    
    for p in packages:
        pkg_name = p.get("name", "")
        pkg_version = p.get("version", "")
        pkg_lang = (p.get("language") or "").lower()
        
        license_val = p.get("license") or p.get("component_license") or ""
        homepage_val = p.get("homepage") or ""
        release_date_val = p.get("release_date") or ""
        
        # Normalize any license that's still full text (>80 chars)
        if license_val and len(str(license_val)) > 80:
            license_val = normalize_license(str(license_val))
            if len(str(license_val)) > 80:
                license_val = ""  # Mark empty for fallback, not NOASSERTION yet
            p["license"] = license_val
            p["component_license"] = license_val
        
        # Check which fields still need fallback
        needs_license = not license_val or str(license_val).strip().lower() in _bad_vals
        needs_homepage = not homepage_val or str(homepage_val).strip().lower() in _bad_vals
        needs_release_date = not release_date_val or str(release_date_val).strip().lower() in _bad_vals
        
        # Also check description/supplier — these are often missing even when license/homepage are set
        _desc_bad = {"", "n/a", "no description available", "no description available.", "unknown"}
        _sup_bad = {"", "n/a", "unknown"}
        desc_val = (p.get("component_description") or p.get("description") or "").strip()
        sup_val = (p.get("component_supplier") or p.get("supplier") or "").strip()
        needs_description = not desc_val or desc_val.lower() in _desc_bad
        needs_supplier = not sup_val or sup_val.lower() in _sup_bad
        
        if needs_license or needs_homepage or needs_release_date or needs_description or needs_supplier:
            # Try registry fallback based on ecosystem
            if pkg_lang in ("python", "pip", ""):
                try:
                    pypi_meta = fetch_pypi_meta(pkg_name, pkg_version)
                    if pypi_meta:
                        if needs_license:
                            pypi_license = extract_license_from_pypi_meta(pypi_meta)
                            if pypi_license:
                                pypi_license = normalize_license(str(pypi_license))
                            if pypi_license and len(str(pypi_license)) > 80:
                                pypi_license = ""
                            if pypi_license and str(pypi_license).strip().lower() not in _bad_vals:
                                p["license"] = pypi_license
                                p["component_license"] = pypi_license
                                needs_license = False
                        
                        if needs_homepage:
                            pypi_homepage = extract_homepage_from_pypi_meta(pypi_meta)
                            if pypi_homepage:
                                p["homepage"] = pypi_homepage
                                needs_homepage = False
                        
                        if needs_release_date:
                            pypi_date = extract_release_date_from_pypi(pypi_meta, pkg_version)
                            if pypi_date:
                                p["release_date"] = pypi_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] PyPI fallback failed for {pkg_name}: {e}")
            
            elif pkg_lang in ("javascript", "node", "npm"):
                try:
                    from sbom.src.clients.npm_client import NpmClient
                    npm_client = NpmClient()
                    npm_result = npm_client.get_package_info(pkg_name, pkg_version)
                    if npm_result and npm_result.get("success") and npm_result.get("raw_data"):
                        raw_data = npm_result["raw_data"]
                        version_data = raw_data.get("versions", {}).get(pkg_version, {})
                        
                        if needs_license:
                            npm_license = version_data.get("license") or raw_data.get("license") or ""
                            if isinstance(npm_license, dict):
                                npm_license = npm_license.get("type", "")
                            if npm_license and str(npm_license).strip().lower() not in _bad_vals:
                                p["license"] = str(npm_license)
                                p["component_license"] = str(npm_license)
                                needs_license = False
                        
                        if needs_homepage:
                            npm_homepage = raw_data.get("homepage") or ""
                            repo = raw_data.get("repository", {})
                            if isinstance(repo, dict):
                                npm_homepage = npm_homepage or repo.get("url", "")
                            if npm_homepage:
                                # Clean git+https:// URLs
                                npm_homepage = npm_homepage.replace("git+", "").replace(".git", "")
                                p["homepage"] = npm_homepage
                                needs_homepage = False
                        
                        if needs_release_date:
                            time_data = raw_data.get("time", {})
                            npm_date = time_data.get(pkg_version, "")
                            if npm_date:
                                p["release_date"] = npm_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] npm fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("dotnet", ".net", "csharp", "c#", "nuget", "fsharp"):
                try:
                    from sbom.src.clients.nuget_client import fetch_nuget_meta, extract_license_from_nuget_meta, extract_release_date_from_nuget
                    meta = fetch_nuget_meta(pkg_name, pkg_version)
                    if meta:
                        if needs_license:
                            nuget_lic = extract_license_from_nuget_meta(meta)
                            if nuget_lic and str(nuget_lic).strip().lower() not in _bad_vals:
                                p["license"] = nuget_lic
                                p["component_license"] = nuget_lic
                                needs_license = False
                        if needs_homepage:
                            nuget_hp = meta.get("projectUrl") or ""
                            if nuget_hp:
                                p["homepage"] = nuget_hp
                                needs_homepage = False
                        if needs_release_date:
                            nuget_date = extract_release_date_from_nuget(meta)
                            if nuget_date:
                                p["release_date"] = nuget_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] NuGet fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("ruby", "gem", "rubygems", "bundler"):
                try:
                    from sbom.src.clients.rubygems_client import fetch_rubygems_meta, extract_license_from_rubygems_meta, extract_release_date_from_rubygems
                    meta = fetch_rubygems_meta(pkg_name, pkg_version)
                    if meta:
                        if needs_license:
                            ruby_lic = extract_license_from_rubygems_meta(meta)
                            if ruby_lic and str(ruby_lic).strip().lower() not in _bad_vals:
                                p["license"] = ruby_lic
                                p["component_license"] = ruby_lic
                                needs_license = False
                        if needs_homepage:
                            ruby_hp = meta.get("homepage_uri") or meta.get("project_uri") or ""
                            if ruby_hp:
                                p["homepage"] = ruby_hp
                                needs_homepage = False
                        if needs_release_date:
                            ruby_date = extract_release_date_from_rubygems(meta)
                            if ruby_date:
                                p["release_date"] = ruby_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] RubyGems fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("php", "composer", "packagist"):
                try:
                    from sbom.src.clients.packagist_client import fetch_packagist_meta, extract_license_from_packagist_meta, extract_release_date_from_packagist
                    meta = fetch_packagist_meta(pkg_name, pkg_version)
                    if meta:
                        if needs_license:
                            php_lic = extract_license_from_packagist_meta(meta)
                            if php_lic and str(php_lic).strip().lower() not in _bad_vals:
                                p["license"] = php_lic
                                p["component_license"] = php_lic
                                needs_license = False
                        if needs_homepage:
                            php_hp = meta.get("homepage") or ""
                            if php_hp:
                                p["homepage"] = php_hp
                                needs_homepage = False
                        if needs_release_date:
                            php_date = extract_release_date_from_packagist(meta)
                            if php_date:
                                p["release_date"] = php_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] Packagist fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("go", "golang"):
                try:
                    from sbom.src.clients.go_client import fetch_go_meta
                    meta = fetch_go_meta(pkg_name, pkg_version)
                    if meta:
                        if needs_homepage:
                            go_hp = meta.get("homepage") or f"https://pkg.go.dev/{pkg_name}"
                            if go_hp:
                                p["homepage"] = go_hp
                                needs_homepage = False
                        if needs_release_date:
                            go_date = meta.get("release_date") or meta.get("Time") or meta.get("time") or ""
                            if go_date:
                                p["release_date"] = go_date
                                needs_release_date = False
                        # Go licenses mostly come from deps.dev; go proxy doesn't expose them
                except Exception as e:
                    logger.debug(f"[FALLBACK] Go proxy fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("java", "maven", "gradle"):
                try:
                    from sbom.src.clients.maven_client import fetch_maven_meta, extract_license_from_maven_meta, extract_release_date_from_maven
                    group_id = p.get("groupId") or p.get("group_id") or ""
                    artifact_id = p.get("artifactId") or p.get("artifact_id") or ""
                    if not group_id and ":" in (pkg_name or ""):
                        parts = pkg_name.split(":")
                        group_id = parts[0]
                        artifact_id = parts[1] if len(parts) > 1 else ""
                    elif not artifact_id and ":" in (pkg_name or ""):
                        parts = pkg_name.split(":")
                        artifact_id = parts[1] if len(parts) > 1 else pkg_name
                    elif not artifact_id:
                        artifact_id = pkg_name
                    meta = fetch_maven_meta(group_id, artifact_id, pkg_version)
                    if meta:
                        if needs_license:
                            mvn_lic = extract_license_from_maven_meta(meta)
                            if mvn_lic and str(mvn_lic).strip().lower() not in _bad_vals:
                                p["license"] = mvn_lic
                                p["component_license"] = mvn_lic
                                needs_license = False
                        if needs_homepage:
                            mvn_hp = meta.get("url") or meta.get("projectUrl") or meta.get("homepage") or ""
                            if mvn_hp:
                                p["homepage"] = mvn_hp
                                needs_homepage = False
                        if needs_release_date:
                            mvn_date = extract_release_date_from_maven(meta)
                            if mvn_date:
                                p["release_date"] = mvn_date
                                needs_release_date = False
                        # Description from POM
                        _BAD_DESC = {"", "N/A", "No description available", "No description available."}
                        cur_desc = (p.get("component_description") or p.get("description") or "").strip()
                        if not cur_desc or cur_desc in _BAD_DESC:
                            mvn_desc = (meta.get("description") or "").strip()
                            if mvn_desc:
                                p["component_description"] = mvn_desc
                                p["description"] = mvn_desc
                        # Supplier from POM developers/organization
                        _BAD_SUPPLIER = {"", "N/A", "Unknown", "unknown"}
                        cur_sup = (p.get("component_supplier") or p.get("supplier") or "").strip()
                        if not cur_sup or cur_sup in _BAD_SUPPLIER:
                            devs = meta.get("developers") or []
                            mvn_sup = devs[0] if isinstance(devs, list) and devs else (
                                meta.get("developer") or meta.get("organization") or ""
                            )
                            if mvn_sup:
                                p["supplier"] = mvn_sup
                                p["component_supplier"] = mvn_sup
                        # Hashes from Maven Central JAR
                        if not p.get("hashes"):
                            mvn_hashes = meta.get("hashes") or []
                            if mvn_hashes:
                                p["hashes"] = mvn_hashes
                except Exception as e:
                    logger.debug(f"[FALLBACK] Maven fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("rust", "cargo", "crate", "crates"):
                try:
                    from sbom.src.clients.cargo_client import fetch_cargo_meta, extract_license_from_cargo_meta, extract_release_date_from_cargo
                    meta = fetch_cargo_meta(pkg_name, pkg_version)
                    if meta:
                        if needs_license:
                            cargo_lic = extract_license_from_cargo_meta(meta)
                            if cargo_lic and str(cargo_lic).strip().lower() not in _bad_vals:
                                p["license"] = cargo_lic
                                p["component_license"] = cargo_lic
                                needs_license = False
                        if needs_homepage:
                            crate_info = meta.get("crate", {})
                            cargo_hp = crate_info.get("homepage") or crate_info.get("repository") or ""
                            if cargo_hp:
                                p["homepage"] = cargo_hp
                                needs_homepage = False
                        if needs_release_date:
                            cargo_date = extract_release_date_from_cargo(meta)
                            if cargo_date:
                                p["release_date"] = cargo_date
                                needs_release_date = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] crates.io fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("swift", "cocoapods", "pods"):
                try:
                    import requests as _req
                    from sbom.src.config.config import COCOAPODS_API, API_TIMEOUT
                    url = f"{COCOAPODS_API}/pods/{pkg_name}"
                    resp = _req.get(url, timeout=API_TIMEOUT)
                    if resp.status_code == 200:
                        pod_data = resp.json()
                        if needs_license:
                            pod_lic = pod_data.get("license", {})
                            if isinstance(pod_lic, dict):
                                pod_lic = pod_lic.get("type", "")
                            if pod_lic and str(pod_lic).strip().lower() not in _bad_vals:
                                p["license"] = str(pod_lic)
                                p["component_license"] = str(pod_lic)
                                needs_license = False
                        if needs_homepage:
                            pod_hp = pod_data.get("homepage") or ""
                            if pod_hp:
                                p["homepage"] = pod_hp
                                needs_homepage = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] CocoaPods fallback failed for {pkg_name}: {e}")

            elif pkg_lang in ("conda", "anaconda"):
                try:
                    from sbom.src.clients.anaconda_client import AnacondaClient
                    conda_client = AnacondaClient()
                    channel = p.get("channel", "conda-forge")
                    meta = conda_client.get_package_info(pkg_name, channel)
                    if meta:
                        if needs_license:
                            conda_lic = meta.get("license") or ""
                            if conda_lic and str(conda_lic).strip().lower() not in _bad_vals:
                                p["license"] = conda_lic
                                p["component_license"] = conda_lic
                                needs_license = False
                        if needs_homepage:
                            conda_hp = meta.get("home") or meta.get("dev_url") or ""
                            if conda_hp:
                                p["homepage"] = conda_hp
                                needs_homepage = False
                except Exception as e:
                    logger.debug(f"[FALLBACK] Conda fallback failed for {pkg_name}: {e}")
    
    await update_session(session_token, packages=packages)
    
    from sbom.src.config import config
    supplier_map = {}
    for p in packages:
        pkg_name = p.get("name", "").lower()
        pkg_supplier = p.get("supplier") or p.get("component_supplier") or p.get("name")
        pkg_version = p.get("version", "")
        pkg_lang = (p.get("language") or "").lower()
        ecosystem = get_purl_type(pkg_lang) if pkg_lang else "pypi"
        cert_in_purl = config.generate_cert_in_identifier(ecosystem, p.get("name"), pkg_version, pkg_supplier)
        supplier_map[f"{pkg_name}@{pkg_version}".lower()] = cert_in_purl
        supplier_map[pkg_name] = {"supplier": pkg_supplier, "ecosystem": ecosystem}
    
    for p in packages:
        comp_deps = p.get("component_dependencies", [])
        if comp_deps:
            updated_deps = []
            for dep in comp_deps:
                dep_lower = dep.lower()
                if dep_lower in supplier_map:
                    updated_deps.append(supplier_map[dep_lower])
                else:
                    updated_deps.append(dep)
            p["component_dependencies"] = updated_deps
    
    source_counts = orchestrator.count_by_metadata_source(packages)
    stats = orchestrator.calculate_statistics(packages)
    
    all_packages = []
    for p in packages:
        is_direct = p.get("is_direct_dependency", True)
        comp_deps = p.get("component_dependencies", [])
        license_val = p.get("license") or p.get("component_license") or "NOASSERTION"
        
        all_packages.append({
            "component_name": p.get("name"),
            "version": p.get("version"),
            "is_direct_dependency": is_direct,
            "dependency_type": "direct" if is_direct else "transitive",
            "version_resolved": p.get("version_resolved", is_direct),
            "version_source": p.get("version_source", "manifest" if is_direct else "unknown"),
            "component_license": license_val,
            "homepage": p.get("homepage") or "N/A",
            "release_date": p.get("release_date") or "N/A",
            "component_dependencies": comp_deps
        })

    await mark_step_complete(session_token, "fetch_depsdev")
    
    logger.info(f"[SBOM] fetch-depsdev: +{len(transitive_packages)} transitive deps, total={len(packages)} packages ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "deps.dev metadata and transitive dependencies fetched",
        "scan_id": session.scan_id,
        "direct_dependencies": stats["scan_summary"]["direct_dependencies"],
        "transitive_dependencies_added": len(transitive_packages),
        "total_packages": stats["scan_summary"]["total_components"],
        "successfully_enriched": source_counts["depsdev"],
        "not_found_in_depsdev": source_counts["fallback"],
        "fields_added": ["component_license", "homepage", "release_date", "component_dependencies"],
        "packages": all_packages,
        "next_step": "GET /sbom/registry_enrich"
    }


@app.get("/sbom/registry-enrich")
async def sbom_registry_enrich(
    session: SessionData = Depends(require_step("registry-enrich")),
    session_token: str = Header(...)
):
    """
    Step 4: Enrich packages with registry data (PyPI/npm APIs).
    
    **Requires:** /sbom/fetch_depsdev to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] registry-enrich: Enriching packages with registry data")
    _t0 = _time.monotonic()
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] registry-enrich: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /sbom/discover_and_parse first."
        })
    
    lock_file_ecosystems = set(session.extra.get("lock_file_ecosystems") or [])
    if lock_file_ecosystems:
        _BAD_STR = {"", "No description available", "N/A", "No description available."}
        _BAD_SUP = {"", "Unknown", "N/A", "unknown"}
        _skip_count = sum(
            1 for p in packages
            if (
                p.get("version_source") == "lock_file"
                and (p.get("description") or "").strip() not in _BAD_STR
                and (p.get("supplier") or "").strip() not in _BAD_SUP
                and bool(p.get("hashes"))
            )
        )
        if _skip_count:
            logger.info(
                f"[SBOM] registry-enrich: {_skip_count}/{len(packages)} packages already have "
                f"full metadata from lock-file catalogers (ecosystems: {lock_file_ecosystems}) — "
                "live registry API calls will be skipped for those packages"
            )

    packages = orchestrator.registry_enrich(packages)
    await update_session(session_token, packages=packages)
    
    registry_counts = orchestrator.count_by_registry(packages)
    stats = orchestrator.calculate_statistics(packages)
    
    all_packages = []
    _REGISTRY_MAP = {
        "python": "PyPI", "pip": "PyPI", "pypi": "PyPI",
        "javascript": "npm", "npm": "npm", "node": "npm", "js": "npm", "typescript": "npm", "ts": "npm",
        "dotnet": "NuGet", ".net": "NuGet", "csharp": "NuGet", "c#": "NuGet", "nuget": "NuGet", "fsharp": "NuGet",
        "ruby": "RubyGems", "gem": "RubyGems", "bundler": "RubyGems",
        "java": "Maven", "maven": "Maven", "gradle": "Maven",
        "go": "Go", "golang": "Go",
        "rust": "crates.io", "cargo": "crates.io",
        "php": "Packagist", "composer": "Packagist",
        "swift": "CocoaPods", "cocoapods": "CocoaPods",
        "conda": "Anaconda", "anaconda": "Anaconda",
        "cpp": "Conan/vcpkg", "c": "Conan/vcpkg", "c++": "Conan/vcpkg", "cc": "Conan/vcpkg",
        "conan": "Conan/vcpkg", "vcpkg": "Conan/vcpkg", "cmake": "Conan/vcpkg",
    }
    for p in packages:
        lang = (p.get("language") or "").lower()
        registry = _REGISTRY_MAP.get(lang, "unknown")
        is_direct = p.get("is_direct_dependency", True)
        
        hashes_list = []
        hashes = p.get("hashes", {})
        if isinstance(hashes, dict):
            for alg, content in hashes.items():
                hashes_list.append({"alg": alg, "content": content})
        elif isinstance(hashes, list):
            hashes_list = hashes
        
        all_packages.append({
            "component_name": p.get("name"),
            "version": p.get("version"),
            "is_direct_dependency": is_direct,
            "registry": registry,
            "component_description": p.get("component_description") or p.get("description") or "N/A",
            "component_supplier": p.get("component_supplier") or p.get("supplier") or "N/A",
            "hashes": hashes_list,
            "unique_identifier": p.get("unique_identifier") or "N/A",
            "eol_status": p.get("eol_status", "unknown"),
            "is_deprecated": p.get("is_deprecated", False),
            "version_resolved": p.get("version_resolved", False),
            "version_source": p.get("version_source", "unknown"),
            "release_date": p.get("release_date") or p.get("component_release_date") or "N/A",
        })
    
    await mark_step_complete(session_token, "registry_enrich")
    
    _rc = registry_counts
    _parts = [f"{_rc['pypi']} PyPI", f"{_rc['npm']} npm", f"{_rc['nuget']} NuGet", f"{_rc['rubygems']} RubyGems",
              f"{_rc['maven']} Maven", f"{_rc['go']} Go", f"{_rc['cargo']} Cargo", f"{_rc['packagist']} Packagist",
              f"{_rc.get('conan', 0)} Conan/vcpkg"]
    _summary = ", ".join(p for p in _parts if not p.startswith("0 "))
    logger.info(f"[SBOM] registry-enrich: {stats['scan_summary']['total_components']} packages ({_summary}) ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "Registry enrichment complete (includes EOL/deprecation check)",
        "scan_id": session.scan_id,
        "total_packages": stats["scan_summary"]["total_components"],
        "pypi_packages": registry_counts["pypi"],
        "npm_packages": registry_counts["npm"],
        "nuget_packages": registry_counts["nuget"],
        "rubygems_packages": registry_counts["rubygems"],
        "maven_packages": registry_counts["maven"],
        "go_packages": registry_counts["go"],
        "cargo_packages": registry_counts["cargo"],
        "packagist_packages": registry_counts["packagist"],
        "conan_packages": registry_counts.get("conan", 0),
        "deprecated_packages": stats["scan_summary"]["deprecated_packages"],
        "fields_added": ["component_description", "component_supplier", "hashes", "unique_identifier", "eol_status", "is_deprecated"],
        "packages": all_packages,
        "next_step": "GET /sbom/fetch_osv"
    }


@app.get("/sbom/fetch-osv")
async def sbom_fetch_osv(
    session: SessionData = Depends(require_step("fetch-osv")),
    session_token: str = Header(...)
):
    """
    Step 5: Fetch vulnerabilities from OSV database.
    
    **Requires:** /sbom/registry_enrich to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] fetch-osv: Fetching vulnerabilities from OSV database")
    _t0 = _time.monotonic()
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] fetch-osv: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    packages, vuln_count = orchestrator.fetch_vulnerabilities(packages)
    await update_session(session_token, packages=packages)
    
    stats = orchestrator.calculate_statistics(packages)
    vulnerable_packages = orchestrator.format_vulnerable_packages(packages)
    
    await mark_step_complete(session_token, "fetch_osv")
    
    logger.info(f"[SBOM] fetch-osv: {stats['vulnerability_summary']['total']} vulnerabilities, {stats['vulnerability_summary']['packages_affected']} packages affected ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "Vulnerability scan complete",
        "scan_id": session.scan_id,
        "packages_scanned": stats["scan_summary"]["total_components"],
        "packages_affected": stats["vulnerability_summary"]["packages_affected"],
        "vulnerabilities_found": stats["vulnerability_summary"]["total"],
        "severity_breakdown": stats["vulnerability_summary"]["by_severity"],
        "patchable": stats["vulnerability_summary"]["patchable"],
        "unpatchable": stats["vulnerability_summary"]["unpatchable"],
        "fields_fetched": ["id", "severity", "severity_level", "cvss_score", "summary", "fixed_in", "url", "aliases", "details"],
        "fields_derived": ["patch_status", "criticality"],
        "vulnerable_packages": vulnerable_packages,
        "next_step": "GET /sbom/generate_sbom"
    }


# =============================================================================
# SBOM STEP 1b: DETECT UNUSED DEPENDENCIES (Optional, after discover_and_parse)
# =============================================================================

@app.get("/sbom/detect-unused")
async def sbom_detect_unused(
    session: SessionData = Depends(require_step("detect-unused")),
    session_token: str = Header(...)
):
    """
    Step 1b (Optional): Detect unused dependencies by comparing manifest packages
    against actual code imports.
    
    Uses Semgrep to scan code for import statements, then compares against
    packages discovered from manifest files. Tags each package as used or unused
    and collects evidence (file path, line number, import statement) for each usage.
    
    **Requires:** /sbom/discover-and-parse to be called first.
    
    **Headers:** `session-token: <token from /sbom/set-repository>`
    
    **Returns:** Used/unused library breakdown with per-import evidence details.
    """
    logger.info("[SBOM] detect-unused: Scanning code imports and comparing with manifest packages")
    _t0 = _time.monotonic()
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] detect-unused: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /sbom/discover_and_parse first."
        })
    
    # Get workspace path
    workspace = Path(get_source_path_aibom(session))
    if not workspace.exists():
        logger.error(f"[SBOM] detect-unused: Source not found at {workspace}")
        raise HTTPException(status_code=404, detail={
            "error": "SOURCE_NOT_FOUND",
            "message": "Validated source no longer exists. Please validate again."
        })
    
    # ----------------------------------------------------------------
    # 1. Determine which languages are present (from package data)
    # ----------------------------------------------------------------
    raw_languages = set()
    for p in packages:
        lang = (p.get("language") or "").lower()
        mapped = SBOM_LANG_TO_RESOLVER.get(lang)
        if mapped:
            raw_languages.add(mapped)
    
    # Only keep languages that semgrep can scan
    languages = raw_languages & SEMGREP_SUPPORTED_LANGS
    if not languages:
        logger.info("[SBOM] detect-unused: No scannable languages detected — skipping import scan")
        await mark_step_complete(session_token, "detect_unused")
        return {
            "message": "No scannable languages detected — skipping unused detection",
            "scan_id": session.scan_id,
            "languages_scanned": [],
            "total_direct_packages": 0,
            "used_count": 0,
            "unused_count": 0,
            "used_libraries": [],
            "unused_libraries": [],
            "next_step": "GET /sbom/fetch_depsdev"
        }
    
    logger.info(f"[SBOM] detect-unused: Languages to scan: {sorted(languages)}")
    
    # ----------------------------------------------------------------
    # 2. Run Semgrep import scan (reuse AIBOM results if available)
    # ----------------------------------------------------------------
    aibom_scan = session.extra.get("semgrep_scan_results")
    if aibom_scan:
        logger.info("[SBOM] detect-unused: Reusing AIBOM semgrep scan results from session")
        scan_results = aibom_scan
        scan_summary = {
            "total_third_party": sum(
                len(scan_results.get(lang, {}).get("third_party", []))
                for lang in languages
            ),
            "total_builtin": sum(
                len(scan_results.get(lang, {}).get("builtin", []))
                for lang in languages
            ),
            "total_relative": sum(
                len(scan_results.get(lang, {}).get("relative", []))
                for lang in languages
            ),
        }
    else:
        try:
            semgrep_result = scan_and_dedupe(str(workspace), languages)
            scan_results = semgrep_result.get("scan_results", {})
            scan_summary = semgrep_result.get("summary", {})
            logger.info(
                f"[SBOM] detect-unused: Semgrep scan complete — "
                f"{scan_summary.get('total_third_party', 0)} third-party imports found"
            )
        except FileNotFoundError:
            logger.warning("[SBOM] detect-unused: Semgrep not installed — skipping import scan")
            await mark_step_complete(session_token, "detect_unused")
            return {
                "message": "Semgrep not installed — cannot detect unused dependencies",
                "scan_id": session.scan_id,
                "languages_scanned": sorted(languages),
                "total_direct_packages": 0,
                "used_count": 0,
                "unused_count": 0,
                "used_libraries": [],
                "unused_libraries": [],
                "skipped_reason": "semgrep_not_installed",
                "next_step": "GET /sbom/fetch_depsdev"
            }
    
    # Filter local/internal imports (same as AIBOM filtered-imports does)
    code_tokens_set = session.extra.get("code_tokens_set")
    if code_tokens_set is None:
        code_tokens_set = set(session.extra.get("code_tokens", []))
    if code_tokens_set:
        scan_results = filter_local_imports(scan_results, code_tokens_set)
    
    # ----------------------------------------------------------------
    # 3. Build manifest_packages dict from SBOM packages
    #    Only direct dependencies — transitive deps should NOT be
    #    flagged as "unused" (they're pulled in by used packages)
    # ----------------------------------------------------------------
    manifest_packages = {lang: [] for lang in languages}
    for p in packages:
        # Skip transitive dependencies
        if not p.get("is_direct_dependency", True):
            continue
        pkg_name = p.get("name", "")
        if not pkg_name:
            continue
        lang = (p.get("language") or "").lower()
        mapped = SBOM_LANG_TO_RESOLVER.get(lang)
        if mapped and mapped in languages:
            manifest_packages[mapped].append(pkg_name)
    
    # ----------------------------------------------------------------
    # 4. Build semgrep_imports dict (same format as AIBOM's resolver)
    # ----------------------------------------------------------------
    semgrep_imports = {
        "python_imports": [],
        "javascript_imports": [],
        "go_imports": [],
        "dotnet_imports": [],
        "java_imports": [],
    }
    
    # Also build a rich evidence_map:  package_name_lower -> [evidence_entries]
    # Each evidence entry carries file, line, module, imported_item, import_type
    evidence_map: dict = {}      # {pkg_lower: [{file, line, module, imported_item, import_type, language}]}
    
    for lang in languages:
        key = f"{lang}_imports"
        if lang in scan_results:
            for imp in scan_results[lang].get("third_party", []):
                pkg_name = imp.get("base_package") or imp.get("import_name") or imp.get("module", "")
                src_file = imp.get("file", "")
                
                # Feed resolve_and_compare (needs package + source_files)
                semgrep_imports[key].append({
                    "package": pkg_name,
                    "source_files": [src_file]
                })
                
                # Collect rich evidence per package
                pkg_lower = pkg_name.lower()
                evidence_map.setdefault(pkg_lower, []).append({
                    "file": src_file,
                    "line": imp.get("line"),
                    "module": imp.get("module", ""),
                    "imported_item": imp.get("imported_item"),
                    "import_type": imp.get("import_type", ""),
                    "language": lang,
                })
    
    # Deduplicate evidence entries (same file+line = same import)
    for pkg_lower in evidence_map:
        seen = set()
        deduped = []
        for ev in evidence_map[pkg_lower]:
            key_tuple = (ev["file"], ev["line"], ev.get("imported_item"))
            if key_tuple not in seen:
                seen.add(key_tuple)
                deduped.append(ev)
        evidence_map[pkg_lower] = deduped
    
    # ----------------------------------------------------------------
    # 5. Call resolve_and_compare (reuses AIBOM's full logic)
    # ----------------------------------------------------------------
    resolve_result = resolve_and_compare(
        manifest_packages=manifest_packages,
        semgrep_imports=semgrep_imports,
        languages=sorted(languages)
    )
    
    used_libraries = resolve_result.get("used_libraries", {})
    unused_libraries = resolve_result.get("unused_libraries", {})
    resolution_summary = resolve_result.get("resolution_summary", {})
    
    # ----------------------------------------------------------------
    # 5b. Detect undeclared imports (imported in code but NOT in manifest)
    #     Filters: stdlib, transitive deps, installed-package internals
    # ----------------------------------------------------------------
    from sbom.src.report.remediation_reporter import PYTHON_STDLIB, NODEJS_BUILTINS

    # Supplement stdlib sets with commonly missing modules
    _py_stdlib = PYTHON_STDLIB | {
        "zlib", "netrc", "struct", "mmap", "resource", "syslog",
        "xmlrpc", "html", "mailbox", "mimetypes", "bdb", "pdb",
        "profile", "cProfile", "timeit", "trace", "ensurepip",
        "venv", "lib2to3", "distutils", "idlelib", "tkinter",
        "turtle", "turtledemo", "test", "dbm", "lzma", "bz2",
        "readline", "rlcompleter", "site", "sysconfig", "zipimport",
        "compileall", "py_compile", "symtable", "tabnanny",
        "formatter", "imaplib", "nntplib", "poplib", "telnetlib",
        "cgi", "cgitb", "chunk", "crypt", "imghdr", "sndhdr",
        "sunau", "uu", "xdrlib", "aifc", "audioop", "ossaudiodev",
        "spwd", "nis",
    }

    manifest_names_lower = set()
    for lang_pkgs in manifest_packages.values():
        for pkg in lang_pkgs:
            manifest_names_lower.add(pkg.lower())
            manifest_names_lower.add(pkg.lower().replace("-", "_"))
            manifest_names_lower.add(pkg.lower().replace("_", "-"))

    # ALL package names (direct + transitive) to filter
    all_pkg_names = set()
    for p in packages:
        name = (p.get("name") or "").lower()
        if name:
            all_pkg_names.add(name)
            all_pkg_names.add(name.replace("-", "_"))
            all_pkg_names.add(name.replace("_", "-"))

    # Known package top-level dirs — imports from inside these dirs are internal
    _known_pkg_dirs = set(all_pkg_names) | manifest_names_lower

    undeclared_imports = []  # [{package, language, files}]
    _seen_undeclared = set()
    for lang in languages:
        if lang not in scan_results:
            continue
        _lang_stdlib = _py_stdlib if lang == "python" else (NODEJS_BUILTINS if lang == "javascript" else set())

        for imp in scan_results[lang].get("third_party", []):
            imp_pkg = (imp.get("base_package") or imp.get("import_name") or imp.get("module", "")).lower()
            if not imp_pkg:
                continue

            # Filter 1: stdlib modules
            if imp_pkg in _lang_stdlib:
                continue

            # Filter 2: private/internal Python modules (e.g. _typeshed, __pycache__)
            if lang == "python" and imp_pkg.startswith("_"):
                continue

            # Filter 3: already in manifest (direct deps)
            normalised = imp_pkg.replace("-", "_")
            if imp_pkg in manifest_names_lower or normalised in manifest_names_lower:
                continue

            # Filter 4: already in packages list (transitive deps)
            if imp_pkg in all_pkg_names or normalised in all_pkg_names:
                continue

            # Filter 5: import comes from inside an installed package directory
            # e.g. httpx/_api.py → top_dir="httpx" → skip (httpx's internal imports)
            src_file = imp.get("file", "")
            if "/" in src_file or "\\" in src_file:
                top_dir = src_file.replace("\\", "/").split("/")[0].lower().replace("-", "_")
                if top_dir in _known_pkg_dirs:
                    continue

            if (imp_pkg, lang) in _seen_undeclared:
                continue
            _seen_undeclared.add((imp_pkg, lang))
            # Gather evidence files
            ev = evidence_map.get(imp_pkg, [])
            files = sorted({e["file"] for e in ev if e.get("file")})[:5]
            undeclared_imports.append({
                "package": imp_pkg,
                "language": lang,
                "imported_in_files": files,
                "remediation": f"Add '{imp_pkg}' to your manifest/requirements file — it is imported in code but not declared as a dependency."
            })

    resolution_summary["total_undeclared"] = len(undeclared_imports)
    
    # ----------------------------------------------------------------
    # 6. Tag packages with is_used_in_code + import_evidence
    # ----------------------------------------------------------------
    # Build a fast lookup: (name_lower, language) -> is_used
    resolved_lookup = {}
    for entry in resolve_result.get("resolved_packages", []):
        pkg_name = entry.get("package", "").lower()
        pkg_lang = entry.get("language", "").lower()
        resolved_lookup[(pkg_name, pkg_lang)] = entry.get("is_used", True)
    
    tagged_count = 0
    for p in packages:
        pkg_name = (p.get("name") or "").lower()
        pkg_lang = (p.get("language") or "").lower()
        mapped_lang = SBOM_LANG_TO_RESOLVER.get(pkg_lang, pkg_lang)
        
        if not p.get("is_direct_dependency", True):
            p["is_used_in_code"] = "transitive"
            p["import_evidence"] = []
            continue
        
        if mapped_lang not in languages:
            p["is_used_in_code"] = "not_scanned"
            p["import_evidence"] = []
            continue
        
        is_used = resolved_lookup.get((pkg_name, mapped_lang))
        if is_used is None:
            is_used = resolved_lookup.get((pkg_name.replace("-", "_"), mapped_lang))
        
        p["is_used_in_code"] = "yes" if is_used else "no"
        
        # Classify unused packages (dev_tool / runtime_optional / truly_unused)
        if not is_used:
            pkg_scope = (p.get("scope") or "required").lower()
            p["unused_classification"] = classify_unused_package(pkg_name, pkg_scope)
        else:
            p["unused_classification"] = None
        
        # Attach evidence: all import locations for this package
        # Try exact match first, then dash/underscore normalised match
        pkg_evidence = evidence_map.get(pkg_name, [])
        if not pkg_evidence:
            pkg_evidence = evidence_map.get(pkg_name.replace("-", "_"), [])
        if not pkg_evidence:
            pkg_evidence = evidence_map.get(pkg_name.replace("_", "-"), [])
        p["import_evidence"] = pkg_evidence
        tagged_count += 1
    
    # Build list-of-objects for API response shape (skip empty languages)
    used_libraries_list = []
    for lang, libs in used_libraries.items():
        if not libs:
            continue
        enriched_libs = []
        for lib in libs:
            pkg_name = (lib.get("package") or "").lower()
            lib_entry = dict(lib)
            # Evidence lookup: try package name, then dash/underscore variants,
            # then each resolved import name (e.g. flask-cors → flask_cors)
            ev = evidence_map.get(pkg_name, [])
            if not ev:
                ev = evidence_map.get(pkg_name.replace("-", "_"), [])
            if not ev:
                ev = evidence_map.get(pkg_name.replace("_", "-"), [])
            if not ev:
                for imp_name in lib.get("import_names", []):
                    ev = evidence_map.get(imp_name.lower(), [])
                    if ev:
                        break
            lib_entry["import_evidence"] = ev
            enriched_libs.append(lib_entry)
        used_libraries_list.append({
            "language": lang,
            "libraries": enriched_libs
        })

    # Build scope lookup from original packages for classification
    # (name_lower, mapped_lang) -> scope string from cataloger
    _scope_lookup: dict[tuple[str, str], str] = {}
    for p in packages:
        pn = (p.get("name") or "").lower()
        pl = SBOM_LANG_TO_RESOLVER.get((p.get("language") or "").lower(), "")
        _scope_lookup[(pn, pl)] = (p.get("scope") or "required").lower()

    unused_libraries_list = []
    for lang, libs in unused_libraries.items():
        if not libs:
            continue
        enriched_libs = []
        for lib in libs:
            pkg_name = (lib.get("package") or "").lower()
            lib_entry = dict(lib)
            # Evidence lookup with normalization (same as used_libraries)
            ev = evidence_map.get(pkg_name, [])
            if not ev:
                ev = evidence_map.get(pkg_name.replace("-", "_"), [])
            if not ev:
                ev = evidence_map.get(pkg_name.replace("_", "-"), [])
            if not ev:
                for imp_name in lib.get("import_names", []):
                    ev = evidence_map.get(imp_name.lower(), [])
                    if ev:
                        break
            lib_entry["import_evidence"] = ev
            # Classify why this package appears unused
            scope = _scope_lookup.get((pkg_name, lang))
            lib_entry["classification"] = classify_unused_package(pkg_name, scope)
            enriched_libs.append(lib_entry)
        unused_libraries_list.append({
            "language": lang,
            "libraries": enriched_libs
        })

    # ----------------------------------------------------------------
    # 7. Persist results in session (with evidence_map for generate-sbom)
    # ----------------------------------------------------------------
    await update_session(
        session_token,
        packages=packages,
        unused_detection={
            "used_libraries": used_libraries_list,
            "unused_libraries": unused_libraries_list,
            "undeclared_imports": undeclared_imports,
            "resolution_summary": resolution_summary,
            "evidence_map": evidence_map,
            "scan_summary": scan_summary,
        }
    )
    
    await mark_step_complete(session_token, "detect_unused")
    
    # ----------------------------------------------------------------
    # 8. Build response
    # ----------------------------------------------------------------
    total_direct = sum(len(v) for v in manifest_packages.values())
    used_count = resolution_summary.get("total_used", 0)
    unused_count = resolution_summary.get("total_unused", 0)
    
    logger.info(
        f"[SBOM] detect-unused: {used_count} used, {unused_count} unused "
        f"out of {total_direct} direct packages across {sorted(languages)} "
        f"({(_time.monotonic()-_t0)*1000:.0f}ms)"
    )
    
    return {
        "message": "Unused dependency detection complete",
        "scan_id": session.scan_id,
        "languages_scanned": sorted(languages),
        "total_direct_packages": total_direct,
        "used_count": used_count,
        "unused_count": unused_count,
        "undeclared_count": len(undeclared_imports),
        "used_libraries": used_libraries_list,
        "unused_libraries": unused_libraries_list,
        "undeclared_imports": undeclared_imports,
        "resolution_summary": resolution_summary,
        "import_scan_summary": {
            "total_third_party_imports": scan_summary.get("total_third_party", 0),
            "total_builtin_imports": scan_summary.get("total_builtin", 0),
            "total_relative_imports": scan_summary.get("total_relative", 0),
            "files_scanned": scan_summary.get("files_scanned_count", 0),
        },
        "next_step": "GET /sbom/fetch_depsdev"
    }


@app.get("/sbom/generate-sbom")
async def sbom_generate_sbom(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Step 6: Generate all SBOM reports (JSON, SPDX, CycloneDX).
    
    **Requires:** /sbom/fetch-osv to be called first.
    
    **Headers:** `session-token: <token from /sbom/set-repository>`
    """
    logger.info("[SBOM] generate-sbom: Generating all SBOM formats")
    _t0 = _time.monotonic()
    from sbom.src.core.sbom_generator import generate_json_sbom, generate_spdx_sbom, generate_cyclonedx_sbom, generate_remediation_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] generate-sbom: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    catalog = orchestrator.build_catalog(
        packages=packages,
        manifests=manifests,
        project_name=project_name,
        source=project_name,
        scan_id=scan_id
    )
    
    license_detection = session.extra.get("repo_license")
    if license_detection:
        catalog["license_detection"] = license_detection
    
    await update_session(session_token, catalog=catalog)
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    json_sbom = generate_json_sbom(catalog, metadata)
    spdx_sbom = generate_spdx_sbom(catalog, metadata)
    cyclonedx_sbom = generate_cyclonedx_sbom(catalog, metadata)
    remediation_sbom = generate_remediation_sbom(catalog, metadata)
    
    stats = orchestrator.calculate_statistics(packages)
    
    logger.info(f"[SBOM] generate-sbom: Generated all formats for '{project_name}' — {stats['scan_summary']['total_components']} components ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    # Build components preview with vulnerability counts by severity
    components_preview = build_component_preview_with_vulns(packages)

    # Include unused detection results if /sbom/detect-unused was called
    unused_detection = session.extra.get("unused_detection")
    unused_summary = None
    if unused_detection:
        evidence_map = unused_detection.get("evidence_map", {})
        unused_summary = {
            "used_count": unused_detection.get("resolution_summary", {}).get("total_used", 0),
            "unused_count": unused_detection.get("resolution_summary", {}).get("total_unused", 0),
            "used_libraries": unused_detection.get("used_libraries", []),
            "unused_libraries": unused_detection.get("unused_libraries", []),
            "evidence_map": evidence_map,
        }

    response = {
        "message": "SBOM generation complete",
        "scan_id": scan_id,
        "project_name": project_name,
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "components_preview": components_preview,
        "reports": {
            "json": json_sbom,
            "spdx": spdx_sbom,
            "cyclonedx": cyclonedx_sbom,
            "remediation": remediation_sbom
        }
    }
    if unused_summary:
        response["unused_detection"] = unused_summary
    return response


@app.get("/sbom/generate-json")
async def sbom_generate_json_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate JSON SBOM format only.
    
    **Requires:** /sbom/fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] generate-json: Generating JSON SBOM format")
    _t0 = _time.monotonic()
    from sbom.src.core.sbom_generator import generate_json_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] generate-json: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
    
    license_detection = session.extra.get("repo_license")
    if license_detection and "license_detection" not in catalog:
        catalog["license_detection"] = license_detection
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    json_sbom = generate_json_sbom(catalog, metadata)
    stats = orchestrator.calculate_statistics(packages)
    
    # Build components preview with vulnerability counts by severity
    components_preview = build_component_preview_with_vulns(packages)
    
    logger.info(f"[SBOM] generate-json: JSON SBOM generated for scan {scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "JSON SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "components_preview": components_preview,
        "full_report": json_sbom
    }


@app.get("/sbom/generate-spdx")
async def sbom_generate_spdx_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate SPDX SBOM format only.
    
    **Requires:** /sbom/fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] generate-spdx: Generating SPDX SBOM format")
    _t0 = _time.monotonic()
    from sbom.src.core.sbom_generator import generate_spdx_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] generate-spdx: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
    
    license_detection = session.extra.get("repo_license")
    if license_detection and "license_detection" not in catalog:
        catalog["license_detection"] = license_detection
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    spdx_sbom = generate_spdx_sbom(catalog, metadata)
    stats = orchestrator.calculate_statistics(packages)
    
    logger.info(f"[SBOM] generate-spdx: SPDX SBOM generated for scan {scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "SPDX SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "full_report": spdx_sbom
    }


@app.get("/sbom/generate-cyclonedx")
async def sbom_generate_cyclonedx_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate CycloneDX SBOM format only.
    
    **Requires:** /sbom/fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /sbom/set_repository>`
    """
    logger.info("[SBOM] generate-cyclonedx: Generating CycloneDX SBOM format")
    _t0 = _time.monotonic()
    from sbom.src.core.sbom_generator import generate_cyclonedx_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] generate-cyclonedx: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
    
    license_detection = session.extra.get("repo_license")
    if license_detection and "license_detection" not in catalog:
        catalog["license_detection"] = license_detection
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    cyclonedx_sbom = generate_cyclonedx_sbom(catalog, metadata)
    stats = orchestrator.calculate_statistics(packages)
    
    logger.info(f"[SBOM] generate-cyclonedx: CycloneDX SBOM generated for scan {scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
    
    return {
        "message": "CycloneDX SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "full_report": cyclonedx_sbom
    }


@app.get("/sbom/generate-remediation")
async def sbom_generate_remediation_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate remediation report only.
    
    **Requires:** /sbom/fetch-osv to be called first.
    
    **Headers:** `session-token: <token from /sbom/set-repository>`
    """
    logger.info("[SBOM] generate-remediation: Generating remediation report")
    _t0 = _time.monotonic()
    from sbom.src.core.sbom_generator import generate_remediation_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        logger.warning("[SBOM] generate-remediation: No packages found")
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    remediation_sbom = generate_remediation_sbom(catalog, metadata)
    
    # ── Unused / Used dependency summary (brief listing only) ─────────
    # Full evidence and details are available at /sbom/detect-unused.
    unused_detection = session.extra.get("unused_detection")
    if unused_detection:
        # Classify unused libraries with per-type remediation advice
        _CLASSIFICATION_REMEDIATION = {
            "dev_tool": "This is a dev/build/test tool. Move it to dev-dependencies (e.g. [tool.poetry.group.dev] or devDependencies) so it is excluded from production builds.",
            "runtime_optional": "This package is invoked via CLI or loaded as a plugin at runtime. Verify it is still needed; if so, document it as a runtime dependency.",
            "truly_unused": "This dependency is not imported anywhere in code. Remove it from your manifest to reduce attack surface.",
        }
        unused_list = []
        for entry in unused_detection.get("unused_libraries", []):
            lang = entry.get("language")
            for lib in entry.get("libraries", []):
                classification = lib.get("classification", "truly_unused")
                unused_list.append({
                    "package": lib.get("package"),
                    "language": lang,
                    "classification": classification,
                    "remediation": _CLASSIFICATION_REMEDIATION.get(classification, _CLASSIFICATION_REMEDIATION["truly_unused"]),
                })
        used_list = []
        for entry in unused_detection.get("used_libraries", []):
            lang = entry.get("language")
            for lib in entry.get("libraries", []):
                used_list.append({"package": lib.get("package"), "language": lang})

        remediation_sbom["dependency_usage"] = {
            "total_used": unused_detection.get("resolution_summary", {}).get("total_used", 0),
            "total_unused": unused_detection.get("resolution_summary", {}).get("total_unused", 0),
            "total_undeclared": unused_detection.get("resolution_summary", {}).get("total_undeclared", 0),
            "used_libraries": used_list,
            "unused_libraries": unused_list,
            "undeclared_imports": unused_detection.get("undeclared_imports", []),
        }
    
    logger.info(f"[SBOM] generate-remediation: Remediation report generated for scan {scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")

    return {
        "message": "Remediation report generated",
        "scan_id": scan_id,
        "full_report": remediation_sbom,
    }


# =============================================================================
# VEX ENDPOINT
# =============================================================================

@app.get("/sbom/generate-vex")
async def sbom_generate_vex_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...),
    format: str = "openvex",
    download: bool = False,
):
    """
    Generate a VEX (Vulnerability Exploitability eXchange) document.

    **Requires:** /sbom/fetch-osv to be called first.

    **Headers:** `session-token: <token from /sbom/set-repository>`

    **Query params:**
    - `format`: `openvex` (default) or `cyclonedx`
    - `download`: if `true`, returns the document as a downloadable `.vex.json` file
    """
    from sbom.src.core.vex_generator import (
        generate_openvex,
        generate_cyclonedx_vex_statements,
        generate_vex_summary,
    )
    from fastapi.responses import JSONResponse
    import json as _json

    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /sbom/fetch-osv first."
        })

    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])

    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id,
        )

    fmt = (format or "openvex").lower().strip()

    if fmt == "cyclonedx":
        cdx_stmts = generate_cyclonedx_vex_statements(catalog)
        payload = {
            "message": "CycloneDX VEX statements generated",
            "scan_id": scan_id,
            "format": "cyclonedx",
            "total_statements": len(cdx_stmts),
            "vulnerabilities": cdx_stmts,
        }
    else:
        vex_summary = generate_vex_summary(catalog, scan_id)
        payload = {
            "message": "OpenVEX document generated",
            "scan_id": scan_id,
            "format": "openvex",
            **vex_summary,
        }

    if download:
        filename = f"{scan_id}_vex_{fmt}.json"
        content = _json.dumps(payload, indent=2, ensure_ascii=False)
        return JSONResponse(
            content=payload,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return payload


# =============================================================================
# CLOUDWATCH LOG UPLOAD ENDPOINT
# =============================================================================


class CloudWatchUploadRequest(BaseModel):
    """Request model for CloudWatch log upload"""
    scan_id: str
    job_json: dict
    result_json: dict = None


class CloudWatchUploadResponse(BaseModel):
    """Response model for CloudWatch log upload"""
    success: bool
    scan_id: str
    log_file: str = None
    stream_name: str = None
    lines_uploaded: int = 0
    batches_sent: int = 0
    is_failed_job: bool = False
    error: str = None


class CloudWatchLogUploadService:
    """Service class to handle CloudWatch log uploads for PrismAIBOM"""
    
    # Constants
    MAX_BATCH_SIZE = 10000  # CloudWatch max events per batch
    MAX_PAYLOAD_SIZE = 1048576  # CloudWatch max payload size (1MB)
    
    def __init__(self):
        # Load configuration from environment
        self.logs_directory = log_directory
        self.aws_region = AWS.REGION
        self.log_group = AWS.CLOUDWATCH_LOG_GROUP
        
        # Initialize CloudWatch client
        self.cloudwatch_client = self._initialize_cloudwatch_client()
        self._ensure_log_group_exists()
    
    def _initialize_cloudwatch_client(self):
        """Initialize AWS CloudWatch Logs client with credential validation"""
        try:
            # Validate AWS credentials are present
            aws_access_key = AWS.ACCESS_KEY_ID
            aws_secret_key = AWS.SECRET_ACCESS_KEY
            
            if not aws_access_key or not aws_secret_key:
                logger.error("AWS credentials not configured for CloudWatch")
                raise HTTPException(
                    status_code=500, 
                    detail="AWS credentials not configured. Please set AWSACCESSKEYID and AWSSECRETACCESSKEY."
                )
            
            if not self.aws_region:
                logger.error("AWS region not configured for CloudWatch")
                raise HTTPException(
                    status_code=500,
                    detail="AWS region not configured. Please set AWSREGION."
                )
            
            client = boto3.client(
                'logs',
                region_name=self.aws_region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
            
            # Validate credentials by making a lightweight API call
            try:
                client.describe_log_groups(limit=1)
                logger.info("AWS CloudWatch credentials validated successfully")
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch', 'AccessDenied']:
                    logger.error(f"AWS credential validation failed: {error_code}")
                    raise HTTPException(
                        status_code=500,
                        detail="AWS credentials validation failed. Please verify your credentials."
                    )
                # Re-raise other errors (like network issues)
                raise
            
            return client
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to initialize CloudWatch client: {e}")
            raise HTTPException(status_code=500, detail="CloudWatch client initialization failed")
    
    def _ensure_log_group_exists(self):
        """Create CloudWatch log group if it doesn't exist"""
        try:
            self.cloudwatch_client.create_log_group(logGroupName=self.log_group)
            logger.info(f"CloudWatch log group created: {self.log_group}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                logger.error(f"Error creating log group: {e}")
                raise
            logger.debug(f"Log group already exists: {self.log_group}")
    
    def find_log_file(self, scan_id: str) -> str:
        """Find log file for given scan_id"""
        try:
            if not os.path.exists(self.logs_directory):
                logger.warning("Logs directory not found")
                return None
            
            # Look for files starting with scan_id
            for filename in os.listdir(self.logs_directory):
                if filename.startswith(scan_id) and filename.endswith('.log'):
                    log_path = os.path.join(self.logs_directory, filename)
                    if os.path.isfile(log_path):
                        logger.info(f"Log resource located for scan {scan_id}")
                        return log_path
            
            logger.warning(f"No log resource found for scan: {scan_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error finding log resource for scan {scan_id}: {type(e).__name__}")
            return None
    
    def create_log_stream(self, stream_name: str) -> bool:
        """Create CloudWatch log stream"""
        try:
            self.cloudwatch_client.create_log_stream(
                logGroupName=self.log_group,
                logStreamName=stream_name
            )
            logger.info(f"Log stream created: {stream_name}")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                logger.error(f"Error creating log stream {stream_name}: {e}")
                return False
            logger.debug(f"Log stream already exists: {stream_name}")
            return True
    
    def group_log_lines(self, lines: list) -> list:
        """
        Group multi-line log entries (especially errors with stack traces) into single entries.
        Lines without timestamps are considered continuations of the previous log entry.
        """
        if not lines:
            return []
        
        grouped_lines = []
        current_entry = []
        
        # Pattern to detect log lines with timestamps
        import re
        timestamp_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}')
        
        for line in lines:
            if timestamp_pattern.match(line.strip()):
                # Save previous entry if exists
                if current_entry:
                    grouped_lines.append(''.join(current_entry))
                # Start new entry
                current_entry = [line]
            else:
                # Continuation of previous entry
                if current_entry:
                    current_entry.append(line)
                else:
                    # Edge case: file starts without timestamp
                    current_entry = [line]
        
        # Add the last entry
        if current_entry:
            grouped_lines.append(''.join(current_entry))
        
        return grouped_lines
    
    def read_log_file(self, log_path: str) -> list:
        """Read log file and return grouped lines"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                raw_lines = f.readlines()
            return self.group_log_lines(raw_lines)
        except Exception as e:
            logger.error(f"Error reading log resource: {type(e).__name__}")
            return []
    
    def upload_to_cloudwatch(
        self,
        scan_id: str,
        log_path: str,
        job_data: dict,
        result_data: dict = None
    ) -> dict:
        """Upload job JSON, log file, and result JSON to CloudWatch"""
        import time
        
        result = {
            'scan_id': scan_id,
            'log_file': os.path.basename(log_path),
            'success': False,
            'lines_uploaded': 0,
            'batches_sent': 0
        }
        
        try:
            # Check if this is a failed job
            job_status = job_data.get('Status', job_data.get('status', 0))
            if isinstance(job_status, str):
                try:
                    job_status = int(job_status)
                except ValueError:
                    job_status = 0
            
            is_failed = job_status == -5  # STATUS_FAILED
            
            # Use log file name (without extension) as stream name
            log_filename = os.path.basename(log_path)
            stream_name = os.path.splitext(log_filename)[0]
            
            if not self.create_log_stream(stream_name):
                result['error'] = 'Failed to create log stream'
                return result
            
            # Prepare all log events
            all_events = []
            base_timestamp = int(time.time() * 1000)
            event_index = 0
            
            # Add failure indicator at the beginning if job failed
            if is_failed:
                all_events.append({
                    'timestamp': base_timestamp + (event_index * 1000),
                    'message': f"*** FAILED JOB - STATUS: {job_status} ***"
                })
                event_index += 1
            
            # 1. Add Job JSON
            all_events.append({
                'timestamp': base_timestamp + (event_index * 1000),
                'message': f"=== JOB DATA ===\n{json.dumps(job_data, indent=2, ensure_ascii=False)}"
            })
            event_index += 1
            
            # 2. Add log file content
            grouped_lines = self.read_log_file(log_path)
            if grouped_lines:
                all_events.append({
                    'timestamp': base_timestamp + (event_index * 1000),
                    'message': f"\n=== LOG FILE CONTENT: {log_filename} ==="
                })
                event_index += 1
                
                for grouped_line in grouped_lines:
                    if grouped_line.strip():
                        all_events.append({
                            'timestamp': base_timestamp + (event_index * 1000),
                            'message': grouped_line.rstrip('\n')
                        })
                        event_index += 1
                
                logger.info(f"Log content added for {scan_id}: {len(grouped_lines)} entries")
            
            # 3. Add Result JSON if provided
            if result_data:
                all_events.append({
                    'timestamp': base_timestamp + (event_index * 1000),
                    'message': f"\n=== RESULT DATA ===\n{json.dumps(result_data, indent=2, ensure_ascii=False)}"
                })
                event_index += 1
            
            if not all_events:
                result['error'] = 'No content to upload'
                logger.warning(f"No content found for scan: {scan_id}")
                return result
            
            # Batch events respecting CloudWatch limits
            batches = []
            current_batch = []
            current_size = 0
            
            for event in all_events:
                event_size = len(event['message']) + 26
                
                if (len(current_batch) >= self.MAX_BATCH_SIZE or 
                    current_size + event_size > self.MAX_PAYLOAD_SIZE):
                    
                    if current_batch:
                        batches.append(current_batch)
                    current_batch = [event]
                    current_size = event_size
                else:
                    current_batch.append(event)
                    current_size += event_size
            
            if current_batch:
                batches.append(current_batch)
            
            # Upload batches to CloudWatch
            sequence_token = None
            total_events = 0
            
            for batch_num, batch in enumerate(batches, 1):
                try:
                    put_params = {
                        'logGroupName': self.log_group,
                        'logStreamName': stream_name,
                        'logEvents': batch
                    }
                    
                    if sequence_token:
                        put_params['sequenceToken'] = sequence_token
                    
                    response = self.cloudwatch_client.put_log_events(**put_params)
                    sequence_token = response.get('nextSequenceToken')
                    total_events += len(batch)
                    
                    logger.info(f"Batch {batch_num}/{len(batches)} uploaded for {scan_id}: {len(batch)} events")
                    
                except ClientError as e:
                    logger.error(f"Error uploading batch {batch_num} for {scan_id}: {e}")
                    if batch_num == 1:
                        result['error'] = 'Upload failed'
                        return result
            
            result.update({
                'success': True,
                'lines_uploaded': total_events,
                'batches_sent': len(batches),
                'stream_name': stream_name,
                'is_failed_job': is_failed
            })
            
            status_msg = "FAILED" if is_failed else "SUCCESS"
            logger.info(f"{status_msg} job upload completed for {scan_id}: {total_events} events in {len(batches)} batches")
            
        except Exception as e:
            logger.error(f"Error uploading to CloudWatch for {scan_id}: {e}")
            result['error'] = str(e)
        
        return result


# Global service instance
_cw_upload_service = None


def get_cw_upload_service() -> CloudWatchLogUploadService:
    """Get or create the upload service instance"""
    global _cw_upload_service
    if _cw_upload_service is None:
        _cw_upload_service = CloudWatchLogUploadService()
    return _cw_upload_service


@app.post("/cwlogsuploader", response_model=CloudWatchUploadResponse)
async def cwlogsuploader_endpoint(request: CloudWatchUploadRequest):
    """
    POST /cwlogsuploader endpoint handler
    
    Receives job and result JSON data, finds the corresponding log file,
    and uploads all data to AWS CloudWatch Logs.
    
    **Body (JSON):**
    ```json
    {
        "scan_id": "unique-scan-id",
        "job_json": {...},
        "result_json": {...}  // optional
    }
    ```
    
    **Returns:** CloudWatch upload status and details
    """
    logger.info(f"=== /cwlogsuploader endpoint called ===")
    logger.info(f"[CLOUDWATCH] Processing upload for scan_id: {request.scan_id}")
    _t0 = _time.monotonic()
    
    try:
        service = get_cw_upload_service()
        
        # Find log file for the scan_id
        log_path = service.find_log_file(request.scan_id)
        
        if not log_path:
            logger.error(f"Log file not found for scan_id: {request.scan_id}")
            raise HTTPException(
                status_code=404,
                detail=f"Log file not found for scan_id: {request.scan_id}"
            )
        
        # Upload to CloudWatch
        upload_result = service.upload_to_cloudwatch(
            scan_id=request.scan_id,
            log_path=log_path,
            job_data=request.job_json,
            result_data=request.result_json
        )
        
        if not upload_result['success']:
            logger.error(f"CloudWatch upload failed: {upload_result.get('error', 'Unknown error')}")
            raise HTTPException(
                status_code=500,
                detail=f"CloudWatch upload failed: {upload_result.get('error', 'Unknown error')}"
            )
        
        logger.info(f"[CLOUDWATCH] Upload successful for {request.scan_id} ({(_time.monotonic()-_t0)*1000:.0f}ms)")
        logger.info(f"=== /cwlogsuploader completed successfully ===")
        
        # Return success response
        return CloudWatchUploadResponse(
            success=True,
            scan_id=request.scan_id,
            log_file=upload_result['log_file'],
            stream_name=upload_result.get('stream_name'),
            lines_uploaded=upload_result['lines_uploaded'],
            batches_sent=upload_result['batches_sent'],
            is_failed_job=upload_result.get('is_failed_job', False)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in cwlogsuploader endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


# =============================================================================
# S3 RESULT UPLOAD ENDPOINT
# =============================================================================

class S3ResultUploadRequest(BaseModel):
    """Request model for S3 result upload"""
    scan_id: str
    result_data: dict


class S3ResultUploadResponse(BaseModel):
    """Response model for S3 result upload"""
    success: bool
    scan_id: str
    s3_arn: str = None
    s3_bucket_path: str = None
    s3_key: str = None
    timestamp: str = None
    status: int = None
    payload_size_kb: float = None
    error: str = None


def _upload_result_to_s3(scan_id: str, payload: dict) -> str:
    """Upload result payload JSON to S3 and return the S3 key."""
    if not AWS.S3_BUCKET:
        raise ValueError("S3 bucket not configured (AWSS3BUCKET)")

    s3_key = f"results/{scan_id}.json"
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS.ACCESS_KEY_ID,
        aws_secret_access_key=AWS.SECRET_ACCESS_KEY,
        region_name=AWS.REGION
    )
    s3_client.put_object(
        Bucket=AWS.S3_BUCKET,
        Key=s3_key,
        Body=json.dumps(payload).encode('utf-8'),
        ContentType='application/json'
    )
    return s3_key


@app.post("/resulttos3bucket", response_model=S3ResultUploadResponse)
async def result_to_s3bucket_endpoint(request: S3ResultUploadRequest):
    """
    POST /resulttos3bucket endpoint handler

    Receives the full result data (same structure as the PAIBOMR18/PAIBOMR21
    result files), strips the 'history' field, and uploads the payload to S3
    at ``results/{scan_id}.json`` in the canonical result format.

    **Body (JSON):**
    ```json
    {
        "scan_id": "PAIBOMR18",
        "result_data": {
            "scan_id": "PAIBOMR18",
            "applicationId": "...",
            "responses": { ... },
            "status": 32,
            "Scanstarttime": "...",
            "endtime": "...",
            "duration_minutes": 1.32,
            ...
        }
    }
    ```

    **Returns:** S3 upload details including full object ARN, S3 key, scan_id,
    timestamp, status, and payload size.
    """
    logger.info(f"=== /resulttos3bucket endpoint called ===")
    logger.info(f"[S3UPLOAD] Processing result for scan_id: {request.scan_id}")
    _t0 = _time.monotonic()

    try:
        # Strip 'history' field — can be 40+ MB of raw endpoint responses
        # Stored format matches PAIBOMR18.json canonical result structure
        payload = {k: v for k, v in request.result_data.items() if k != 'history'}

        # Embed S3 location fields into the persisted result JSON.
        # These values are part of the uploaded file, not only the API response.
        s3_key = f"results/{request.scan_id}.json"
        s3_bucket_path = f"s3://{AWS.S3_BUCKET}/{s3_key}"
        s3_arn = f"arn:aws:s3:::{AWS.S3_BUCKET}/{s3_key}"
        payload["s3_bucket_path"] = s3_bucket_path
        payload["s3_arn"] = s3_arn

        # Keep S3 location in the canonical `result` object too.
        # Some downstream consumers read only payload["result"].
        result_obj = payload.get("result")
        if not isinstance(result_obj, dict):
            result_obj = {}
            payload["result"] = result_obj
        result_obj["s3_bucket_path"] = s3_bucket_path
        result_obj["s3_arn"] = s3_arn

        payload_size_kb = round(len(json.dumps(payload).encode('utf-8')) / 1024, 1)
        logger.info(f"[S3UPLOAD] Payload size: {payload_size_kb} KB (history excluded)")

        # Upload to S3
        try:
            uploaded_s3_key = _upload_result_to_s3(request.scan_id, payload)
        except ValueError as e:
            logger.error(f"[S3UPLOAD] Configuration error: {e}")
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            logger.error(f"[S3UPLOAD] S3 upload failed for {request.scan_id}: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"S3 upload failed: {str(e)}")

        # Keep return key in sync with actual uploader output.
        s3_key = uploaded_s3_key
        timestamp = datetime.now().isoformat()
        status = request.result_data.get('status')

        elapsed_ms = (_time.monotonic() - _t0) * 1000
        logger.info(f"[S3UPLOAD] ✅ Uploaded successfully in {elapsed_ms:.0f}ms — {s3_arn}")
        logger.info(f"=== /resulttos3bucket completed successfully ===")

        return S3ResultUploadResponse(
            success=True,
            scan_id=request.scan_id,
            s3_arn=s3_arn,
            s3_bucket_path=s3_bucket_path,
            s3_key=s3_key,
            timestamp=timestamp,
            status=status,
            payload_size_kb=payload_size_kb
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in /resulttos3bucket endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# =============================================================================
# RESULT POSTING ENDPOINT (boto3 Lambda invocation)
# =============================================================================

RESULT_POSTING_LAMBDA_ARN = AWS.LAMBDA_RESULT_POSTING_ARN 


class ResultPostingRequest(BaseModel):
    """Request model for result posting Lambda invocation"""
    scanId: str
    s3_bucket_path: str | None = None


class ResultPostingResponse(BaseModel):
    """Response model for result posting Lambda invocation"""
    success: bool
    scanId: str
    status_code: int = None
    payload: dict = None
    error: str = None


@app.post("/resultposting", response_model=ResultPostingResponse)
async def result_posting_endpoint(request: ResultPostingRequest):
    """
    Invoke the AIBOM-ResultPosting Lambda function directly via boto3.

    **Body (JSON):**
    ```json
    {
        "scanId": "PAIBOMR22",
        "s3_bucket_path": "s3://aiprism-discovery/results/PAIBOMR22.json"
    }
    ```

    **Returns:** Lambda invocation result including function response payload.
    """
    logger.info(f"=== /resultposting endpoint called ===")
    logger.info(f"[{request.scanId}] Invoking Lambda: {RESULT_POSTING_LAMBDA_ARN}")
    logger.info(f"[{request.scanId}] s3_bucket_path: {request.s3_bucket_path}")

    try:
        if not RESULT_POSTING_LAMBDA_ARN:
            raise HTTPException(status_code=500, detail="AWSLAMBDARESULTPOSTINGARN is not configured")

        from botocore.config import Config as BotoConfig

        lambda_client = boto3.client(
            'lambda',
            region_name=AWS.REGION or "ap-south-1",
            aws_access_key_id=AWS.ACCESS_KEY_ID,
            aws_secret_access_key=AWS.SECRET_ACCESS_KEY,
            config=BotoConfig(read_timeout=900, connect_timeout=10, retries={'max_attempts': 0}),
        )

        event_payload = {
            "scanId": request.scanId,
            "s3_bucket_path": request.s3_bucket_path,
        }

        response = lambda_client.invoke(
            FunctionName=RESULT_POSTING_LAMBDA_ARN,
            InvocationType="RequestResponse",
            Payload=json.dumps(event_payload).encode("utf-8"),
        )

        status_code = response.get("StatusCode")
        function_error = response.get("FunctionError")

        raw_payload = response["Payload"].read()
        try:
            payload = json.loads(raw_payload)
        except (ValueError, json.JSONDecodeError):
            payload = {"raw": raw_payload.decode("utf-8", errors="replace")}

        if function_error:
            error_msg = payload.get("errorMessage") or str(payload)
            logger.error(f"[{request.scanId}] ❌ Lambda function error ({function_error}): {error_msg}")
            return ResultPostingResponse(
                success=False,
                scanId=request.scanId,
                status_code=status_code,
                payload=payload,
                error=f"Lambda function error ({function_error}): {error_msg}",
            )

        logger.info(f"[{request.scanId}] ✅ Lambda invoked successfully (HTTP {status_code})")
        logger.info(f"=== /resultposting completed successfully ===")

        return ResultPostingResponse(
            success=True,
            scanId=request.scanId,
            status_code=status_code,
            payload=payload,
        )

    except Exception as e:
        logger.error(f"[{request.scanId}] ❌ Lambda invocation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Lambda invocation failed: {str(e)}")


# =============================================================================
# APPLICATION STARTUP
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )