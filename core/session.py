"""
Unified Session Management for PrismAIBOM (Production-Hardened)
================================================================

Security improvements:
- asyncio.Lock for proper async-safe concurrency (FastAPI/uvicorn)
- Idle timeout (SESSION_IDLE_TIMEOUT_MINUTES) in addition to absolute TTL
- Background cleanup task (runs every CLEANUP_INTERVAL_SECONDS)
- LRU eviction at 90% capacity to prevent hard-reject under load
- Capped session.extra keys (MAX_SESSION_EXTRA_KEYS) to prevent memory abuse
- Session rotation support (rotate_session) for fixation prevention
- Sensitive data scrubbing on session destruction
- get_session_stats() replaces get_all_sessions() (no token/data leak)

Performance improvements:
- Background cleanup avoids blocking the request path
- Lazy expiry on each access (no full-scan per request)
- LRU eviction keeps memory bounded
"""

import os
import asyncio
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from fastapi import Header, HTTPException

logger = logging.getLogger("prismaibom.session")

# =============================================================================
# SESSION CONFIGURATION
# =============================================================================

SESSION_TTL_HOURS: int = int(os.getenv("SESSION_TTL_HOURS", "24"))
SESSION_IDLE_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "120"))
MAX_SESSIONS: int = int(os.getenv("MAX_SESSIONS", "1000"))
MAX_SESSION_EXTRA_KEYS: int = int(os.getenv("MAX_SESSION_EXTRA_KEYS", "50"))
CLEANUP_INTERVAL_SECONDS: int = int(os.getenv("SESSION_CLEANUP_INTERVAL", "60"))
SESSION_EVICTION_THRESHOLD: float = 0.9  # LRU eviction at 90% capacity


# =============================================================================
# UNIFIED SESSION DATA CLASS
# =============================================================================

@dataclass
class SessionData:
    """
    Unified session data supporting both AIBOM and SBOM workflows.

    Common fields:
        local_path: Path to cloned/uploaded repository
        file_count: Number of files in the repository
        validated: Whether the repository has been validated
        extra: Flexible dict for additional module-specific data (capped)
        created_at: Session creation timestamp
        last_accessed: Last access timestamp for idle-timeout tracking

    SBOM-specific fields:
        scan_id: Unique identifier for SBOM scan
        repo_name: Repository name for SBOM
        pat: PAT token for private repos
        completed_steps: Workflow step tracking for SBOM
    """
    # Common fields
    local_path: Optional[str] = None
    file_count: Optional[int] = None
    validated: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)

    # SBOM-specific fields
    scan_id: Optional[str] = None
    repo_name: Optional[str] = None
    pat: Optional[str] = None
    completed_steps: List[str] = field(default_factory=list)
    source_type: Optional[str] = None  # "github", "local", "zip"

    # Security metadata
    _created_ip: Optional[str] = field(default=None, repr=False)
    _rotated_from: Optional[str] = field(default=None, repr=False)

    def is_expired(self) -> bool:
        """Check if session has exceeded absolute TTL."""
        return datetime.utcnow() - self.created_at > timedelta(hours=SESSION_TTL_HOURS)

    def is_idle(self) -> bool:
        """Check if session has exceeded idle timeout."""
        return datetime.utcnow() - self.last_accessed > timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)

    def is_invalid(self) -> bool:
        """Check if session should be removed (expired OR idle)."""
        return self.is_expired() or self.is_idle()

    def touch(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed = datetime.utcnow()

    def safe_dict(self) -> Dict[str, Any]:
        """Return session metadata without sensitive fields (for logging/admin)."""
        return {
            "validated": self.validated,
            "file_count": self.file_count,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "scan_id": self.scan_id,
            "repo_name": self.repo_name,
            "source_type": self.source_type,
            "has_pat": self.pat is not None,
            "completed_steps": self.completed_steps,
            "extra_keys": list(self.extra.keys()),
            "is_expired": self.is_expired(),
            "is_idle": self.is_idle(),
        }


# =============================================================================
# SESSION STORE (Async-safe)
# =============================================================================

_lock = asyncio.Lock()

_SESSION_STORE: Dict[str, SessionData] = {}

_SESSION_FIELDS: frozenset = frozenset({
    'local_path', 'file_count', 'validated', 'extra',
    'scan_id', 'repo_name', 'pat', 'completed_steps', 'source_type'
})

_cleanup_task: Optional[asyncio.Task] = None


# =============================================================================
# BACKGROUND CLEANUP
# =============================================================================

async def _background_cleanup_loop():
    """Periodic background task to remove expired and idle sessions."""
    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            count = await cleanup_expired_sessions()
            if count > 0:
                active = await get_session_count()
                logger.info(f"[SESSION] Background cleanup removed {count} session(s). Active: {active}")
        except asyncio.CancelledError:
            logger.info("[SESSION] Background cleanup task cancelled")
            break
        except Exception as e:
            logger.error(f"[SESSION] Background cleanup error: {e}")


def start_cleanup_task():
    """Start background cleanup. Call during app startup (inside async context)."""
    global _cleanup_task
    if _cleanup_task is None or _cleanup_task.done():
        _cleanup_task = asyncio.create_task(_background_cleanup_loop())
        logger.info(f"[SESSION] Background cleanup started (interval: {CLEANUP_INTERVAL_SECONDS}s, "
                     f"TTL: {SESSION_TTL_HOURS}h, idle: {SESSION_IDLE_TIMEOUT_MINUTES}m)")


def stop_cleanup_task():
    """Stop background cleanup. Call during app shutdown."""
    global _cleanup_task
    if _cleanup_task and not _cleanup_task.done():
        _cleanup_task.cancel()
        logger.info("[SESSION] Background cleanup stopped")


# =============================================================================
# INTERNAL HELPERS (must be called while holding _lock)
# =============================================================================

def _safe_destroy_session(token: str):
    """Destroy a session and scrub sensitive data. Caller must hold _lock."""
    session = _SESSION_STORE.pop(token, None)
    if session:
        session.pat = None
        session.extra.clear()
        session.local_path = None


async def _evict_lru_sessions(count: int = 1):
    """Evict least-recently-used sessions. Caller must hold _lock."""
    if not _SESSION_STORE:
        return
    sorted_tokens = sorted(
        _SESSION_STORE.keys(),
        key=lambda t: _SESSION_STORE[t].last_accessed
    )
    evicted = 0
    for token in sorted_tokens:
        if evicted >= count:
            break
        _safe_destroy_session(token)
        evicted += 1
    if evicted:
        logger.warning(f"[SESSION] LRU-evicted {evicted} session(s) (capacity pressure)")


# =============================================================================
# SESSION OPERATIONS (all async-safe)
# =============================================================================

async def cleanup_expired_sessions() -> int:
    """Remove expired and idle sessions. Returns count removed."""
    async with _lock:
        expired = [t for t, s in _SESSION_STORE.items() if s.is_invalid()]
        for t in expired:
            _safe_destroy_session(t)
        return len(expired)


async def create_session(token: Optional[str] = None, client_ip: Optional[str] = None) -> str:
    """
    Create a new session with cryptographically secure token.

    Args:
        token: Optional pre-generated token (for unified AIBOM/SBOM sessions).
        client_ip: Optional client IP for audit trail.

    Returns:
        The session token.

    Raises:
        RuntimeError: If maximum session limit reached after eviction.
    """
    async with _lock:
        # Cleanup expired/idle first
        expired = [t for t, s in _SESSION_STORE.items() if s.is_invalid()]
        for t in expired:
            _safe_destroy_session(t)

        # LRU eviction at threshold
        if len(_SESSION_STORE) >= int(MAX_SESSIONS * SESSION_EVICTION_THRESHOLD):
            await _evict_lru_sessions(count=max(1, MAX_SESSIONS // 10))

        if len(_SESSION_STORE) >= MAX_SESSIONS:
            raise RuntimeError(
                f"Maximum session limit ({MAX_SESSIONS}) reached. "
                "Please try again later or contact support."
            )

        if token is None:
            token = secrets.token_urlsafe(32)

        session = SessionData()
        session._created_ip = client_ip
        _SESSION_STORE[token] = session
        return token


async def get_session(token: str) -> Optional[SessionData]:
    """
    Get session data for a token.
    Returns None and removes session if expired or idle.
    """
    async with _lock:
        session = _SESSION_STORE.get(token)
        if session is None:
            return None

        if session.is_invalid():
            _safe_destroy_session(token)
            return None

        session.touch()
        return session


async def update_session(token: str, **kwargs) -> bool:
    """
    Update session data. Known fields set directly; unknown go to extra.
    Extra keys are capped at MAX_SESSION_EXTRA_KEYS.

    Returns:
        True if session exists and was updated, False otherwise.
    """
    async with _lock:
        session = _SESSION_STORE.get(token)
        if not session:
            return False

        if session.is_invalid():
            _safe_destroy_session(token)
            return False

        for key, value in kwargs.items():
            if key in _SESSION_FIELDS:
                setattr(session, key, value)
            else:
                if key not in session.extra and len(session.extra) >= MAX_SESSION_EXTRA_KEYS:
                    logger.warning(f"[SESSION] Extra keys limit ({MAX_SESSION_EXTRA_KEYS}) reached, "
                                   f"rejecting key: {key}")
                    continue
                session.extra[key] = value

        session.touch()
        return True


async def rotate_session(old_token: str) -> Optional[str]:
    """
    Rotate session token (fixation prevention).
    Creates new token, migrates session, deletes old token.

    Returns:
        New token if successful, None if session not found/invalid.
    """
    async with _lock:
        session = _SESSION_STORE.get(old_token)
        if session is None or session.is_invalid():
            if session:
                _safe_destroy_session(old_token)
            return None

        new_token = secrets.token_urlsafe(32)
        session._rotated_from = hashlib.sha256(old_token.encode()).hexdigest()[:16]
        session.touch()

        _SESSION_STORE[new_token] = session
        del _SESSION_STORE[old_token]

        logger.info("[SESSION] Token rotated successfully")
        return new_token


async def clear_session(token: str) -> bool:
    """Clear a specific session and scrub sensitive data."""
    async with _lock:
        if token in _SESSION_STORE:
            _safe_destroy_session(token)
            return True
        return False


async def get_session_count() -> int:
    """Get current active session count."""
    async with _lock:
        return len(_SESSION_STORE)


async def clear_all_sessions() -> int:
    """Clear all sessions (admin). Returns count cleared."""
    async with _lock:
        count = len(_SESSION_STORE)
        for token in list(_SESSION_STORE.keys()):
            _safe_destroy_session(token)
        return count


async def get_session_stats() -> Dict[str, Any]:
    """
    Get aggregate session statistics (safe for admin endpoints).
    Does NOT expose tokens or session contents.
    """
    async with _lock:
        now = datetime.utcnow()
        expired_count = sum(1 for s in _SESSION_STORE.values() if s.is_expired())
        idle_count = sum(1 for s in _SESSION_STORE.values() if s.is_idle())
        validated_count = sum(1 for s in _SESSION_STORE.values() if s.validated)

        ages = [(now - s.created_at).total_seconds() for s in _SESSION_STORE.values()]
        avg_age = sum(ages) / len(ages) if ages else 0

        return {
            "active_sessions": len(_SESSION_STORE),
            "max_sessions": MAX_SESSIONS,
            "utilization_pct": round(len(_SESSION_STORE) / MAX_SESSIONS * 100, 1),
            "expired_pending_cleanup": expired_count,
            "idle_pending_cleanup": idle_count,
            "validated_sessions": validated_count,
            "avg_session_age_seconds": round(avg_age, 1),
            "ttl_hours": SESSION_TTL_HOURS,
            "idle_timeout_minutes": SESSION_IDLE_TIMEOUT_MINUTES,
        }


# =============================================================================
# BACKWARD COMPATIBILITY: Synchronous wrappers
# =============================================================================
# These allow existing sync code (AIBOM/SBOM session adapters called from
# within FastAPI async endpoints) to work without changing every call-site.
# They detect whether an event loop is running and adapt accordingly.

def _run_async(coro):
    """Run an async coroutine from sync context, handling event loop detection."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an async context (FastAPI endpoint) —
        # create a future and run it in the current loop.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


def create_session_sync(token: Optional[str] = None, client_ip: Optional[str] = None) -> str:
    """Sync wrapper for create_session."""
    return _run_async(create_session(token=token, client_ip=client_ip))


def get_session_sync(token: str) -> Optional[SessionData]:
    """Sync wrapper for get_session."""
    return _run_async(get_session(token))


def update_session_sync(token: str, **kwargs) -> bool:
    """Sync wrapper for update_session."""
    return _run_async(update_session(token, **kwargs))


def clear_session_sync(token: str) -> bool:
    """Sync wrapper for clear_session."""
    return _run_async(clear_session(token))


def clear_all_sessions_sync() -> int:
    """Sync wrapper for clear_all_sessions."""
    return _run_async(clear_all_sessions())


def get_session_count_sync() -> int:
    """Sync wrapper for get_session_count."""
    return _run_async(get_session_count())


def cleanup_expired_sessions_sync() -> int:
    """Sync wrapper for cleanup_expired_sessions."""
    return _run_async(cleanup_expired_sessions())


# =============================================================================
# SBOM WORKFLOW HELPERS
# =============================================================================

async def mark_step_complete(token: str, step: str) -> bool:
    """Mark a workflow step as completed for SBOM."""
    async with _lock:
        session = _SESSION_STORE.get(token)
        if session and not session.is_invalid() and step not in session.completed_steps:
            session.completed_steps.append(step)
            session.touch()
            return True
        return False


async def is_step_complete(token: str, step: str) -> bool:
    """Check if a workflow step is completed."""
    async with _lock:
        session = _SESSION_STORE.get(token)
        if session and not session.is_invalid():
            return step in session.completed_steps
        return False


# =============================================================================
# SBOM WORKFLOW CONSTANTS
# =============================================================================

ENDPOINT_MAP: Dict[str, str] = {
    "github": "/set_repository",
    "local": "/upload",
    "zip": "/upload_zip",
}

WORKFLOW_STEPS: List[str] = [
    "discover_and_parse",
    "detect_unused",       # optional – only needs packages + source code
    "fetch_depsdev",
    "registry_enrich",
    "fetch_osv",
    "generate",
]

STEP_DEPENDENCIES: Dict[str, List[str]] = {
    "discover_and_parse": [],
    # detect-unused only needs the manifest packages – no enrichment required
    "detect_unused": ["discover_and_parse"],
    "detect-unused": ["discover_and_parse"],
    "fetch_depsdev": ["discover_and_parse"],
    "fetch-depsdev": ["discover_and_parse"],
    "registry_enrich": ["discover_and_parse", "fetch_depsdev"],
    "registry-enrich": ["discover_and_parse", "fetch_depsdev"],
    "fetch_osv": ["discover_and_parse", "fetch_depsdev", "registry_enrich"],
    "fetch-osv": ["discover_and_parse", "fetch_depsdev", "registry_enrich"],
    "generate": ["discover_and_parse", "fetch_depsdev", "registry_enrich", "fetch_osv"],
}


# =============================================================================
# FASTAPI DEPENDENCIES
# =============================================================================

def require_validated_session():
    """
    FastAPI dependency — requires a validated session with local_path set.

    Usage:
        @app.post("/endpoint")
        async def handler(..., session: SessionData = Depends(require_validated_session())):
    """
    async def dependency(session_token: str = Header(..., description="Session token from /set_repository endpoint")):
        session = await get_session(session_token)

        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found or session expired. Call /set_repository first.",
                    "hint": "POST to /set_repository with your repository URL to get a session token"
                }
            )

        if not session.validated or not session.local_path:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Repository has not been validated yet. Complete validation first.",
                    "hint": "Call /set_repository to validate your repository"
                }
            )

        return session

    return dependency


def require_scan_initialized():
    """
    FastAPI dependency — requires scan_id to be set (SBOM workflow).

    Usage:
        @app.post("/endpoint")
        async def handler(..., session: SessionData = Depends(require_scan_initialized())):
    """
    async def dependency(session_token: str = Header(..., description="Session token from /set_repository endpoint")):
        session = await get_session(session_token)

        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found or session expired. Call /set_repository first.",
                    "hint": "POST to /set_repository with your repository URL to get a session token"
                }
            )

        if not session.validated:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Repository not validated. Complete validation first.",
                    "hint": "Call /set_repository to validate your repository"
                }
            )

        if not session.scan_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "SCAN_NOT_INITIALIZED",
                    "message": "Scan not initialized. Call /start_scan first.",
                    "hint": "POST to /start_scan to initialize the scan and get a scan ID"
                }
            )

        return session

    return dependency


def require_step(step_name: str):
    """
    FastAPI dependency — validates all required previous SBOM workflow steps
    are completed before allowing the current step.

    Usage:
        @app.post("/fetch_osv")
        async def handler(..., session: SessionData = Depends(require_step("fetch_osv"))):
    """
    async def dependency(session_token: str = Header(..., description="Session token from /set_repository endpoint")):
        session = await get_session(session_token)

        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found or session expired. Call /set_repository first.",
                    "hint": "POST to /set_repository with your repository URL to get a session token"
                }
            )

        if not session.validated:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Source not validated. Complete validation first.",
                    "hint": f"Call {ENDPOINT_MAP.get(session.source_type, '/set_repository')} to validate your source"
                }
            )

        if not session.scan_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "SCAN_NOT_INITIALIZED",
                    "message": "Scan not initialized. Call /start_scan first.",
                    "hint": "POST to /start_scan to initialize the scan and get a scan ID"
                }
            )

        # Check required previous steps
        required_steps = STEP_DEPENDENCIES.get(step_name, [])
        completed = session.completed_steps or []
        missing_steps = [s for s in required_steps if s not in completed]

        if missing_steps:
            step_to_endpoint = {
                "discover_and_parse": "/discover_and_parse",
                "fetch_depsdev": "/fetch_depsdev",
                "registry_enrich": "/registry_enrich",
                "fetch_osv": "/fetch_osv",
                "detect_unused": "/detect_unused",
            }
            missing_endpoints = [step_to_endpoint.get(s, f"/{s}") for s in missing_steps]
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "STEP_SKIPPED",
                    "message": f"Cannot proceed to /{step_name}. Required previous steps not completed.",
                    "missing_steps": missing_steps,
                    "missing_endpoints": missing_endpoints,
                    "completed_steps": completed,
                    "hint": f"Please complete these steps first: {', '.join(missing_endpoints)}"
                }
            )

        return session

    return dependency


async def create_session_with_token(token: str) -> str:
    """Create a new session with a specific token (for unified AIBOM/SBOM sessions)."""
    return await create_session(token=token)
