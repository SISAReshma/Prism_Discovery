"""
SBOM Session Management
Handles session tokens, source type locking, and validated path tracking via FastAPI dependencies
"""

import uuid
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from fastapi import Header, HTTPException

from src.api.config import ENDPOINT_MAP


# =============================================================================
# SESSION DATA CLASS
# =============================================================================

@dataclass
class SessionData:
    """Session data stored for each token"""
    source_type: str
    local_path: Optional[str] = None
    file_count: Optional[int] = None
    validated: bool = False
    # SBOM-specific fields
    scan_id: Optional[str] = None
    repo_name: Optional[str] = None
    token: Optional[str] = None  # PAT for private repos
    extra: Dict[str, Any] = field(default_factory=dict)
    # Step tracking for workflow validation
    completed_steps: list = field(default_factory=list)


# =============================================================================
# SESSION STORE
# =============================================================================

# In-memory session store (for demo/dev - use Redis/DB in production)
_SESSION_STORE: Dict[str, SessionData] = {}


def create_session(source_type: str) -> str:
    """Create a new session with the given source type and return the token"""
    token = str(uuid.uuid4())
    _SESSION_STORE[token] = SessionData(source_type=source_type)
    return token


def get_session(token: str) -> Optional[SessionData]:
    """Get the full session data for a token"""
    return _SESSION_STORE.get(token)


def get_session_source_type(token: str) -> Optional[str]:
    """Get the source type for a given session token"""
    session = _SESSION_STORE.get(token)
    return session.source_type if session else None


def update_session(token: str, **kwargs) -> bool:
    """
    Update session data with new values.
    Usage: update_session(token, local_path="/temp/repo", validated=True)
    """
    session = _SESSION_STORE.get(token)
    if not session:
        return False
    
    for key, value in kwargs.items():
        if hasattr(session, key):
            setattr(session, key, value)
        else:
            session.extra[key] = value
    return True


def clear_session(token: str) -> bool:
    """Clear a session (for use when flow completes)"""
    if token in _SESSION_STORE:
        del _SESSION_STORE[token]
        return True
    return False


def get_all_sessions() -> Dict[str, SessionData]:
    """Get all active sessions (for debugging)"""
    return _SESSION_STORE.copy()


# =============================================================================
# FASTAPI DEPENDENCIES - Endpoint Locking
# =============================================================================

def require_source_type(required_type: str):
    """
    Factory that creates a FastAPI dependency to check source type.
    This locks endpoints based on the source_type set in the session.
    
    Usage:
        @app.post("/validate/repo_public")
        async def endpoint(..., _: str = Depends(require_source_type("repo_public"))):
            ...
    """
    def dependency(session_token: str = Header(..., description="Session token from /source_type endpoint")):
        session = get_session(session_token)
        
        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found. Call /source_type first to set your source type.",
                    "hint": "POST to /source_type with a valid source_type to get a session token"
                }
            )
        
        if session.source_type != required_type:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ENDPOINT_LOCKED",
                    "message": f"This endpoint is locked. Your source_type is '{session.source_type}', but this endpoint requires '{required_type}'.",
                    "current_source_type": session.source_type,
                    "available_endpoint": ENDPOINT_MAP.get(session.source_type),
                    "hint": f"Use {ENDPOINT_MAP.get(session.source_type)} instead, or call /source_type to change your source type"
                }
            )
        
        return session.source_type
    
    return dependency


def require_validated_session():
    """
    FastAPI dependency that requires a validated session (validation completed).
    Use for endpoints that need the validated local_path.
    """
    def dependency(session_token: str = Header(..., description="Session token from /source_type endpoint")):
        session = get_session(session_token)
        
        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found. Call /source_type first.",
                    "hint": "POST to /source_type with a valid source_type to get a session token"
                }
            )
        
        if not session.validated or not session.local_path:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Source not validated. Complete validation first.",
                    "source_type": session.source_type,
                    "validate_endpoint": ENDPOINT_MAP.get(session.source_type),
                    "hint": f"Call {ENDPOINT_MAP.get(session.source_type)} to validate your source"
                }
            )
        
        return session
    
    return dependency


def require_scan_initialized():
    """
    FastAPI dependency that requires scan to be initialized (scan_id assigned).
    Use for scan step endpoints.
    """
    def dependency(session_token: str = Header(..., description="Session token from /source_type endpoint")):
        session = get_session(session_token)
        
        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found. Call /source_type first.",
                    "hint": "POST to /source_type with a valid source_type to get a session token"
                }
            )
        
        if not session.validated:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Source not validated. Complete validation first.",
                    "hint": f"Call {ENDPOINT_MAP.get(session.source_type)} to validate your source"
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


# Workflow step order
WORKFLOW_STEPS = [
    "discover_and_parse",
    "fetch_depsdev",
    "registry_enrich",
    "fetch_osv",
    "generate"  # Any generate endpoint
]

STEP_DEPENDENCIES = {
    "discover_and_parse": [],  # No previous step required (after scan init)
    "fetch_depsdev": ["discover_and_parse"],
    "registry_enrich": ["discover_and_parse", "fetch_depsdev"],
    "fetch_osv": ["discover_and_parse", "fetch_depsdev", "registry_enrich"],
    "generate": ["discover_and_parse", "fetch_depsdev", "registry_enrich", "fetch_osv"]
}


def mark_step_complete(token: str, step: str) -> bool:
    """Mark a workflow step as completed"""
    session = get_session(token)
    if session and step not in session.completed_steps:
        session.completed_steps.append(step)
        return True
    return False


def require_step(step_name: str):
    """
    FastAPI dependency that validates all required previous steps are completed.
    
    Usage:
        @app.post("/fetch_osv")
        async def endpoint(..., session: SessionData = Depends(require_step("fetch_osv"))):
            ...
    """
    def dependency(session_token: str = Header(..., description="Session token from /source_type endpoint")):
        session = get_session(session_token)
        
        if session is None:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "NO_SESSION",
                    "message": "No session found. Call /source_type first.",
                    "hint": "POST to /source_type with a valid source_type to get a session token"
                }
            )
        
        if not session.validated:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "NOT_VALIDATED",
                    "message": "Source not validated. Complete validation first.",
                    "hint": f"Call {ENDPOINT_MAP.get(session.source_type)} to validate your source"
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
                "fetch_osv": "/fetch_osv"
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
