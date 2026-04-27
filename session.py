"""
AIBOM Session Management
Handles session tokens, source type locking, and validated path tracking via FastAPI dependencies
"""

import uuid
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from fastapi import Header, HTTPException

from aibom.config import ENDPOINT_MAP


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
    extra: Dict[str, Any] = field(default_factory=dict)


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
    session = get_session(token)  # Reuse get_session to avoid duplicate lookup pattern
    return session.source_type if session else None


# Pre-computed set of SessionData fields for O(1) lookup in update_session
_SESSION_FIELDS: frozenset = frozenset({'source_type', 'local_path', 'file_count', 'validated', 'extra'})


def update_session(token: str, **kwargs) -> bool:
    """
    Update session data with new values.
    Usage: update_session(token, local_path="/temp/repo", validated=True)
    """
    session = _SESSION_STORE.get(token)
    if not session:
        return False
    
    # Use pre-computed field set instead of hasattr() for each iteration
    for key, value in kwargs.items():
        if key in _SESSION_FIELDS:
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
                    "message": "Source has not been validated yet. Complete validation first.",
                    "hint": f"Call {ENDPOINT_MAP.get(session.source_type)} to validate your source"
                }
            )
        
        return session
    
    return dependency
