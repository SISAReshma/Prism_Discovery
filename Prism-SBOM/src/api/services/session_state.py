"""Session state for API operations."""

from __future__ import annotations

from enum import Enum
from typing import Optional, List, Dict, Tuple
from pathlib import Path
from contextvars import ContextVar
import uuid


class ScanState(str, Enum):
    IDLE = "idle"
    UPLOADED = "uploaded"
    VALIDATED = "validated"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SessionData:
    """Stores current session data"""
    def __init__(self):
        self.reset()

    def reset(self):
        self.scan_id: Optional[str] = None  # Current scan ID
        self.selected_source_type: Optional[str] = None  # Selected source type from /select_source
        self.upload_type: Optional[str] = None  # "repository", "folder"
        self.repository_url: Optional[str] = None
        self.token: Optional[str] = None
        self.is_private: bool = False
        self.provider: Optional[str] = None  # "github", "gitlab", "bitbucket"
        self.repo_name: Optional[str] = None
        self.temp_path: Optional[Path] = None
        self.uploaded_files: List[str] = []
        self.ecosystems_detected: List[str] = []
        self.manifest_files: List[Dict[str, str]] = []
        self.repo_license: Optional[Dict] = None  # Detected LICENSE file info
        self.state: ScanState = ScanState.IDLE
        self.progress: int = 0
        self.current_step: str = ""
        self.scan_results: Optional[Dict] = None
        self.vulnerabilities: List[Dict] = []
        self.remediation: List[Dict] = []
        self.remediation_path: Optional[str] = None  # Path to remediation report
        self.error_message: Optional[str] = None
        self.scan_timestamp: Optional[str] = None
        self.sbom_files: Dict[str, str] = {}  # format -> file path


_sessions: Dict[str, SessionData] = {}
_current_session: ContextVar[Optional[SessionData]] = ContextVar("current_session", default=None)
_current_token: ContextVar[Optional[str]] = ContextVar("current_token", default=None)


def create_session() -> Tuple[str, SessionData]:
    token = uuid.uuid4().hex
    data = SessionData()
    _sessions[token] = data
    return token, data


def get_session(token: str) -> Optional[SessionData]:
    return _sessions.get(token)


def set_current_session(token: str, data: SessionData) -> None:
    _current_token.set(token)
    _current_session.set(data)


def clear_current_session() -> None:
    _current_token.set(None)
    _current_session.set(None)


def get_current_session() -> Optional[SessionData]:
    return _current_session.get()


def get_current_token() -> Optional[str]:
    return _current_token.get()


class SessionProxy:
    def __getattr__(self, item):
        data = _current_session.get()
        if data is None:
            raise RuntimeError("No active session. Provide X-Session-Token header or session_token query param.")
        return getattr(data, item)

    def __setattr__(self, key, value):
        data = _current_session.get()
        if data is None:
            raise RuntimeError("No active session. Provide X-Session-Token header or session_token query param.")
        return setattr(data, key, value)


# Session proxy used by endpoints
session = SessionProxy()
