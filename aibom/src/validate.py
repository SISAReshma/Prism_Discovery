"""
Validate Endpoint Logic
Handles validation for: GitHub repo (public/private), ZIP upload, Local folder upload
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from typing import Optional, Tuple

import requests
from fastapi import UploadFile

# Import from modules
from aibom.config import (
    TEMP_DIR_PREFIX,
    SKIP_DIRECTORIES,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_UPLOAD_SIZE_MB,
    MAX_ZIP_FILE_COUNT,
    MAX_ZIP_FILE_SIZE,
    MAX_LOCAL_FILE_COUNT,
    GITHUB_API_TIMEOUT,
    GITHUB_CLONE_TIMEOUT,
    VALID_PAT_PREFIXES,
)
from aibom.src.errors import (
    raise_validation_error,
    raise_upload_error,
    raise_api_error,
    raise_clone_error,
)

# =============================================================================
# MODULE-LEVEL CONSTANTS (computed once at import)
# =============================================================================

# Cache base directory - computed once, reused everywhere
_BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# TEMP DIRECTORY MANAGEMENT
# =============================================================================

TEMP_BASE_DIR = None

# Use system temp dir (e.g. C:\Users\...\AppData\Local\Temp) so cloned repos
# are NOT inside the OneDrive-synced project folder. OneDrive dehydrates files
# written there within minutes, making them unreadable by semgrep.
_SYSTEM_TEMP_ROOT = os.path.join(tempfile.gettempdir(), "stacksq_aibom")


def get_temp_dir() -> str:
    """Get or create the base temp directory for this session.

    Uses the OS system temp directory (outside OneDrive) so that cloned
    repository files remain physically on disk and are readable by semgrep.
    """
    global TEMP_BASE_DIR
    base_dir = _SYSTEM_TEMP_ROOT
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)
    if TEMP_BASE_DIR is None or not os.path.exists(TEMP_BASE_DIR):
        TEMP_BASE_DIR = tempfile.mkdtemp(prefix=TEMP_DIR_PREFIX, dir=base_dir)
    return TEMP_BASE_DIR


def cleanup_temp_dir():
    """Cleanup temp directory - call on app shutdown"""
    global TEMP_BASE_DIR
    if TEMP_BASE_DIR and os.path.exists(TEMP_BASE_DIR):
        shutil.rmtree(TEMP_BASE_DIR, ignore_errors=True)
        TEMP_BASE_DIR = None


def get_relative_path(path: str) -> str:
    """Return the path as-is (absolute). Kept for backwards compatibility."""
    return os.path.abspath(path)


# =============================================================================
# DIRECTORY UTILITIES
# =============================================================================

def get_directory_details(path: str) -> dict:
    """Get details about a directory: file count"""
    file_count = 0
    
    for _, dirs, files in os.walk(path):
        # Skip hidden directories and common non-source directories (in-place modification controls os.walk behavior)
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRECTORIES]
        
        for file in files:
            if not file.startswith('.'):
                file_count += 1
    
    return {"file_count": file_count}


# =============================================================================
# OUTPUT SANITIZATION
# =============================================================================

def _sanitize_git_output(output: str, pat: Optional[str] = None) -> str:
    """Remove sensitive data (PAT, credentials) from git command output.
    
    Args:
        output: The git command output (stdout or stderr)
        pat: Optional PAT token to redact
    
    Returns:
        Sanitized output with credentials replaced by [REDACTED]
    """
    if not output:
        return output
    
    sanitized = output
    
    # Redact explicit PAT if provided
    if pat:
        sanitized = sanitized.replace(pat, "[REDACTED]")
    
    # Redact common credential patterns in git URLs
    # Pattern: https://TOKEN@github.com or https://user:TOKEN@github.com
    sanitized = re.sub(
        r'https://[^@:]+(?::[^@]+)?@',
        'https://[REDACTED]@',
        sanitized
    )
    
    # Redact GitHub PAT patterns (ghp_, gho_, ghu_, ghs_, ghr_)
    sanitized = re.sub(
        r'\b(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}\b',
        '[REDACTED]',
        sanitized
    )
    
    # Redact Bearer tokens
    sanitized = re.sub(
        r'Bearer\s+[a-zA-Z0-9_-]+',
        'Bearer [REDACTED]',
        sanitized,
        flags=re.IGNORECASE
    )
    
    return sanitized


# =============================================================================
# GITHUB URL PARSING
# =============================================================================

def parse_github_url(url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse GitHub URL to extract owner and repo name.
    Returns (owner, repo, error_reason) or (None, None, error_reason) if invalid.
    """
    url = url.strip()
    
    if not url:
        return None, None, "URL cannot be empty"
    
    if "github.com" not in url.lower():
        return None, None, "URL must be a GitHub repository URL (github.com)"
    
    if url.count("github.com") > 1:
        return None, None, "URL contains multiple 'github.com' references"
    
    patterns = [
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
        r"https?://github\.com/([^/]+)/([^/]+?)(?:/.*)?$",
    ]
    
    for pattern in patterns:
        match = re.match(pattern, url)
        if match:
            owner = match.group(1)
            repo = match.group(2).replace(".git", "")
            
            if not owner or owner in [".", ".."]:
                return None, None, "Invalid repository owner name"
            if not repo or repo in [".", ".."]:
                return None, None, "Invalid repository name"
            
            return owner, repo, None
    
    if "//" not in url and "github.com" in url:
        return None, None, "URL is missing protocol (https://)"
    
    parts = url.replace("https://", "").replace("http://", "").split("/")
    if len(parts) < 3:
        return None, None, "URL is incomplete. Expected format: https://github.com/owner/repo"
    
    return None, None, "Invalid GitHub URL format. Expected: https://github.com/owner/repo"


# =============================================================================
# GITHUB API
# =============================================================================

def check_repo_exists(owner: str, repo: str, pat: Optional[str] = None) -> dict:
    """Check if a GitHub repo exists and determine if it's public or private"""
    def result(exists=None, is_private=None, repo_data=None, error=None):
        return {"exists": exists, "is_private": is_private, "repo_data": repo_data, "error": error}
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    
    if pat:
        headers["Authorization"] = f"token {pat}"
    
    try:
        response = requests.get(api_url, headers=headers, timeout=GITHUB_API_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            return result(exists=True, is_private=data.get("private", False), repo_data=data)
        
        if response.status_code == 404:
            return result(exists=False, error="not_found")
        
        if response.status_code == 401:
            error = "invalid_pat_format" if pat and not pat.startswith(VALID_PAT_PREFIXES) else "invalid_pat"
            return result(error=error)
        
        if response.status_code == 403:
            error = "rate_limited" if response.headers.get("X-RateLimit-Remaining") == "0" else "access_forbidden"
            return result(error=error)
        
        return result(error=f"github_api_error_{response.status_code}")
        
    except requests.exceptions.Timeout:
        return result(error="connection_timeout")
    except requests.exceptions.ConnectionError:
        return result(error="connection_failed")
    except requests.exceptions.RequestException:
        return result(error="request_error")


# =============================================================================
# GIT CLONE
# =============================================================================

def clone_repo(owner: str, repo: str, pat: Optional[str] = None) -> Tuple[str, dict]:
    """Clone a GitHub repo to temp directory. Returns (path_to_cloned_repo, repo_details)"""
    # Validate owner/repo format strictly to prevent command injection
    if not re.match(r'^[a-zA-Z0-9_.-]+$', owner):
        raise ValueError(f"Invalid owner format: {owner}")
    if not re.match(r'^[a-zA-Z0-9_.-]+$', repo):
        raise ValueError(f"Invalid repo format: {repo}")
    
    temp_dir = get_temp_dir()
    clone_path = os.path.join(temp_dir, f"{owner}_{repo}")
    
    if os.path.exists(clone_path):
        shutil.rmtree(clone_path)
    
    # Use PAT embedded in URL for authentication (sanitized in error logging)
    env = os.environ.copy()
    if pat:
        clone_url = f"https://x-access-token:{pat}@github.com/{owner}/{repo}.git"
    else:
        clone_url = f"https://github.com/{owner}/{repo}.git"
    
    try:
        result = subprocess.run(
            ["git", "-c", "core.longpaths=true", "clone", "--depth", "1", clone_url, clone_path],
            capture_output=True,
            text=True,
            timeout=GITHUB_CLONE_TIMEOUT,
            env=env
        )
        if result.returncode != 0:
            # Sanitize stderr to prevent credential exposure in logs/exceptions
            raw_stderr = _sanitize_git_output(result.stderr, pat)
            stderr = raw_stderr.lower()
            if "authentication" in stderr or "401" in stderr:
                raise Exception("CLONE_AUTH_FAILED")
            elif "not found" in stderr or "404" in stderr:
                raise Exception("CLONE_REPO_NOT_FOUND")
            elif "permission denied" in stderr or "403" in stderr:
                raise Exception("CLONE_PERMISSION_DENIED")
            else:
                raise Exception(f"CLONE_FAILED: {raw_stderr[:200]}")
        
        return clone_path, get_directory_details(clone_path)
        
    except subprocess.TimeoutExpired:
        raise Exception("CLONE_TIMEOUT")
    except FileNotFoundError:
        raise Exception("GIT_NOT_INSTALLED")


# =============================================================================
# MAIN VALIDATION FUNCTIONS
# =============================================================================

async def validate_github_repo(repo_url: str, pat: Optional[str] = None) -> dict:
    """Validate a GitHub repository (public or private)"""
    # 1. Parse URL
    owner, repo, url_error = parse_github_url(repo_url)
    if url_error:
        raise_validation_error("INVALID_URL", url_error)
    
    # 2. Check repo exists (PAT provided means potentially private)
    check = check_repo_exists(owner, repo, pat)
    
    if check.get("error"):
        raise_api_error(check["error"], owner, repo)
    
    if not check["exists"]:
        raise_api_error("not_found", owner, repo)
    
    # 3. Clone repo
    try:
        clone_path, repo_details = clone_repo(owner, repo, pat)
    except Exception as e:
        raise_clone_error(str(e))
    
    # 4. Return success
    return {
        "valid": True,
        "repository": f"{owner}/{repo}",
        "branch": check.get("repo_data", {}).get("default_branch", "main"),
        "file_count": repo_details["file_count"],
        "local_path": get_relative_path(clone_path)
    }


async def validate_zip_upload(file: UploadFile) -> dict:
    """Validate and extract an uploaded ZIP file"""
    # 1. Check if file was provided
    if not file:
        raise_upload_error("NO_FILE", "No file was uploaded", hint="Select a ZIP file to upload")
    
    if not file.filename:
        raise_upload_error("NO_FILENAME", "Uploaded file has no name", hint="Ensure you're uploading a valid file")
    
    if not file.filename.lower().endswith('.zip'):
        ext = os.path.splitext(file.filename)[1] or "no extension"
        raise_upload_error("INVALID_FILE_TYPE", f"Expected .zip file, got '{ext}'", hint="Only ZIP archives are accepted")
    
    # 2. Save uploaded file to temp
    temp_dir = get_temp_dir()
    safe_filename = re.sub(r'[^\w\-\.]', '_', file.filename)
    zip_path = os.path.join(temp_dir, safe_filename)
    
    try:
        contents = await file.read()
        if len(contents) == 0:
            raise_upload_error("EMPTY_FILE", "The uploaded file is empty (0 bytes)", hint="Select a valid ZIP file with content")
        
        if len(contents) > MAX_UPLOAD_SIZE_BYTES:
            raise_upload_error("FILE_TOO_LARGE", f"File size ({len(contents) // (1024*1024)}MB) exceeds {MAX_UPLOAD_SIZE_MB}MB limit", status=413, hint="Upload a smaller ZIP file")
        
        with open(zip_path, "wb") as f:
            f.write(contents)
    except Exception as e:
        if "HTTPException" in str(type(e)):
            raise
        raise_upload_error("UPLOAD_FAILED", "Failed to save uploaded file", status=500, hint="Try uploading again")
    
    # 3. Validate ZIP file
    if not zipfile.is_zipfile(zip_path):
        os.remove(zip_path)
        raise_upload_error("INVALID_ZIP", "File is not a valid ZIP archive", hint="The file may be corrupted or not a real ZIP file")
    
    # 4. Extract ZIP
    extract_folder_name = os.path.splitext(safe_filename)[0]
    extract_path = os.path.join(temp_dir, extract_folder_name)
    
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Cache namelist once - avoid calling namelist() multiple times (O(n) each)
            members = zip_ref.namelist()
            
            # Check file count first (fast O(1) check)
            if len(members) > MAX_ZIP_FILE_COUNT:
                os.remove(zip_path)
                raise_upload_error("TOO_MANY_FILES", f"ZIP contains too many files (>{MAX_ZIP_FILE_COUNT:,})", hint="Reduce the number of files in your archive")
            
            # Security check: prevent path traversal (cache extract_path abs once)
            extract_path_abs = os.path.abspath(extract_path)
            for member in zip_ref.infolist():
                # Check for absolute paths
                if member.filename.startswith('/') or member.filename.startswith('\\'):
                    os.remove(zip_path)
                    raise_upload_error("MALICIOUS_ZIP", "ZIP contains absolute paths", hint="The ZIP file may be malicious (absolute path detected)")
                
                # Check for path traversal
                member_path = os.path.join(extract_path, member.filename)
                if not os.path.abspath(member_path).startswith(extract_path_abs):
                    os.remove(zip_path)
                    raise_upload_error("MALICIOUS_ZIP", "ZIP contains path traversal", hint="The ZIP file may be malicious (path traversal detected)")
                
                # Check for symlinks (external_attr high bits indicate symlink on Unix)
                # Unix symlinks have (0o120000 << 16) in external_attr
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    os.remove(zip_path)
                    raise_upload_error("MALICIOUS_ZIP", "ZIP contains symbolic links", hint="The ZIP file may be malicious (symlinks not allowed)")
                
                # Check for suspicious file sizes (zip bomb protection)
                if member.file_size > MAX_ZIP_FILE_SIZE:
                    os.remove(zip_path)
                    raise_upload_error("MALICIOUS_ZIP", f"ZIP contains suspiciously large file ({member.file_size // (1024*1024)}MB)", hint="Individual files cannot exceed 100MB (zip bomb protection)")
            
            zip_ref.extractall(extract_path)
    except zipfile.BadZipFile:
        if os.path.exists(zip_path):
            os.remove(zip_path)
        raise_upload_error("CORRUPTED_ZIP", "ZIP file is corrupted and cannot be extracted", hint="Re-create the ZIP file and try again")
    except Exception as e:
        if "HTTPException" in str(type(e)):
            raise
        if os.path.exists(zip_path):
            os.remove(zip_path)
        raise_upload_error("EXTRACTION_FAILED", "Failed to extract ZIP file", status=500, hint="The ZIP file may be corrupted")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
    
    # 5. Get directory details
    repo_details = get_directory_details(extract_path)
    
    if repo_details["file_count"] == 0:
        shutil.rmtree(extract_path)
        raise_upload_error("EMPTY_ARCHIVE", "ZIP file contains no valid files", hint="Ensure your ZIP contains source code files")
    
    return {
        "valid": True,
        "message": f"ZIP file '{file.filename}' extracted successfully",
        "source": file.filename,
        "file_count": repo_details["file_count"],
        "local_path": get_relative_path(extract_path)
    }


async def validate_local_upload(files: list[UploadFile]) -> dict:
    """Validate uploaded local files/folder"""
    if not files:
        raise_upload_error("NO_FILES", "No files were uploaded", hint="Select files or a folder to upload")
    
    if len(files) == 0:
        raise_upload_error("EMPTY_UPLOAD", "Upload request contains no files", hint="Select at least one file to upload")
    
    if len(files) > MAX_LOCAL_FILE_COUNT:
        raise_upload_error("TOO_MANY_FILES", f"Too many files ({len(files)}). Maximum is {MAX_LOCAL_FILE_COUNT:,}", hint="Upload fewer files or use ZIP upload instead")
    
    # Create a unique folder for this upload
    temp_dir = get_temp_dir()
    upload_id = f"local_{int(time.time() * 1000)}"
    upload_path = os.path.join(temp_dir, upload_id)
    os.makedirs(upload_path, exist_ok=True)
    
    uploaded_count = 0
    total_size = 0
    
    try:
        for file in files:
            if not file.filename:
                continue
            
            # Sanitize and preserve directory structure
            safe_path = file.filename.replace("\\", "/")
            safe_path = re.sub(r'^[./\\]+', '', safe_path)
            if not safe_path:
                continue
            
            file_path = os.path.join(upload_path, safe_path)
            
            # Security check
            if not os.path.abspath(file_path).startswith(os.path.abspath(upload_path)):
                continue
            
            file_dir = os.path.dirname(file_path)
            if file_dir and not os.path.exists(file_dir):
                os.makedirs(file_dir, exist_ok=True)
            
            contents = await file.read()
            total_size += len(contents)
            
            if total_size > MAX_UPLOAD_SIZE_BYTES:
                shutil.rmtree(upload_path)
                raise_upload_error("UPLOAD_TOO_LARGE", f"Total upload size exceeds {MAX_UPLOAD_SIZE_MB}MB limit", status=413, hint="Upload fewer files or use ZIP upload")
            
            with open(file_path, "wb") as f:
                f.write(contents)
            uploaded_count += 1
    except Exception as e:
        if "HTTPException" in str(type(e)):
            raise
        if os.path.exists(upload_path):
            shutil.rmtree(upload_path)
        raise_upload_error("UPLOAD_FAILED", "Failed to save uploaded files", status=500, hint="Try uploading again")
    
    if uploaded_count == 0:
        shutil.rmtree(upload_path)
        raise_upload_error("NO_VALID_FILES", "No valid files found in upload", hint="Ensure you're uploading valid source files")
    
    repo_details = get_directory_details(upload_path)
    
    return {
        "valid": True,
        "message": f"Successfully uploaded {uploaded_count} file(s)",
        "file_count": repo_details["file_count"],
        "local_path": get_relative_path(upload_path)
    }
