"""
SBOM Validation Logic
Handles validation for: GitHub repo (public/private), ZIP upload, Local folder upload
"""

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from typing import Optional, Tuple, List
from pathlib import Path

import requests
from fastapi import UploadFile

from sbom.src.api.config import (
    TEMP_DIR_PREFIX,
    SKIP_DIRECTORIES,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_UPLOAD_SIZE_MB,
    MAX_ZIP_FILE_COUNT,
    MAX_LOCAL_FILE_COUNT,
    GITHUB_API_TIMEOUT,
    GITHUB_CLONE_TIMEOUT,
    VALID_PAT_PREFIXES,
    MAX_FILE_SIZE,
)
from sbom.src.api.errors import (
    raise_validation_error,
    raise_upload_error,
    raise_api_error,
    raise_clone_error,
)


# =============================================================================
# TEMP DIRECTORY MANAGEMENT
# =============================================================================

TEMP_BASE_DIR = None


def get_temp_dir() -> str:
    """Get or create the base temp directory for this session"""
    global TEMP_BASE_DIR
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "temp")
    base_dir = os.path.abspath(base_dir)
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
    """Get path relative to the project root"""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.relpath(path, start=project_root)


# =============================================================================
# DIRECTORY UTILITIES
# =============================================================================

def get_directory_details(path: str) -> dict:
    """Get details about a directory: file count and directory count"""
    file_count = 0
    dir_count = 0
    
    for root, dirs, files in os.walk(path):
        # Skip hidden directories and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRECTORIES]
        dir_count += len(dirs)
        
        for file in files:
            if not file.startswith('.'):
                file_count += 1
    
    return {"file_count": file_count, "directory_count": dir_count}


# =============================================================================
# GITHUB URL PARSING
# =============================================================================

def parse_github_url(url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse GitHub URL to extract owner and repo name.
    Returns (owner, repo, error_reason) or (None, None, error_reason) if invalid.
    """
    url = url.strip()
    
    # Support both HTTPS and SSH formats
    patterns = [
        r'^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',  # HTTPS
        r'^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$',         # SSH
    ]
    
    for pattern in patterns:
        match = re.match(pattern, url)
        if match:
            owner, repo = match.groups()
            return owner, repo, None
    
    return None, None, "Invalid GitHub URL format. Expected: https://github.com/owner/repo"


# =============================================================================
# GITHUB VALIDATION
# =============================================================================

async def validate_github_repo(repo_url: str, pat: Optional[str] = None) -> dict:
    """
    Validate a GitHub repository (public or private).
    
    Args:
        repo_url: GitHub repository URL
        pat: Personal Access Token (optional, required for private repos)
    
    Returns:
        dict with validation results and local_path
    """
    # Parse URL
    owner, repo, error = parse_github_url(repo_url)
    if error:
        raise_validation_error("INVALID_URL", error)
    
    # Validate PAT format if provided
    if pat and not pat.startswith(VALID_PAT_PREFIXES):
        raise_validation_error(
            "INVALID_PAT_FORMAT", 
            f"Invalid PAT format. Token should start with one of: {', '.join(VALID_PAT_PREFIXES)}"
        )
    
    # Check if repo exists via GitHub API
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if pat:
        headers["Authorization"] = f"token {pat}"
    
    try:
        resp = requests.get(api_url, headers=headers, timeout=GITHUB_API_TIMEOUT)
        
        if resp.status_code == 404:
            if pat:
                raise_api_error("REPO_NOT_FOUND", f"Repository '{owner}/{repo}' not found or PAT lacks access")
            else:
                raise_api_error("REPO_NOT_FOUND", f"Repository '{owner}/{repo}' not found or is private. Provide PAT if repository is private.")
        
        if resp.status_code == 401:
            raise_api_error("UNAUTHORIZED", "Invalid or expired Personal Access Token")
        
        if resp.status_code == 403:
            raise_api_error("FORBIDDEN", "Access forbidden. Check PAT permissions (needs 'repo' scope)")
        
        if resp.status_code != 200:
            raise_api_error("API_ERROR", f"GitHub API returned status {resp.status_code}")
        
        repo_data = resp.json()
        default_branch = repo_data.get("default_branch", "main")
        is_private = repo_data.get("private", False)
        
    except requests.exceptions.Timeout:
        raise_api_error("TIMEOUT", "GitHub API request timed out")
    except requests.exceptions.RequestException as e:
        raise_api_error("NETWORK_ERROR", f"Network error: {str(e)}")
    
    # Clone the repository
    temp_dir = get_temp_dir()
    clone_dir = os.path.join(temp_dir, f"{owner}_{repo}")
    
    # Clean up if exists from previous attempt
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir, ignore_errors=True)
    
    # Build clone URL
    if pat:
        clone_url = f"https://{pat}@github.com/{owner}/{repo}.git"
    else:
        clone_url = f"https://github.com/{owner}/{repo}.git"
    
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=GITHUB_CLONE_TIMEOUT
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            raise_clone_error("CLONE_FAILED", f"Git clone failed: {error_msg}")
        
    except subprocess.TimeoutExpired:
        raise_clone_error("CLONE_TIMEOUT", f"Git clone timed out after {GITHUB_CLONE_TIMEOUT}s")
    except FileNotFoundError:
        raise_clone_error("GIT_NOT_FOUND", "Git is not installed or not in PATH")
    
    # Get file count
    details = get_directory_details(clone_dir)
    
    return {
        "valid": True,
        "repository": f"{owner}/{repo}",
        "branch": default_branch,
        "file_count": details["file_count"],
        "local_path": get_relative_path(clone_dir)
    }


# =============================================================================
# ZIP VALIDATION
# =============================================================================

async def validate_zip_upload(file: UploadFile) -> dict:
    """
    Validate and extract an uploaded ZIP file.
    
    Args:
        file: Uploaded ZIP file
    
    Returns:
        dict with validation results and local_path
    """
    # Check filename
    if not file.filename:
        raise_upload_error("NO_FILENAME", "No filename provided")
    
    if not file.filename.lower().endswith('.zip'):
        raise_upload_error("INVALID_FORMAT", "File must be a ZIP archive")
    
    # Read content
    try:
        content = await file.read()
    except Exception as e:
        raise_upload_error("READ_ERROR", f"Failed to read file: {str(e)}")
    
    # Check size
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise_upload_error("FILE_TOO_LARGE", f"File exceeds maximum size of {MAX_UPLOAD_SIZE_MB}MB")
    
    if len(content) == 0:
        raise_upload_error("EMPTY_FILE", "Uploaded file is empty")
    
    # Extract
    temp_dir = get_temp_dir()
    extract_dir = os.path.join(temp_dir, file.filename.replace('.zip', '').replace('.ZIP', ''))
    
    # Clean up if exists
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir, ignore_errors=True)
    
    os.makedirs(extract_dir, exist_ok=True)
    
    # Save and extract
    zip_path = os.path.join(temp_dir, "upload.zip")
    try:
        with open(zip_path, 'wb') as f:
            f.write(content)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Check file count
            if len(zip_ref.namelist()) > MAX_ZIP_FILE_COUNT:
                raise_upload_error("TOO_MANY_FILES", f"ZIP contains more than {MAX_ZIP_FILE_COUNT} files")
            
            zip_ref.extractall(extract_dir)
        
        # Remove temp zip
        os.remove(zip_path)
        
    except zipfile.BadZipFile:
        raise_upload_error("CORRUPTED_ZIP", "ZIP file is corrupted or invalid")
    except Exception as e:
        raise_upload_error("EXTRACT_ERROR", f"Failed to extract ZIP: {str(e)}")
    
    # If there's only one folder inside, use that as root
    items = list(Path(extract_dir).iterdir())
    if len(items) == 1 and items[0].is_dir():
        extract_dir = str(items[0])
    
    # Get file count
    details = get_directory_details(extract_dir)
    
    return {
        "valid": True,
        "message": "ZIP file validated and extracted successfully",
        "source": file.filename,
        "file_count": details["file_count"],
        "local_path": get_relative_path(extract_dir)
    }


# =============================================================================
# LOCAL FOLDER VALIDATION
# =============================================================================

async def validate_local_upload(files: List[UploadFile]) -> dict:
    """
    Validate and save uploaded local files.
    
    Args:
        files: List of uploaded files
    
    Returns:
        dict with validation results and local_path
    """
    if not files:
        raise_upload_error("NO_FILES", "No files uploaded")
    
    if len(files) > MAX_LOCAL_FILE_COUNT:
        raise_upload_error("TOO_MANY_FILES", f"Maximum {MAX_LOCAL_FILE_COUNT} files allowed")
    
    # Create project directory
    temp_dir = get_temp_dir()
    project_dir = os.path.join(temp_dir, "uploaded_project")
    
    # Clean up if exists
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir, ignore_errors=True)
    
    os.makedirs(project_dir, exist_ok=True)
    
    total_size = 0
    saved_files = []
    
    for file in files:
        if not file.filename:
            continue
        
        try:
            content = await file.read()
        except Exception as e:
            raise_upload_error("READ_ERROR", f"Failed to read file {file.filename}: {str(e)}")
        
        if not content:
            continue
        
        # Check individual file size
        if len(content) > MAX_FILE_SIZE:
            raise_upload_error("FILE_TOO_LARGE", f"File '{file.filename}' exceeds {MAX_FILE_SIZE // (1024*1024)}MB limit")
        
        total_size += len(content)
        
        if total_size > MAX_UPLOAD_SIZE_BYTES:
            raise_upload_error("TOTAL_SIZE_EXCEEDED", f"Total upload size exceeds {MAX_UPLOAD_SIZE_MB}MB")
        
        # Preserve folder structure
        file_path = os.path.join(project_dir, file.filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        saved_files.append(file.filename)
    
    if not saved_files:
        raise_upload_error("NO_VALID_FILES", "No valid files could be saved")
    
    # Get file count
    details = get_directory_details(project_dir)
    
    return {
        "valid": True,
        "message": f"Uploaded {len(saved_files)} files successfully",
        "file_count": details["file_count"],
        "local_path": get_relative_path(project_dir)
    }
