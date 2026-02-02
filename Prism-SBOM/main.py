"""
StackSQScanner FastAPI REST API

SBOM Generator and Vulnerability Scanner.
See API_DOCUMENTATION.md for full endpoint documentation.

Run with: uvicorn main:app --reload --port 8000
Test with: http://localhost:8000/docs
"""

import os
import json
import zipfile
import shutil
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from src.api.services.rate_limits import get_api_rate_limit_status
from src.api.services.repo_validation import (
    get_provider_from_url,
    extract_repo_name,
    check_repository,
    validate_token_format,
    validate_url_format,
)
from src.api.services.ecosystem_detection import detect_ecosystems
from src.api.services.token_hints import get_token_format_hint, get_token_troubleshooting_hint
from src.api.services.cleanup import cleanup_temp_workspace
from src.registry.language_registry import (
    get_all_manifest_files,
    get_language_for_manifest,
    get_purl_type,
)
import time

from fastapi import HTTPException, UploadFile, File, Request
from fastapi.responses import JSONResponse, FileResponse
from src.api.app import app

# Import config values
from src.config.config import (
    TOOL_NAME, TOOL_VERSION, TOOL_VENDOR,
    REPORTS_DIR as CONFIG_REPORTS_DIR,
    TEMP_DIR as CONFIG_TEMP_DIR,
    MAX_FOLDER_SIZE
)

from src.api.models import SourceTypeEnum, SelectSourceRequest, UploadRepositoryRequest, SetTokenRequest
from src.api.services.session_state import (
    session,
    ScanState,
    create_session,
    set_current_session,
)
from src.api.context import orchestrator, github_rate_limiter, REPORTS_DIR, TEMP_DIR


# =============================================================================
# Enums and Constants
# =============================================================================

# These are now imported from config:
# - SUPPORTED_PROVIDERS
# - MAX_FOLDER_SIZE

# Additional upload limits (not yet in config)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
MAX_FILES_COUNT = 20

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/", tags=["Info"])
def root():
    """Root endpoint - API info and workflow"""
    return {
        "name": f"{TOOL_NAME} API",
        "version": TOOL_VERSION,
        "vendor": TOOL_VENDOR,
        "docs": "/docs",
        "workflow_sequence": {
            "step_1": "POST /select_source - MUST be called first to select source type",
            "step_2": "POST /upload_repository - Choose ONE upload method based on your source",
            "step_3": "POST /set_token - (Optional) Only for private repos",
            "step_4": "POST /upload_zip - Alternative: Upload ZIP file",
            "step_5": "POST /upload_folder - Alternative: Upload local folder",
            "step_6": "POST /validate - Validate the content",
            "step_7": "POST /start_scan - Initialize scan and assign ID",
            "step_8": "POST /discover_manifests - Discover manifest files",
            "step_9": "POST /parse_manifests - Parse manifests and extract packages",
            "step_10": "POST /fetch_depsdev - Fetch from Google package manager (deps.dev)",
            "step_11": "POST /registry_enrich - Enrich from registry APIs",
            "step_12": "POST /fetch_osv - Fetch vulnerabilities",
            "step_13": "GET /scan_status - Check scan status",
            "step_14": "POST /generate_json - Generate SBOM (JSON format)",
            "step_15": "POST /generate_spdx - Generate SBOM (SPDX format)",
            "step_16": "POST /generate_cyclonedx - Generate SBOM (CycloneDX format)",
            "step_17": "POST /generate_remediation - Generate remediation report",
            "step_18": "POST /generate_sbom - Generate all SBOM formats at once",
            "step_19": "GET /scan_results - Get scan results summary",
            "step_20": "GET /vulnerabilities - Get vulnerability list",
            "step_21": "GET /remediation - Get remediation suggestions",
            "step_22": "GET /download - Download report links",
            "step_23": "GET /api/v1/download_file/{filename} - Download specific file"
        },
        "utility": {
            "reset": "POST /reset - Clear session and start fresh (use if stuck)"
        },
        "endpoints": {
            "source_selection": [
                "POST /select_source - Select source type (MUST be first)"
            ],
            "upload": [
                "POST /upload_repository - Upload Git repository URL",
                "POST /set_token - Set PAT for private repos",
                "POST /upload_zip - Upload ZIP file",
                "POST /upload_folder - Upload folder files"
            ],
            "validation": [
                "POST /validate - Validate uploaded content"
            ],
            "scan_initialization": [
                "POST /start_scan - Initialize scan, assign ID",
                "POST /reset - Reset session state"
            ],
            "scan_steps": [
                "POST /discover_manifests - Find manifest files",
                "POST /parse_manifests - Extract packages",
                "POST /fetch_depsdev - Fetch from deps.dev (license, homepage, release_date)",
                "POST /registry_enrich - Enrich from registry APIs (description, supplier, hashes)",
                "POST /fetch_osv - Fetch vulnerabilities from OSV database"
            ],
            "sbom_generation": [
                "POST /generate_json - Generate JSON SBOM only",
                "POST /generate_spdx - Generate SPDX SBOM only",
                "POST /generate_cyclonedx - Generate CycloneDX SBOM only",
                "POST /generate_sbom - Generate all SBOM formats at once",
                "POST /generate_remediation - Generate remediation report"
            ],
            "status_check": [
                "GET /scan_status - Check current scan status"
            ],
            "results": [
                "GET /scan_results - Get scan results summary",
                "GET /vulnerabilities - Get vulnerability list",
                "GET /remediation - Get remediation suggestions",
                "GET /download - Get download links",
                "GET /api/v1/download_file/{filename} - Download specific file"
            ]
        },
        "supported_ecosystems": ["Python (PyPI)", "npm (JavaScript/Node)"]
    }


# -----------------------------------------------------------------------------
# GET /rate_limits - Check API rate limit status
# -----------------------------------------------------------------------------
@app.get("/rate_limits", tags=["Info"])
def get_rate_limits():
    """
    Check current API rate limit status.
    
    Shows usage for:
    - GitHub API (most restrictive: 60/hr without token, 5000/hr with token)
    - deps.dev API (1000/hr)
    - PyPI/npm registries (generous limits)
    
    Use this to monitor if you're approaching limits.
    """
    rate_status = get_api_rate_limit_status(github_rate_limiter)
    
    return {
        "message": "Rate limit status",
        "apis": rate_status['status'],
        "warnings": rate_status['warnings'],
        "tips": [
            "Provide a GitHub token via /set_token to increase limit from 60/hr to 5000/hr",
            "deps.dev results are cached locally to reduce API calls",
            "Rate limits reset every hour"
        ]
    }


# -----------------------------------------------------------------------------
# GET /db_status - Check database connection and cache status
# -----------------------------------------------------------------------------
@app.get("/db_status", tags=["Info"])
def get_db_status():
    """
    Check database connection and cache status.
    
    Shows:
    - Database connection status
    - Cache table counts
    - Cache strategy (API First → DB Fallback)
    """
    try:
        from src.clients.db_cache_client import test_db_connection, get_db_cache_stats
        db_connection = test_db_connection()
        cache_stats = get_db_cache_stats()
        
        return {
            "message": "Database status",
            "strategy": "API First → DB Cache Fallback",
            "connection": db_connection,
            "cache_stats": cache_stats,
            "config": {
                "host": db_connection.get("host", "unknown"),
                "port": db_connection.get("port", "unknown"),
                "database": db_connection.get("database", "unknown")
            }
        }
    except ImportError:
        return {
            "message": "Database client not available",
            "strategy": "API First → DB Cache Fallback",
            "connection": {"connected": False, "error": "pymysql not installed"},
            "note": "Install pymysql: pip install pymysql"
        }
    except Exception as e:
        return {
            "message": "Database status check failed",
            "error": str(e)
        }


# -----------------------------------------------------------------------------
# POST /reset - Reset session state
# -----------------------------------------------------------------------------
@app.post("/reset", tags=["Info"])
def reset_session():
    """
    Reset the current session state.
    
    Use this if:
    - A previous scan was interrupted
    - You want to start fresh
    - You're getting "scan in progress" errors
    """
    global session
    
    # Cleanup temp files if any
    if session.temp_path:
        try:
            temp_path = Path(session.temp_path)
            if temp_path.exists():
                shutil.rmtree(temp_path, ignore_errors=True)
        except:
            pass
    
    # Reset session
    session.reset()
    
    return {
        "message": "Session reset successfully",
        "state": session.state.value,
        "note": "You can now start a new scan with /select_source"
    }


# -----------------------------------------------------------------------------
# 0. POST /select_source - Choose source type
# -----------------------------------------------------------------------------
@app.post("/select_source", tags=["Upload"])
def select_source(request: SelectSourceRequest):
    """
    Step 0: Select the source type for scanning.
    
    Choose from: repository, zip_file, folder
    Returns the next endpoint to call based on source type.
    MUST be called first before any upload endpoint.
    """
    global session

    # Create new session and bind it for this request
    session_token, session_data = create_session()
    set_current_session(session_token, session_data)
    
    source_type = request.source_type
    
    # Store selected source type
    session.selected_source_type = source_type.value
    
    next_steps = {
        SourceTypeEnum.REPOSITORY: {
            "next_endpoint": "Choose: POST /repo_public OR POST /repo_private",
            "request_format": {"repository_url": "https://github.com/owner/repo"},
            "public_repo": {
                "endpoint": "POST /repo_public",
                "description": "For public repositories - direct validation and upload"
            },
            "private_repo": {
                "endpoint": "POST /repo_private", 
                "description": "For private repositories - will redirect to /set_token for authentication"
            }
        },
        SourceTypeEnum.ZIP_FILE: {
            "next_endpoint": "POST /upload_zip",
            "request_format": "Multipart form: file=<zip_file>"
        },
        SourceTypeEnum.FOLDER: {
            "next_endpoint": "POST /upload_folder",
            "request_format": "Multipart form: files=<multiple_files>"
        }
    }
    
    return {
        "message": f"Source type '{source_type.value}' selected",
        "source_type": source_type.value,
        "session_token": session_token,
        **next_steps[source_type]
    }


# -----------------------------------------------------------------------------
# 1a. POST /repo_public - Upload public Git repository
# -----------------------------------------------------------------------------
@app.post("/repo_public", tags=["Upload"])
def repo_public(request: UploadRepositoryRequest):
    """
    Upload a PUBLIC Git repository URL for scanning.
    
    - Validates the URL format
    - Checks if repository is publicly accessible
    - If repository is private or inaccessible, returns error (use /repo_private instead)
    
    Supported providers: GitHub, GitLab, Bitbucket
    
    NOTE: Call /select_source first with source_type='repository'
    """
    global session
    
    # Check if source type was selected
    if not session.selected_source_type:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Please select source type first using /select_source"}
        )
    
    # Check if correct source type was selected
    if session.selected_source_type != "repository":
        return JSONResponse(
            status_code=400,
            content={
                "message": "Upload failed", 
                "error": f"Source type mismatch. You selected '{session.selected_source_type}' but trying to upload repository. Please call /select_source with source_type='repository'"
            }
        )
    
    # Validate URL format
    is_valid, error = validate_url_format(request.repository_url)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": error}
        )
    
    url = request.repository_url.strip()
    provider = get_provider_from_url(url)
    repo_name = extract_repo_name(url)
    
    # Check repository accessibility (without token)
    result = check_repository(url, rate_limiter=github_rate_limiter)
    
    if not result["accessible"]:
        if result["is_private"]:
            # Private repo detected - tell user to use /repo_private
            owner_repo = f"{url.rstrip('/').split('/')[-2]}/{repo_name}" if '/' in url else repo_name
            return JSONResponse(
                status_code=400,
                content={
                    "message": f"Repository '{owner_repo}' is private or inaccessible",
                    "error": "This repository requires authentication. Please use POST /repo_private instead",
                    "suggestion": "POST /repo_private with your repository URL, then follow with /set_token"
                }
            )
        else:
            # Other error (not found, network error, etc.)
            return JSONResponse(
                status_code=400,
                content={"message": "Upload failed", "error": result["error"]}
            )
    
    # Success - public repo accessible
    session.upload_type = "repository"
    session.repository_url = url
    session.provider = provider
    session.repo_name = repo_name
    session.is_private = False
    session.state = ScanState.UPLOADED
    
    return {
        "message": f"Public repository '{repo_name}' uploaded successfully",
        "is_private": False,
        "provider": provider,
        "repo_name": repo_name,
        "next_step": "POST /validate"
    }


# -----------------------------------------------------------------------------
# 1b. POST /repo_private - Upload private Git repository
# -----------------------------------------------------------------------------
@app.post("/repo_private", tags=["Upload"])
def repo_private(request: UploadRepositoryRequest):
    """
    Upload a PRIVATE Git repository URL for scanning.
    
    - Validates the URL format
    - Stores repository info and redirects to /set_token for authentication
    
    Supported providers: GitHub, GitLab, Bitbucket
    
    NOTE: Call /select_source first with source_type='repository'
    After calling this endpoint, you MUST call /set_token to provide your PAT.
    """
    global session
    
    # Check if source type was selected
    if not session.selected_source_type:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Please select source type first using /select_source"}
        )
    
    # Check if correct source type was selected
    if session.selected_source_type != "repository":
        return JSONResponse(
            status_code=400,
            content={
                "message": "Upload failed", 
                "error": f"Source type mismatch. You selected '{session.selected_source_type}' but trying to upload repository. Please call /select_source with source_type='repository'"
            }
        )
    
    # Validate URL format
    is_valid, error = validate_url_format(request.repository_url)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": error}
        )
    
    url = request.repository_url.strip()
    provider = get_provider_from_url(url)
    repo_name = extract_repo_name(url)
    
    # Store repository info for private access
    session.upload_type = "repository"
    session.repository_url = url
    session.provider = provider
    session.repo_name = repo_name
    session.is_private = True
    session.state = ScanState.UPLOADED
    
    # Format owner/repo for message
    owner_repo = f"{url.rstrip('/').split('/')[-2]}/{repo_name}" if '/' in url else repo_name
    
    return {
        "message": f"Private repository '{owner_repo}' registered. Please provide authentication token.",
        "is_private": True,
        "provider": provider,
        "repo_name": repo_name,
        "next_step": "POST /set_token",
        "request_format": {"token": "your_personal_access_token"},
        "token_requirements": {
            "github": "Token needs 'repo' scope for private repositories",
            "gitlab": "Token needs 'read_repository' scope",
            "bitbucket": "Use App Password with 'repository:read' permission"
        }
    }


# -----------------------------------------------------------------------------
# 2. POST /set_token - Set PAT for private repository
# -----------------------------------------------------------------------------
@app.post("/set_token", tags=["Upload"])
def set_token(request: SetTokenRequest):
    """
    Set Personal Access Token for private repository access.
    
    Call this after /upload_repository if the repository is private.
    
    Token requirements:
    - GitHub: Token starting with 'ghp_' or 'github_pat_' with 'repo' scope
    - GitLab: Token starting with 'glpat-' with read_repository scope
    - Bitbucket: App password with repository read access
    """
    global session
    
    # Check if repository was uploaded
    if session.upload_type != "repository" or not session.repository_url:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Token setting failed",
                "error": "No repository uploaded. Please upload repository first using /upload_repository"
            }
        )
    
    # Check if already have a valid token
    if session.token and not session.is_private:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Token setting failed",
                "error": "Repository is already accessible. Token not needed"
            }
        )
    
    # Validate token format
    is_valid, error = validate_token_format(request.token, session.provider)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Token setting failed",
                "error": error,
                "hint": get_token_format_hint(session.provider)
            }
        )
    
    token = request.token.strip()
    
    # Verify token works with the repository
    result = check_repository(session.repository_url, token, rate_limiter=github_rate_limiter)
    
    if not result["accessible"]:
        # Token didn't work - provide specific error
        return JSONResponse(
            status_code=400,
            content={
                "message": "Token setting failed",
                "error": result["error"],
                "hint": get_token_troubleshooting_hint(session.provider, result["error"])
            }
        )
    
    # Token is valid - update session
    session.token = token
    session.is_private = result.get("is_private", True)
    
    return {
        "message": "Token verified successfully",
        "repo_name": session.repo_name,
        "is_private": session.is_private,
        "next_step": "POST /validate"
    }


# -----------------------------------------------------------------------------
# Helper functions for token hints
# -----------------------------------------------------------------------------
    return "Please verify your token is valid and has the required permissions"


# -----------------------------------------------------------------------------
# 3. POST /upload_zip
# -----------------------------------------------------------------------------
@app.post("/upload_zip", tags=["Upload"])
async def upload_zip(file: UploadFile = File(..., description="ZIP file containing the project folder")):
    """
    Upload a zipped folder for scanning.
    
    The folder should contain manifest files like requirements.txt, package.json, etc.
    
    NOTE: Call /select_source first with source_type='zip_file'
    """
    global session
    
    # Check if source type was selected
    if not session.selected_source_type:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Please select source type first using /select_source"}
        )
    
    # Check if correct source type was selected
    if session.selected_source_type != "zip_file":
        return JSONResponse(
            status_code=400,
            content={
                "message": "Upload failed", 
                "error": f"Source type mismatch. You selected '{session.selected_source_type}' but trying to upload zip. Please call /select_source with source_type='zip_file'"
            }
        )
    
    # Validate file
    if not file:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "No file uploaded. Please select a folder to upload"}
        )
    
    # Check file extension
    filename = file.filename or ""
    if not filename.lower().endswith('.zip'):
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Invalid file type. Please upload a ZIP file"}
        )
    
    # Read file content
    try:
        content = await file.read()
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": f"Failed to read file: {str(e)}"}
        )
    
    # Check file size
    if len(content) > MAX_FOLDER_SIZE:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "File too large. Maximum allowed size is 500MB"}
        )
    
    if len(content) == 0:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Uploaded ZIP file is empty"}
        )
    
    # Create temp directory and extract
    try:
        temp_dir = Path(tempfile.mkdtemp(dir=TEMP_DIR))
        zip_path = temp_dir / "upload.zip"
        
        # Save ZIP file
        with open(zip_path, 'wb') as f:
            f.write(content)
        
        # Extract
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir()
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        except zipfile.BadZipFile:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return JSONResponse(
                status_code=400,
                content={"message": "Upload failed", "error": "Corrupted or invalid ZIP file. Please re-upload"}
            )
        
        # Check if extract_dir has content
        extracted_items = list(extract_dir.iterdir())
        if not extracted_items:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return JSONResponse(
                status_code=400,
                content={"message": "Upload failed", "error": "No project files found in the uploaded folder"}
            )
        
        # If there's only one folder inside, use that as root
        if len(extracted_items) == 1 and extracted_items[0].is_dir():
            extract_dir = extracted_items[0]
        
        # Get folder name from zip filename
        folder_name = filename.replace('.zip', '').replace('.ZIP', '')
        
        # Save session state
        session.upload_type = "folder"
        session.temp_path = extract_dir
        session.repo_name = folder_name
        session.state = ScanState.UPLOADED
        
        return {"message": f"Folder '{folder_name}' uploaded successfully"}
        
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": f"Failed to extract ZIP file: {str(e)}"}
        )


# -----------------------------------------------------------------------------
# 3b. POST /upload_folder - Upload Unzipped Folder (Multiple Files)
# -----------------------------------------------------------------------------
@app.post("/upload_folder", tags=["Upload"])
async def upload_folder(request: Request):
    """
    Upload an unzipped folder for scanning.
    
    Upload all files from a folder - must include manifest files like requirements.txt, package.json, etc.
    
    NOTE: Call /select_source first with source_type='folder'
    
    Use form-data with key 'files' for each file you want to upload.
    """
    global session
    
    # Check if source type was selected
    if not session.selected_source_type:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "Please select source type first using /select_source"}
        )
    
    # Check if correct source type was selected
    if session.selected_source_type != "folder":
        return JSONResponse(
            status_code=400,
            content={
                "message": "Upload failed", 
                "error": f"Source type mismatch. You selected '{session.selected_source_type}' but trying to upload folder. Please call /select_source with source_type='folder'"
            }
        )
    
    # Parse form data to get ALL uploaded files
    try:
        form = await request.form()
        files = []
        for key in form.keys():
            item = form.getlist(key)
            for f in item:
                if hasattr(f, 'filename') and f.filename:
                    files.append(f)
        
        print(f"[DEBUG] Form keys: {list(form.keys())}")
        print(f"[DEBUG] Total files found: {len(files)}")
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": f"Failed to parse form data: {str(e)}"}
        )
    
    # Validate files
    if not files or len(files) == 0:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": "No files uploaded. Please select files to upload"}
        )
    
    # Check file count limit
    if len(files) > MAX_FILES_COUNT:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": f"Too many files. Maximum {MAX_FILES_COUNT} files allowed"}
        )
    
    # Create temp directory
    try:
        temp_dir = Path(tempfile.mkdtemp(dir=TEMP_DIR))
        project_dir = temp_dir / "project"
        project_dir.mkdir()
        
        total_size = 0
        saved_files = []
        manifest_found = False
        
        skipped_files = []
        
        # Debug: Log how many files received
        received_count = len(files) if files else 0
        print(f"[DEBUG] upload_folder received {received_count} files")
        
        for file in files:
            print(f"[DEBUG] Processing file: {file.filename}")
            if not file.filename:
                skipped_files.append({"file": "unknown", "reason": "No filename"})
                continue
            
            # Read file content
            try:
                content = await file.read()
                if not content:
                    skipped_files.append({"file": file.filename, "reason": "Empty file"})
                    continue
            except Exception as e:
                skipped_files.append({"file": file.filename, "reason": f"Read error: {str(e)}"})
                continue
            
            # Check individual file size
            if len(content) > MAX_FILE_SIZE:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return JSONResponse(
                    status_code=400,
                    content={"message": "Upload failed", "error": f"File '{file.filename}' is too large. Maximum 10MB per file"}
                )
            
            total_size += len(content)
            
            # Check total size
            if total_size > MAX_FOLDER_SIZE:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return JSONResponse(
                    status_code=400,
                    content={"message": "Upload failed", "error": "Total upload size exceeds 500MB limit"}
                )
            
            # Preserve folder structure from filename (e.g., "src/utils/helper.py")
            file_path = project_dir / file.filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save file
            with open(file_path, 'wb') as f:
                f.write(content)
            
            saved_files.append(file.filename)
            
            # Check if it's a manifest file
            base_name = os.path.basename(file.filename).lower()
            for manifest_name in get_all_manifest_files():
                if base_name == manifest_name.lower():
                    manifest_found = True
                    break
        
        if not saved_files:
            shutil.rmtree(temp_dir, ignore_errors=True)
            error_msg = "No valid files could be saved"
            if skipped_files:
                error_msg += f". Skipped {len(skipped_files)} file(s): {skipped_files}"
            return JSONResponse(
                status_code=400,
                content={"message": "Upload failed", "error": error_msg}
            )
        
        if not manifest_found:
            supported = ", ".join(get_all_manifest_files())
            # Don't fail - just warn. Validation step will check properly
            pass
        
        # Save session state
        session.upload_type = "files"
        session.temp_path = project_dir
        session.repo_name = "uploaded_project"
        session.uploaded_files = saved_files
        session.state = ScanState.UPLOADED
        
        response = {
            "message": f"Files uploaded successfully",
            "files_count": len(saved_files),
            "files_received": received_count,  # Debug info
            "files": saved_files[:20] if len(saved_files) > 20 else saved_files,  # Show first 20
            "note": f"...and {len(saved_files) - 20} more files" if len(saved_files) > 20 else None
        }
        
        if skipped_files:
            response["skipped_count"] = len(skipped_files)
            response["skipped_files"] = skipped_files
        
        return response
        
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"message": "Upload failed", "error": f"Failed to save files: {str(e)}"}
        )


# -----------------------------------------------------------------------------
# 4. POST /validate
# -----------------------------------------------------------------------------
@app.post("/validate", tags=["Validation"])
def validate():
    """
    Validate the uploaded content and detect ecosystems.
    
    Call this after uploading content to verify it can be scanned.
    Requires: /select_source and upload endpoint to be called first.
    """
    global session
    
    # Check if source type was selected
    if not session.selected_source_type:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Validation failed",
                "error": "Please select source type first using /select_source"
            }
        )
    
    # Check if anything was uploaded
    if session.state == ScanState.IDLE:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Validation failed",
                "error": "Nothing to validate. Please upload repository or folder first using /upload_repository, /upload_zip, or /upload_folder"
            }
        )
    
    # For repository, check if private and no token
    if session.upload_type == "repository":
        if session.is_private and not session.token:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Validation failed",
                    "error": "Repository is private. Please provide token using /set_token"
                }
            )
        
        # Re-verify repository is accessible
        result = check_repository(session.repository_url, session.token, rate_limiter=github_rate_limiter)
        if not result["accessible"]:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Validation failed",
                    "error": result["error"] or "Unable to access repository. Please check URL and try again"
                }
            )
        
        # For repositories, we cannot detect ecosystems without cloning first.
        # The actual ecosystem detection will happen during the scan when the repo is cloned.
        # We return a message indicating this limitation.
        session.state = ScanState.VALIDATED
        
        return {
            "message": "Validation successful. Repository is accessible.",
            "note": "Ecosystem detection will occur during scan when repository is cloned.",
            "ecosystems_detected": [],  # Will be detected during scan after cloning
            "manifest_files": []  # Will be detected during scan after cloning
        }
    
    # For folder or files, detect ecosystems
    if session.temp_path and session.temp_path.exists():
        ecosystems, manifest_files = detect_ecosystems(session.temp_path)
        
        if not manifest_files:
            supported = ", ".join(get_all_manifest_files())
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Validation failed",
                    "error": f"No manifest files found. Supported: {supported}"
                }
            )
        
        if not ecosystems:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Validation failed",
                    "error": "No supported ecosystems detected. Please check manifest files"
                }
            )
        
        session.ecosystems_detected = ecosystems
        session.manifest_files = manifest_files
        session.state = ScanState.VALIDATED
        
        return {
            "message": "Validation successful",
            "ecosystems_detected": ecosystems,
            "manifest_files": manifest_files
        }
    
    return JSONResponse(
        status_code=400,
        content={
            "message": "Validation failed",
            "error": "Uploaded content not found. Please upload again"
        }
    )


# -----------------------------------------------------------------------------
# 5. POST /start_scan - Initialize scan and assign ID
# -----------------------------------------------------------------------------
@app.post("/start_scan", tags=["Scan"])
def start_scan():
    """
    Initialize the scan and assign a scan ID.
    
    This is the entry point after /validate. It:
    - Assigns a unique scan ID
    - Does NOT run any scan step
    
    After this, call the step-by-step endpoints:
    /discover_and_parse → /fetch_depsdev → /registry_enrich → /fetch_osv → /generate_sbom → /generate_remediation
    """
    global session, orchestrator
    
    # Check state
    if session.state == ScanState.IDLE:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Scan initialization failed",
                "error": "Nothing to scan. Please upload repository or folder first"
            }
        )
    
    if session.state == ScanState.UPLOADED:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Scan initialization failed",
                "error": "Please validate first using /validate"
            }
        )
    
    if session.scan_id:
        # Already initialized - return current scan info
        return {
            "message": "Scan already initialized",
            "scan_id": session.scan_id,
            # "state": session.state.value,
            "current_step": session.current_step or "Ready for /discover_and_parse",
            "progress": session.progress
        }
    
    if session.state == ScanState.COMPLETED:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Scan already completed",
                "scan_id": session.scan_id,
                "note": "Use /reset to start a new scan"
            }
        )
    
    try:
        # Get next scan ID
        scan_id = orchestrator.get_next_scan_id()
        
        # Initialize session for step-by-step scanning
        session.scan_id = scan_id
        session.state = ScanState.VALIDATED
        session.progress = 0
        session.current_step = "Scan initialized - ready for /discover_and_parse"
        session.scan_results = {}
        session.scan_timestamp = datetime.now().isoformat()
        
        return {
            "message": "Scan initialized successfully",
            "scan_id": scan_id,
            "next_step": "POST /discover_and_parse",
            "workflow": [
                "/discover_and_parse - Find manifests and extract packages",
                "/fetch_depsdev - Enrich with deps.dev metadata",
                "/registry_enrich - Enrich from PyPI/npm registries",
                "/fetch_osv - Fetch vulnerabilities",
                "/generate_sbom - Generate all SBOM formats",
                "/generate_json- Generate JSON SBOM only",
                "/generate_spdx - Generate SPDX SBOM only",
                "/generate_cyclonedx - Generate CycloneDX SBOM only",
                "/generate_remediation"
            ]
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"message": "Scan initialization failed", "error": str(e)}
        )


# -----------------------------------------------------------------------------
# Step-by-step Scan Endpoints (orchestrator-backed)
# These expose individual pipeline steps so the ScanOrchestrator can be driven
# by the API or by an external orchestration layer. Each endpoint updates the
# global `session` state and writes artifacts under the orchestrator temp/reports dirs.
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Step 1+2 Combined: Discover and Parse Manifests in one step
# -----------------------------------------------------------------------------
@app.post("/discover_and_parse", tags=["ScanSteps"])
def discover_and_parse():
    """
    Step 1+2 Combined: Discover manifests AND parse them in a single call.
    
    Requires: /start_scan to be called first (to get scan ID).
    
    This is a convenience endpoint that combines /discover_manifests and /parse_manifests.
    It will:
    1. Scan the workspace for manifest files (requirements.txt, package.json, etc.)
    2. Parse the manifests to extract package dependencies
    
    If manifests were already discovered, it skips to parsing.
    If packages were already parsed, it returns the existing results.
    """
    global session, orchestrator
    
    # Check if scan was initialized
    if not session.scan_id:
        return JSONResponse(status_code=400, content={
            "message": "Discover and parse failed", 
            "error": "Scan not initialized. Call /start_scan first to get a scan ID"
        })
    
    # Check if already parsed - return existing results
    if session.scan_results and session.scan_results.get("packages"):
        packages = session.scan_results["packages"]
        manifest_details = []
        for m in (session.manifest_files or []):
            if isinstance(m, dict):
                path = m.get("path", m.get("file", ""))
                filename = m.get("file", os.path.basename(str(path)))
            else:
                path = str(m)
                filename = os.path.basename(path)
            ecosystem = get_language_for_manifest(filename) or "unknown"
            manifest_details.append({"file": filename, "ecosystem": ecosystem, "path": path})
        
        # Group packages by ecosystem
        by_ecosystem = {}
        for p in packages:
            eco = p.get("language", "unknown")
            if eco not in by_ecosystem:
                by_ecosystem[eco] = []
            by_ecosystem[eco].append({"name": p.get("name"), "version": p.get("version")})
        
        # Format packages summary (no per-package codebase props)
        packages_summary = [{
            "component_name": p.get("name"),
            "version": p.get("version"),
            "language": p.get("language", "unknown"),
            "is_direct_dependency": p.get("is_direct", True)
        } for p in packages[:15]]
        
        # Get codebase-level properties from first package (all same)
        codebase_props = {"executable": "No", "archive": "No", "structured_properties": "No"}
        if packages:
            codebase_props = {
                "executable": packages[0].get("executable", "No"),
                "archive": packages[0].get("archive", "No"),
                "structured_properties": packages[0].get("structured_properties", "No")
            }
        
        return {
            "message": "Manifests and packages already processed",
            "scan_id": session.scan_id,
            "manifests_found": len(session.manifest_files or []),
            "manifests": manifest_details,
            "packages_found": len(packages),
            "by_ecosystem": {eco: len(pkgs) for eco, pkgs in by_ecosystem.items()},
            "packages": packages_summary if len(packages) <= 15 else packages_summary + [{"note": f"...and {len(packages) - 15} more"}],
            "codebase_properties": codebase_props,
            "next_step": "POST /fetch_depsdev"
        }

    try:
        # Step 1: Prepare workspace if not present
        if not session.temp_path or (isinstance(session.temp_path, (str, Path)) and not Path(session.temp_path).exists()):
            if session.upload_type == "repository":
                workspace = orchestrator.prepare_workspace(
                    source=session.repository_url, 
                    source_type="repo", 
                    scan_id=session.scan_id, 
                    token=session.token
                )
                session.temp_path = workspace
            elif session.upload_type in ("folder", "files"):
                if not session.temp_path:
                    return JSONResponse(status_code=400, content={
                        "message": "Discover and parse failed", 
                        "error": "No workspace available. Please upload a ZIP file first using /upload_zip, then call /start_scan."
                    })
                workspace = Path(session.temp_path) if isinstance(session.temp_path, str) else session.temp_path
            else:
                return JSONResponse(status_code=400, content={
                    "message": "Discover and parse failed", 
                    "error": f"Unsupported upload type: {session.upload_type}. Please call /upload_zip or /start_repo first."
                })
        else:
            if isinstance(session.temp_path, dict):
                return JSONResponse(status_code=400, content={
                    "message": "Discover and parse failed",
                    "error": "Invalid workspace state. Please restart the scan by calling /upload_zip followed by /start_scan."
                })
            workspace = Path(session.temp_path) if isinstance(session.temp_path, str) else session.temp_path

        # Step 2: Discover manifests (if not already done)
        if not session.manifest_files or len(session.manifest_files) == 0:
            manifests = orchestrator.discover_manifests(workspace)
            session.manifest_files = manifests
            session.current_step = "Manifest discovery complete"
            session.progress = 10
        else:
            manifests = session.manifest_files

        # Step 3: Parse manifests and extract packages
        if not workspace.exists():
            return JSONResponse(status_code=400, content={
                "message": "Discover and parse failed", 
                "error": "Workspace not found. Please re-upload and restart the scan."
            })
        
        packages, cataloger_manifests = orchestrator.run_catalogers(workspace)

        # Store results
        session.scan_results = session.scan_results or {}
        session.scan_results["packages"] = packages
        
        # Merge manifest files
        existing_paths = set()
        for m in session.manifest_files:
            if isinstance(m, dict):
                existing_paths.add(m.get("path", m.get("file", "")))
            else:
                existing_paths.add(str(m))
        
        for m in cataloger_manifests:
            path_str = m.get("path", m.get("file", str(m))) if isinstance(m, dict) else str(m)
            if path_str and path_str not in existing_paths:
                existing_paths.add(path_str)
                if isinstance(m, dict):
                    session.manifest_files.append(m)
                else:
                    session.manifest_files.append({"path": str(m), "file": os.path.basename(str(m))})
        
        session.progress = 30
        session.current_step = "Manifest discovery and parsing complete"

        # Format manifest details
        manifest_details = []
        ecosystems_found = set()
        for m in session.manifest_files:
            if isinstance(m, dict):
                path = m.get("path", m.get("file", ""))
                filename = m.get("file", os.path.basename(str(path)))
            else:
                path = str(m)
                filename = os.path.basename(path)
            
            ecosystem = get_language_for_manifest(filename) or "unknown"
            ecosystems_found.add(ecosystem)
            manifest_details.append({"file": filename, "ecosystem": ecosystem, "path": path})

        # Step 4: Detect LICENSE files in repository
        license_info = None
        try:
            from src.utils.license_detector import detect_license_files, get_license_summary_for_sbom
            license_detection = detect_license_files(workspace)
            license_info = get_license_summary_for_sbom(workspace)
            session.repo_license = license_info  # Store for later use in SBOM
        except Exception as e:
            print(f"[WARNING] License detection failed: {e}")
            license_info = {"declared_license": "NOASSERTION", "error": str(e)}

        # Step 5: Scan codebase for executable, archive, structured_properties
        codebase_props = {"executable": "No", "archive": "No", "structured_properties": "No"}
        try:
            packages = orchestrator.scan_codebase_properties(workspace, packages)
            # Update stored packages with codebase properties
            session.scan_results["packages"] = packages
            # Get codebase-level values from the first package (all same)
            if packages:
                codebase_props = {
                    "executable": packages[0].get("executable", "No"),
                    "archive": packages[0].get("archive", "No"),
                    "structured_properties": packages[0].get("structured_properties", "No")
                }
        except Exception as e:
            print(f"[WARNING] Codebase property scanning failed: {e}")

        # Group packages by ecosystem
        by_ecosystem = {}
        for p in packages:
            eco = p.get("language", "unknown")
            if eco not in by_ecosystem:
                by_ecosystem[eco] = []
            by_ecosystem[eco].append({"name": p.get("name"), "version": p.get("version")})
        
        # Format packages for response (show first 15)
        packages_summary = [{
            "component_name": p.get("name"),
            "version": p.get("version"),
            "language": p.get("language", "unknown"),
            "is_direct_dependency": p.get("is_direct", True)
        } for p in packages[:15]]

        return {
            "message": "Manifest discovery and parsing complete",
            "scan_id": session.scan_id,
            "manifests_found": len(session.manifest_files),
            "ecosystems_detected": list(ecosystems_found),
            "manifests": manifest_details,
            "packages_found": len(packages),
            "by_ecosystem": {eco: len(pkgs) for eco, pkgs in by_ecosystem.items()},
            "packages": packages_summary if len(packages) <= 15 else packages_summary + [{"note": f"...and {len(packages) - 15} more"}],
            "codebase_properties": codebase_props,
            "license_detection": license_info,
            "next_step": "POST /fetch_depsdev"
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "Discover and parse failed", "error": str(e)})




# -----------------------------------------------------------------------------
# Step 3: Enrich Metadata (deps.dev) - license, homepage, release_date
# -----------------------------------------------------------------------------
@app.post("/fetch_depsdev", tags=["ScanSteps"])
def fetch_depsdev():
    """
    Step 3: Enrich packages with metadata AND transitive dependencies from deps.dev API.
    
    Requires: /discover_and_parse to be called first (which returns direct dependencies only).
    
    This endpoint:
    1. Fetches transitive dependencies for each direct dependency
    2. Adds metadata (license, homepage, release_date) to all packages
    3. Adds component_dependencies field to each package
    
    Fields fetched from deps.dev:
    - license: Package license (MIT, Apache-2.0, etc.)
    - homepage: Project homepage URL
    - release_date: When this version was released
    - component_dependencies: List of transitive dependencies (PURLs)
    """
    global session, orchestrator
    
    if not session.scan_id:
        return JSONResponse(status_code=400, content={
            "message": "Enrich failed", 
            "error": "Scan not initialized. Call /start_scan first"
        })
    
    if not session.scan_results or not session.scan_results.get("packages"):
        return JSONResponse(status_code=400, content={
            "message": "Enrich failed", 
            "error": "No packages found. Run /discover_and_parse first"
        })

    try:
        packages = session.scan_results.get("packages")
        direct_count = len(packages)
        
        # Track what we're about to fetch
        print(f"[deps.dev] Fetching metadata and transitive dependencies for {direct_count} direct dependencies...")
        
        # Step 1: Fetch transitive dependencies and add them to the package list
        from src.clients.depsdev_client import get_client
        client = get_client()
        
        transitive_packages = []
        seen_packages = set()  # Track seen packages to avoid duplicates
        
        # Mark direct dependencies
        for p in packages:
            p["is_direct_dependency"] = True
            key = f"{p.get('name')}@{p.get('version')}"
            seen_packages.add(key.lower())
        
        # Fetch transitive dependencies for each direct dependency
        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            lang = (pkg.get("language") or pkg.get("ecosystem") or "").lower()
            
            if not name or not version:
                continue
            
            # Map language to deps.dev ecosystem
            ecosystem = get_purl_type(lang)
            
            try:
                dep_graph = client.get_dependency_graph(ecosystem, name, version)
                
                # Add component_dependencies field (PURL format)
                all_deps = dep_graph.get("direct", []) + dep_graph.get("transitive", [])
                component_deps = []
                
                for dep in all_deps:
                    dep_name = dep.get("name")
                    dep_version = dep.get("version", "unknown")
                    key = f"{dep_name}@{dep_version}"
                    
                    # Add to component_dependencies as PURL
                    purl = f"pkg:{ecosystem}/{dep_name}@{dep_version}"
                    component_deps.append(purl)
                    
                    # Add transitive package if not already seen
                    if key.lower() not in seen_packages:
                        seen_packages.add(key.lower())
                        transitive_packages.append({
                            "name": dep_name,
                            "version": dep_version,
                            "language": lang,
                            "ecosystem": ecosystem,
                            "is_direct_dependency": False,
                            "parent_package": name
                        })
                
                pkg["component_dependencies"] = component_deps
                pkg["total_dependencies"] = len(component_deps)
                
            except Exception as e:
                print(f"[WARN] Failed to fetch deps for {name}@{version}: {e}")
                pkg["component_dependencies"] = []
                pkg["total_dependencies"] = 0
        
        # Add transitive packages to the list
        packages.extend(transitive_packages)
        
        # Step 2: Enrich all packages with metadata
        packages = orchestrator.enrich_metadata(packages)
        session.scan_results["packages"] = packages
        session.progress = 40
        session.current_step = "deps.dev enrichment complete"

        # Build complete package list with deps.dev fields
        depsdev_count = 0
        fallback_count = 0
        all_packages = []
        
        for p in packages:
            source = p.get("metadata_source", "").lower()
            if source == "deps.dev":
                depsdev_count += 1
            else:
                fallback_count += 1
            
            comp_deps = p.get("component_dependencies", [])
            is_direct = p.get("is_direct_dependency", p.get("is_direct", True))
            all_packages.append({
                "component_name": p.get("name"),
                "version": p.get("version"),
                "is_direct_dependency": is_direct,
                "dependency_type": "direct" if is_direct else "transitive",
                "component_license": p.get("license", "N/A"),
                "homepage": p.get("homepage", "N/A"),
                "release_date": p.get("release_date", "N/A"),
                "component_dependencies": comp_deps
            })

        return {
            "message": "deps.dev metadata and transitive dependencies fetched",
            "scan_id": session.scan_id,
            "direct_dependencies": direct_count,
            "transitive_dependencies_added": len(transitive_packages),
            "total_packages": len(packages),
            "successfully_enriched": depsdev_count,
            "not_found_in_depsdev": fallback_count,
            "fields_added": ["component_license", "homepage", "release_date", "component_dependencies"],
            "packages": all_packages,
            "next_step": "POST /registry_enrich"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=400, content={"message": "Enrich failed", "error": str(e)})


# --------------------------------------------------hi---------------------------
# Step 9: Registry Enrichment - description, supplier, hashes, executable, etc.
# -----------------------------------------------------------------------------
@app.post("/registry_enrich", tags=["ScanSteps"])
def registry_enrich():
    """
    Step 4: Enrich packages with registry data (PyPI/npm APIs).
    
    Requires: /fetch_depsdev to be called first.
    
    Fields fetched from PyPI/npm registries (deps.dev doesn't have these):
    - component_description: Package summary/description
    - component_supplier: Package author/maintainer
    - hashes: SHA-256/SHA-512 checksums for integrity
    - unique_identifier: PURL format identifier
    """
    global session, orchestrator
    
    if not session.scan_id:
        return JSONResponse(status_code=400, content={
            "message": "Registry enrich failed", 
            "error": "Scan not initialized. Call /start_scan first"
        })
    
    if not session.scan_results or not session.scan_results.get("packages"):
        return JSONResponse(status_code=400, content={
            "message": "Registry enrich failed", 
            "error": "No packages found. Run /parse_manifests first"
        })

    try:
        packages = session.scan_results["packages"]
        original_count = len(packages)
        
        print(f"[registry] Fetching registry data for {original_count} packages...")
        
        # Use orchestrator's registry_enrich method
        packages = orchestrator.registry_enrich(packages)
        
        session.scan_results["packages"] = packages
        session.progress = 50
        session.current_step = "Registry enrichment complete"
        
        # Build complete package list with registry fields
        pypi_count = 0
        npm_count = 0
        all_packages = []
        
        def format_hashes(hashes_data):
            """Format hashes for display - handles both list and dict formats."""
            if not hashes_data:
                return []
            if isinstance(hashes_data, dict):
                return [{"alg": k, "content": v} for k, v in hashes_data.items()]
            if isinstance(hashes_data, list):
                result = []
                for h in hashes_data:
                    if isinstance(h, dict):
                        result.append({"alg": h.get("alg", h.get("algorithm", "unknown")), "content": h.get("content", h.get("hash", ""))})
                    else:
                        result.append({"alg": "unknown", "content": str(h)})
                return result
            return []
        
        for p in packages:
            lang = (p.get("language") or "").lower()
            if lang in ["python", "pip"]:
                pypi_count += 1
                registry = "PyPI"
            elif lang in ["javascript", "npm", "node"]:
                npm_count += 1
                registry = "npm"
            else:
                registry = "unknown"
            
            is_direct = p.get("is_direct_dependency", p.get("is_direct", True))
            all_packages.append({
                "component_name": p.get("name"),
                "version": p.get("version"),
                "is_direct_dependency": is_direct,
                "dependency_type": "direct" if is_direct else "transitive",
                "registry": registry,
                "component_description": p.get("description", "N/A"),
                "component_supplier": p.get("supplier", "N/A"),
                "hashes": format_hashes(p.get("hashes")),
                "unique_identifier": p.get("unique_identifier", p.get("purl", f"pkg:{registry.lower()}/{p.get('name')}@{p.get('version')}"))
            })

        return {
            "message": "Registry enrichment complete",
            "scan_id": session.scan_id,
            "packages_processed": original_count,
            "by_registry": {
                "PyPI": pypi_count,
                "npm": npm_count
            },
            "fields_added": ["component_description", "component_supplier", "hashes", "unique_identifier"],
            "packages": all_packages,
            "next_step": "POST /fetch_osv"
        }
        
    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "Registry enrich failed", "error": str(e)})


# -----------------------------------------------------------------------------
# Step 5: Fetch Vulnerabilities (OSV/NVD)
# -----------------------------------------------------------------------------
@app.post("/fetch_osv", tags=["ScanSteps"]) 
def fetch_osv():
    """
    Step 5: Fetch vulnerabilities from OSV database.
    
    Requires: /registry_enrich to be called first.
    
    Fields fetched from OSV:
    - vulnerabilities: List of CVEs/advisories with id, severity, severity_level, summary, fixed_in, url, aliases, details
    
    Derived fields (computed from vulnerabilities):
    - patch_status: Whether a fix is available (patched/unpatched)
    - criticality: Overall risk level based on severity
    """
    global session, orchestrator
    
    if not session.scan_id:
        return JSONResponse(status_code=400, content={
            "message": "Vulnerability fetch failed", 
            "error": "Scan not initialized. Call /start_scan first"
        })
    
    if not session.scan_results or not session.scan_results.get("packages"):
        return JSONResponse(status_code=400, content={
            "message": "Vulnerability fetch failed", 
            "error": "No packages found. Run /parse_manifests first"
        })

    try:
        packages = session.scan_results.get("packages")
        original_count = len(packages)
        
        print(f"[OSV] Checking {original_count} packages for vulnerabilities...")
        
        # Fetch vulnerabilities from OSV/NVD
        packages, vuln_count = orchestrator.fetch_vulnerabilities(packages)
        
        session.scan_results["packages"] = packages
        session.vulnerabilities = []
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        # Build package-wise vulnerability structure (like in reports)
        vulnerable_packages = []
        
        for p in packages:
            pkg_vulns = p.get("vulnerabilities", [])
            if not pkg_vulns:
                continue
            
            pkg_name = p.get("name", "unknown")
            pkg_version = p.get("version", "unknown")
            
            # Build vulnerability list for this package
            vuln_list = []
            for v in pkg_vulns:
                # Derive patch_status
                fixed_version = v.get("fixed_in", "")
                patch_status = "patched" if fixed_version and fixed_version != "Unknown" else "unpatched"
                
                # Derive criticality
                severity_level = v.get("severity_level", "UNKNOWN").upper()
                criticality_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
                criticality = criticality_map.get(severity_level, "unknown")
                
                vuln_record = {
                    "id": v.get("id", "Unknown"),
                    "severity": v.get("severity", "UNKNOWN"),
                    "severity_level": severity_level,
                    "summary": v.get("summary", "No summary"),
                    "details": v.get("details", "No details"),
                    "fixed_in": fixed_version or "Unknown",
                    "url": v.get("url", ""),
                    "aliases": v.get("aliases", []),
                    "patch_status": patch_status,
                    "criticality": criticality
                }
                vuln_list.append(vuln_record)
                session.vulnerabilities.append({**vuln_record, "package": pkg_name, "version": pkg_version})
                
                if severity_level in severity_breakdown:
                    severity_breakdown[severity_level] += 1
                else:
                    severity_breakdown["UNKNOWN"] += 1
            
            # Add package with its vulnerabilities
            vulnerable_packages.append({
                "component_name": pkg_name,
                "version": pkg_version,
                "vulnerabilities": vuln_list
            })

        session.progress = 60
        session.current_step = "Vulnerability scan complete"

        return {
            "message": "Vulnerability scan complete",
            "scan_id": session.scan_id,
            "packages_scanned": original_count,
            "packages_affected": len(vulnerable_packages),
            "vulnerabilities_found": len(session.vulnerabilities),
            "severity_breakdown": severity_breakdown,
            "fields_fetched": ["id", "severity", "severity_level", "summary", "fixed_in", "url", "aliases", "details"],
            "fields_derived": ["patch_status", "criticality"],
            "vulnerable_packages": vulnerable_packages,
            "next_step": "POST /generate_json (or /generate_spdx, /generate_cyclonedx)"
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "Vulnerability fetch failed", "error": str(e)})


@app.post("/generate_sbom", tags=["ScanSteps"]) 
def generate_sbom():
    """
    Step 19: Generate all SBOM reports (JSON, SPDX, CycloneDX) at once.
    
    This is a convenience endpoint that generates all formats.
    If you've already generated individual formats using /generate_json, /generate_spdx, 
    or /generate_cyclonedx, this will skip those and only generate missing ones.
    """
    global session, orchestrator
    if not session.scan_id or not session.scan_results:
        return JSONResponse(status_code=400, content={"message": "SBOM generation failed", "error": "Missing scan context. Run previous steps first"})

    try:
        scan_id = session.scan_id
        packages = session.scan_results.get("packages", [])
        manifests = session.manifest_files or []
        project_name = session.repo_name or f"project_{scan_id}"

        # Check which reports already exist
        output_dir = Path(orchestrator.reports_dir) / scan_id
        json_path = output_dir / f"{scan_id}.json.json"
        spdx_path = output_dir / f"{scan_id}.spdx.json"
        cyclonedx_path = output_dir / f"{scan_id}.cyclonedx.json"
        remediation_path = output_dir / f"{scan_id}_remediation.json"
        
        already_exists = []
        to_generate = []
        
        if json_path.exists() and session.sbom_files.get("json"):
            already_exists.append("json")
        else:
            to_generate.append("json")
            
        if spdx_path.exists() and session.sbom_files.get("spdx"):
            already_exists.append("spdx")
        else:
            to_generate.append("spdx")
            
        if cyclonedx_path.exists() and session.sbom_files.get("cyclonedx"):
            already_exists.append("cyclonedx")
        else:
            to_generate.append("cyclonedx")

        if remediation_path.exists() and session.sbom_files.get("remediation"):
            already_exists.append("remediation")
        else:
            to_generate.append("remediation")

        # If all already exist, return message
        if not to_generate:
            return {
                "message": "All SBOM reports already exist",
                "scan_id": scan_id,
                "already_generated": already_exists,
                "reports": {
                    "json": str(json_path),
                    "spdx": str(spdx_path),
                    "cyclonedx": str(cyclonedx_path),
                    "remediation": str(remediation_path)
                },
                "note": "Files were generated previously. Use /download to get the files."
            }

        # Build catalog if not exists
        if not session.scan_results.get("catalog"):
            catalog = orchestrator.build_catalog(packages=packages, manifests=manifests, project_name=project_name, source=session.repository_url or project_name, scan_id=scan_id)
            session.scan_results["catalog"] = catalog
        else:
            catalog = session.scan_results["catalog"]

        # Generate only the missing formats
        output_dir.mkdir(parents=True, exist_ok=True)
        newly_generated = []
        
        from src.core.sbom_generator import generate_json_sbom, generate_spdx_sbom, generate_cyclonedx_sbom, generate_remediation_sbom
        
        metadata = {
            "timestamp": catalog.get("timestamp"),
            "tool": catalog.get("tool", {}),
            "source": catalog.get("source"),
            "scan_id": scan_id
        }
        
        if "json" in to_generate:
            json_sbom = generate_json_sbom(catalog, metadata)
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_sbom, f, indent=2, ensure_ascii=False)
            session.sbom_files["json"] = str(json_path)
            newly_generated.append("json")
        
        if "spdx" in to_generate:
            spdx_sbom = generate_spdx_sbom(catalog, metadata)
            with open(spdx_path, 'w', encoding='utf-8') as f:
                json.dump(spdx_sbom, f, indent=2, ensure_ascii=False)
            session.sbom_files["spdx"] = str(spdx_path)
            newly_generated.append("spdx")
        
        if "cyclonedx" in to_generate:
            cyclonedx_sbom = generate_cyclonedx_sbom(catalog, metadata)
            with open(cyclonedx_path, 'w', encoding='utf-8') as f:
                json.dump(cyclonedx_sbom, f, indent=2, ensure_ascii=False)
            session.sbom_files["cyclonedx"] = str(cyclonedx_path)
            newly_generated.append("cyclonedx")
        
        if "remediation" in to_generate:
            remediation_sbom = generate_remediation_sbom(catalog, metadata)
            with open(remediation_path, 'w', encoding='utf-8') as f:
                json.dump(remediation_sbom, f, indent=2, ensure_ascii=False)
            session.sbom_files["remediation"] = str(remediation_path)
            newly_generated.append("remediation")

        session.progress = 90
        session.current_step = "SBOM reports generated"
        session.state = ScanState.COMPLETED
        
        # Count vulnerabilities for summary
        total_vulns = len(session.vulnerabilities) if session.vulnerabilities else 0
        
        cleanup_temp_workspace(session.temp_path, TEMP_DIR)

        return {
            "message": "SBOM generation complete",
            "scan_id": scan_id,
            "project_name": project_name,
            "newly_generated": newly_generated,
            "already_existed": already_exists,
            "scan_summary": {
                "total_components": len(packages),
                "total_vulnerabilities": total_vulns,
                "ecosystems": session.ecosystems_detected
            },
            "reports": {
                "json": str(json_path),
                "spdx": str(spdx_path),
                "cyclonedx": str(cyclonedx_path),
                "remediation": str(remediation_path)
            },
            "next_step": "Call /download to get files"
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "SBOM generation failed", "error": str(e)})


# -----------------------------------------------------------------------------
# Step 6a: Generate JSON SBOM Only
# -----------------------------------------------------------------------------
@app.post("/generate_json", tags=["ScanSteps"]) 
def generate_json_sbom():
    """Step 6a: Generate JSON SBOM format only"""
    global session, orchestrator
    if not session.scan_id or not session.scan_results:
        return JSONResponse(status_code=400, content={"message": "JSON generation failed", "error": "Missing scan context. Run previous steps first"})

    try:
        scan_id = session.scan_id
        
        # Check if JSON SBOM already exists
        output_dir = Path(orchestrator.reports_dir) / scan_id
        json_path = output_dir / f"{scan_id}.json.json"
        
        if json_path.exists() and session.sbom_files.get("json"):
            # Read and return full content
            with open(json_path, 'r', encoding='utf-8') as f:
                report_content = json.load(f)
            return {
                "message": "JSON SBOM already exists",
                "scan_id": scan_id,
                "report_path": str(json_path),
                "report": report_content
            }
        
        packages = session.scan_results.get("packages", [])
        manifests = session.manifest_files or []
        project_name = session.repo_name or f"project_{scan_id}"

        # Build catalog if not exists
        if not session.scan_results.get("catalog"):
            catalog = orchestrator.build_catalog(packages=packages, manifests=manifests, project_name=project_name, source=session.repository_url or project_name, scan_id=scan_id)
            session.scan_results["catalog"] = catalog
        else:
            catalog = session.scan_results["catalog"]

        # Generate only JSON format
        from src.core.sbom_generator import generate_json_sbom
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        metadata = {
            "timestamp": catalog.get("timestamp"),
            "tool": catalog.get("tool", {}),
            "source": catalog.get("source"),
            "scan_id": scan_id
        }
        
        json_sbom = generate_json_sbom(catalog, metadata)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_sbom, f, indent=2, ensure_ascii=False)
        
        session.sbom_files["json"] = str(json_path)
        
        return {
            "message": "JSON SBOM generated",
            "scan_id": scan_id,
            "report_path": str(json_path),
            "report": json_sbom
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "JSON generation failed", "error": str(e)})


# -----------------------------------------------------------------------------
# Step 6b: Generate SPDX SBOM Only
# -----------------------------------------------------------------------------
@app.post("/generate_spdx", tags=["ScanSteps"]) 
def generate_spdx_sbom():
    """Step 6b: Generate SPDX SBOM format only"""
    global session, orchestrator
    if not session.scan_id or not session.scan_results:
        return JSONResponse(status_code=400, content={"message": "SPDX generation failed", "error": "Missing scan context. Run previous steps first"})

    try:
        scan_id = session.scan_id
        
        # Check if SPDX SBOM already exists
        output_dir = Path(orchestrator.reports_dir) / scan_id
        spdx_path = output_dir / f"{scan_id}.spdx.json"
        
        if spdx_path.exists() and session.sbom_files.get("spdx"):
            # Read and return full content
            with open(spdx_path, 'r', encoding='utf-8') as f:
                report_content = json.load(f)
            return {
                "message": "SPDX SBOM already exists",
                "scan_id": scan_id,
                "report_path": str(spdx_path),
                "report": report_content
            }
        
        packages = session.scan_results.get("packages", [])
        manifests = session.manifest_files or []
        project_name = session.repo_name or f"project_{scan_id}"

        # Build catalog if not exists
        if not session.scan_results.get("catalog"):
            catalog = orchestrator.build_catalog(packages=packages, manifests=manifests, project_name=project_name, source=session.repository_url or project_name, scan_id=scan_id)
            session.scan_results["catalog"] = catalog
        else:
            catalog = session.scan_results["catalog"]

        # Generate only SPDX format
        from src.core.sbom_generator import generate_spdx_sbom
        
        output_dir = Path(orchestrator.reports_dir) / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        metadata = {
            "timestamp": catalog.get("timestamp"),
            "tool": catalog.get("tool", {}),
            "source": catalog.get("source"),
            "scan_id": scan_id
        }
        
        spdx_sbom = generate_spdx_sbom(catalog, metadata)
        spdx_path = output_dir / f"{scan_id}.spdx.json"
        with open(spdx_path, 'w', encoding='utf-8') as f:
            json.dump(spdx_sbom, f, indent=2, ensure_ascii=False)
        
        session.sbom_files["spdx"] = str(spdx_path)
        
        return {
            "message": "SPDX SBOM generated",
            "scan_id": scan_id,
            "report_path": str(spdx_path),
            "report": spdx_sbom
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "SPDX generation failed", "error": str(e)})


# -----------------------------------------------------------------------------
# Step 6c: Generate CycloneDX SBOM Only
# -----------------------------------------------------------------------------
@app.post("/generate_cyclonedx", tags=["ScanSteps"]) 
def generate_cyclonedx_sbom():
    """Step 6c: Generate CycloneDX SBOM format only"""
    global session, orchestrator
    if not session.scan_id or not session.scan_results:
        return JSONResponse(status_code=400, content={"message": "CycloneDX generation failed", "error": "Missing scan context. Run previous steps first"})

    try:
        scan_id = session.scan_id
        
        # Check if CycloneDX SBOM already exists
        output_dir = Path(orchestrator.reports_dir) / scan_id
        cyclonedx_path = output_dir / f"{scan_id}.cyclonedx.json"
        
        if cyclonedx_path.exists() and session.sbom_files.get("cyclonedx"):
            # Read and return full content
            with open(cyclonedx_path, 'r', encoding='utf-8') as f:
                report_content = json.load(f)
            return {
                "message": "CycloneDX SBOM already exists",
                "scan_id": scan_id,
                "report_path": str(cyclonedx_path),
                "report": report_content
            }
        packages = session.scan_results.get("packages", [])
        manifests = session.manifest_files or []
        project_name = session.repo_name or f"project_{scan_id}"

        # Build catalog if not exists
        if not session.scan_results.get("catalog"):
            catalog = orchestrator.build_catalog(packages=packages, manifests=manifests, project_name=project_name, source=session.repository_url or project_name, scan_id=scan_id)
            session.scan_results["catalog"] = catalog
        else:
            catalog = session.scan_results["catalog"]

        # Generate only CycloneDX format
        from src.core.sbom_generator import generate_cyclonedx_sbom
        
        output_dir = Path(orchestrator.reports_dir) / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        metadata = {
            "timestamp": catalog.get("timestamp"),
            "tool": catalog.get("tool", {}),
            "source": catalog.get("source"),
            "scan_id": scan_id
        }
        
        cyclonedx_sbom = generate_cyclonedx_sbom(catalog, metadata)
        cyclonedx_path = output_dir / f"{scan_id}.cyclonedx.json"
        with open(cyclonedx_path, 'w', encoding='utf-8') as f:
            json.dump(cyclonedx_sbom, f, indent=2, ensure_ascii=False)
        
        session.sbom_files["cyclonedx"] = str(cyclonedx_path)
        
        return {
            "message": "CycloneDX SBOM generated",
            "scan_id": scan_id,
            "report_path": str(cyclonedx_path),
            "report": cyclonedx_sbom
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "CycloneDX generation failed", "error": str(e)})


# -----------------------------------------------------------------------------
# Step 7: Generate Remediation Report (Final Step)
# -----------------------------------------------------------------------------
@app.post("/generate_remediation", tags=["ScanSteps"]) 
def generate_remediation():
    """Step 7: Generate remediation report (Final step - marks scan as COMPLETED)"""
    global session, orchestrator
    if not session.scan_id or not session.scan_results or not session.scan_results.get("catalog"):
        return JSONResponse(status_code=400, content={"message": "Remediation generation failed", "error": "Missing catalog. Run /generate_sbom first"})

    try:
        scan_id = session.scan_id
        
        # Check if remediation report already exists
        output_dir = Path(orchestrator.reports_dir) / scan_id
        remediation_path = output_dir / f"{scan_id}_remediation.json"
        
        if remediation_path.exists() and session.remediation_path:
            # Read and return full content
            with open(remediation_path, 'r', encoding='utf-8') as f:
                report_content = json.load(f)
            return {
                "message": "Remediation report already exists",
                "scan_id": scan_id,
                "report_path": str(remediation_path),
                "report": report_content
            }
        
        catalog = session.scan_results.get("catalog")
        remediation_file = orchestrator.generate_remediation_report(catalog, scan_id, session.repository_url or "local")
        session.remediation_path = remediation_file
        
        # Build remediation list for GET /remediation endpoint
        packages = catalog.get("packages", [])
        remediation_list = []
        seen_packages = set()
        
        for pkg in packages:
            vulns = pkg.get("vulnerabilities", [])
            if not vulns:
                continue
                
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            pkg_key = f"{pkg_name}@{pkg_version}"
            
            if pkg_key in seen_packages:
                continue
            seen_packages.add(pkg_key)
            
            # Get first vuln for severity info
            first_vuln = vulns[0] if vulns else {}
            severity_level = first_vuln.get("severity_level", "UNKNOWN").upper()
            
            # Determine urgency based on severity
            urgency = "STANDARD"
            if severity_level == "CRITICAL":
                urgency = "IMMEDIATE"
            elif severity_level == "HIGH":
                urgency = "HIGH"
            elif severity_level == "MEDIUM":
                urgency = "STANDARD"
            
            # Get fixed version
            fixed_in = "Unknown"
            for v in vulns:
                if v.get("fixed_in") and v.get("fixed_in") != "Unknown":
                    fixed_in = v.get("fixed_in")
                    break
            
            remediation_list.append({
                "package": pkg_name,
                "current_version": pkg_version,
                "fix_version": fixed_in,
                "severity": first_vuln.get("severity", "Unknown"),
                "severity_level": severity_level,
                "urgency": urgency,
                "action": f"Upgrade to version {fixed_in} or later" if fixed_in != "Unknown" else "Review and update to latest secure version",
                "cves_fixed": [v.get("id") for v in vulns if v.get("id")]
            })
        
        # Sort by urgency
        urgency_order = {"IMMEDIATE": 0, "URGENT": 1, "HIGH": 2, "STANDARD": 3}
        remediation_list.sort(key=lambda x: urgency_order.get(x.get("urgency", "STANDARD"), 3))
        
        session.remediation = remediation_list
        
        # Also mark scan as completed since this is the final step in step-by-step workflow
        session.progress = 100
        session.state = ScanState.COMPLETED
        session.current_step = "Scan completed"

        # Read the generated remediation file for full content
        remediation_content = None
        if remediation_file and Path(remediation_file).exists():
            with open(remediation_file, 'r', encoding='utf-8') as f:
                remediation_content = json.load(f)

        cleanup_temp_workspace(session.temp_path, TEMP_DIR)

        return {
            "message": "Remediation report generated - Scan complete",
            "scan_id": scan_id,
            "report_path": str(remediation_path),
            "total_actions": len(remediation_list),
            "report": remediation_content
        }

    except Exception as e:
        return JSONResponse(status_code=400, content={"message": "Remediation generation failed", "error": str(e)})


# NOTE: /generate_executive_summary endpoint REMOVED - executive summary not needed




# =============================================================================
# Run with: uvicorn main:app --port 8000
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
