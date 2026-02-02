"""
AIBOM Endpoints - FastAPI Application
Main entry point containing all endpoint definitions
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List
from collections import defaultdict
from fastapi import FastAPI, File, UploadFile, Form, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Import from modules
from config import ENDPOINT_MAP, CODE_FILE_EXTENSIONS
from models import (
    SourceTypeRequest, SourceTypeResponse, FilesResponse, CodeTokensResponse,
    PackagesResponse, SemgrepScanResponse, FilteredImportsResponse, LLMValidationResponse,
    CategorizationResponse, CategorizedLibrary, CategoryGroup,
    ResolvePackagesResponse, UnifiedPackage, ResolutionSummary,
    DependencyGraphResponse, GraphNode, GraphEdge, GraphMetadata,
    AIBranchTraceResponse, AIBranch, BranchSummaryItem, BranchTraceSummary, CategoryStats,
    RepoPublicRequest, RepoPrivateRequest
)
from session import (
    create_session,
    get_session,
    update_session,
    require_source_type,
    require_validated_session,
    SessionData
)
from validate import (
    validate_github_repo,
    validate_zip_upload,
    validate_local_upload,
    cleanup_temp_dir,
    get_temp_dir
)


# =============================================================================
# APP LIFECYCLE
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown - cleanup temp directory
    cleanup_temp_dir()


app = FastAPI(
    title="AIBOM API",
    description="AI Bill of Materials Generator API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware - Must be added before any routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# =============================================================================
# ROOT & HEALTH ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    return {"message": "AIBOM API is running", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# =============================================================================
# 1. SOURCE TYPE ENDPOINT - Entry point, unlocks respective validate endpoint
# =============================================================================

@app.post("/source_type", response_model=SourceTypeResponse)
async def set_source_type(request: SourceTypeRequest):
    """
    Set the source type for this session. This determines which validate endpoint is available.
    
    **Source Types:**
    - `repo_public`: Public GitHub repository (no PAT required)
    - `repo_private`: Private GitHub repository (PAT required)  
    - `zip`: ZIP file upload
    - `local`: Local folder/files upload
    
    **Returns:** A session token to use in subsequent requests via the `session-token` header.
    """
    token = create_session(request.source_type)
    
    unlocked = ENDPOINT_MAP[request.source_type]
    locked = [ep for k, ep in ENDPOINT_MAP.items() if k != request.source_type]
    
    return SourceTypeResponse(
        message=f"Source type '{request.source_type}' set successfully.",
        session_token=token,
        source_type=request.source_type,
        unlocked_endpoint=unlocked,
        locked_endpoints=locked
    )


# =============================================================================
# 2. VALIDATE ENDPOINTS - Locked based on source_type
# =============================================================================

@app.post("/validate/repo_public")
async def validate_public_repo_endpoint(
    request: RepoPublicRequest,
    _: str = Depends(require_source_type("repo_public")),
    session_token: str = Header(...)
):
    """
    Validate a **public** GitHub repository.
    
    **Requires:** `source_type = "repo_public"` set via /source_type
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Body (JSON):**
    ```json
    {
        "repo_url": "https://github.com/owner/repo"
    }
    ```
    """
    result = await validate_github_repo(repo_url=request.repo_url, repo_type="public", pat=None)
    
    # Update session with validated path
    update_session(
        session_token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True
    )
    
    return result


@app.post("/validate/repo_private")
async def validate_private_repo_endpoint(
    request: RepoPrivateRequest,
    _: str = Depends(require_source_type("repo_private")),
    session_token: str = Header(...)
):
    """
    Validate a **private** GitHub repository.
    
    **Requires:** `source_type = "repo_private"` set via /source_type
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Body (JSON):**
    ```json
    {
        "repo_url": "https://github.com/owner/repo",
        "pat": "ghp_xxxxxxxxxxxx"
    }
    ```
    """
    result = await validate_github_repo(repo_url=request.repo_url, repo_type="private", pat=request.pat)
    
    # Update session with validated path
    update_session(
        session_token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True
    )
    
    return result


@app.post("/validate/zip")
async def validate_zip_endpoint(
    file: UploadFile = File(..., description="ZIP file to upload"),
    _: str = Depends(require_source_type("zip")),
    session_token: str = Header(...)
):
    """
    Validate and extract an uploaded **ZIP file**.
    
    **Requires:** `source_type = "zip"` set via /source_type
    
    **Headers:** `session-token: <token from /source_type>`
    """
    result = await validate_zip_upload(file)
    
    # Update session with validated path
    update_session(
        session_token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True
    )
    
    return result


@app.post("/validate/local")
async def validate_local_endpoint(
    files: List[UploadFile] = File(..., description="Files/folder to upload"),
    _: str = Depends(require_source_type("local")),
    session_token: str = Header(...)
):
    """
    Validate uploaded **local files/folder**.
    
    **Requires:** `source_type = "local"` set via /source_type
    
    **Headers:** `session-token: <token from /source_type>`
    """
    result = await validate_local_upload(files)
    
    # Update session with validated path
    update_session(
        session_token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True
    )
    
    return result


# =============================================================================
# 3. FILES ENDPOINT - List all files in validated source
# =============================================================================

@app.get("/files", response_model=FilesResponse)
async def list_files(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    List all files in the validated source.
    
    **Requires:** Completed validation via one of the /validate/* endpoints.
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** List of all file paths relative to the source root, grouped by extension.
    """
    # Get absolute path from session's relative path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    source_path = os.path.join(base_dir, session.local_path)
    
    if not os.path.exists(source_path):
        from errors import raise_error
        raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404,
                    hint="The source may have been cleaned up. Please validate again.")
    
    # Collect all files
    all_files = []
    by_extension = defaultdict(list)
    
    skip_dirs = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git'}
    
    for root, dirs, files in os.walk(source_path):
        # Skip hidden and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_dirs]
        
        for file in files:
            if file.startswith('.'):
                continue
            
            # Get relative path from source root
            abs_path = os.path.join(root, file)
            rel_path = os.path.relpath(abs_path, source_path).replace("\\", "/")
            
            all_files.append(rel_path)
            
            # Group by extension
            ext = os.path.splitext(file)[1].lower() or "(no extension)"
            by_extension[ext].append(rel_path)
    
    # Store files list in session for next endpoints
    update_session(session_token, files_list=all_files)
    
    return FilesResponse(
        total_files=len(all_files),
        files=sorted(all_files),
        by_extension=dict(by_extension)
    )


# =============================================================================
# 4. CODE TOKENS ENDPOINT - Extract folder/file names from code files
# =============================================================================

@app.get("/code_tokens", response_model=CodeTokensResponse)
async def extract_code_tokens(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Extract code tokens (folder names and file stems) from source code files.
    
    These tokens are used to filter out local/internal imports from third-party imports.
    Only processes files with recognized code extensions (.py, .js, .ts, etc.).
    
    **Requires:** Completed /files endpoint call (files_list in session).
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** 
    - `tokens`: Unique set of folder names and file stems (without extension)
    - `token_count`: Number of unique tokens
    """
    # Check if files_list is in session
    files_list = session.extra.get("files_list")
    
    if not files_list:
        # If not cached, get files directly
        base_dir = os.path.dirname(os.path.abspath(__file__))
        source_path = os.path.join(base_dir, session.local_path)
        
        if not os.path.exists(source_path):
            from errors import raise_error
            raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404)
        
        files_list = []
        skip_dirs = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git'}
        
        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_dirs]
            for file in files:
                if not file.startswith('.'):
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, source_path).replace("\\", "/")
                    files_list.append(rel_path)
    
    # Extract tokens from code files only
    tokens = set()
    code_files_processed = 0
    
    for file_path in files_list:
        ext = Path(file_path).suffix.lower()
        if ext not in CODE_FILE_EXTENSIONS:
            continue
        
        code_files_processed += 1
        parts = Path(file_path).parts
        
        # Add folder names (all parts except the last one which is the filename)
        for part in parts[:-1]:
            tokens.add(part)
        
        # Add file stem (name without extension)
        tokens.add(Path(file_path).stem)
    
    sorted_tokens = sorted(tokens)
    
    # Store tokens in session for next endpoints (import filtering)
    update_session(session_token, code_tokens=sorted_tokens)
    
    return CodeTokensResponse(
        token_count=len(sorted_tokens),
        tokens=sorted_tokens,
        code_files_processed=code_files_processed
    )


# =============================================================================
# 5. PACKAGES ENDPOINT - Detect languages and dependencies
# =============================================================================

@app.get("/packages", response_model=PackagesResponse)
async def analyze_packages(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Detect programming languages and extract dependencies from manifest files.
    
    Matches the orchestrator's write_packages_report function:
    - Detects languages (Python, JavaScript/TypeScript)
    - Finds manifest files (requirements.txt, package.json, etc.)
    - Extracts dependencies from manifests
    
    **Requires:** Completed validation via one of the /validate/* endpoints.
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** Languages detected, manifests found, and dependencies extracted.
    """
    from manifest_parser import analyze_packages as do_analyze_packages
    
    # Get files list from session or fetch directly
    files_list = session.extra.get("files_list")
    
    if not files_list:
        # Fetch files if not in session
        base_dir = os.path.dirname(os.path.abspath(__file__))
        source_path = os.path.join(base_dir, session.local_path)
        
        if not os.path.exists(source_path):
            from errors import raise_error
            raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404)
        
        files_list = []
        skip_dirs = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git'}
        
        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_dirs]
            for file in files:
                if not file.startswith('.'):
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, source_path).replace("\\", "/")
                    files_list.append(rel_path)
    
    # Get absolute checkout path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    checkout_path = Path(os.path.join(base_dir, session.local_path))
    
    # Run package analysis (matches orchestrator's write_packages_report)
    result = do_analyze_packages(checkout_path, files_list)
    
    # Store results in session state
    update_session(
        session_token,
        languages_detected=result["languages_detected"],
        manifests_found=result["manifests_found"],
        dependencies=result["dependencies"]
    )
    
    # Build response matching orchestrator output structure
    from models import ManifestsFound, DependenciesFound, PackagesSummary
    
    return PackagesResponse(
        languages_detected=result["languages_detected"],
        manifests_found=ManifestsFound(
            python=result["manifests_found"].get("python", []),
            javascript=result["manifests_found"].get("javascript", [])
        ),
        dependencies=DependenciesFound(
            python=result["dependencies"].get("python", []),
            javascript=result["dependencies"].get("javascript", [])
        ),
        summary=PackagesSummary(
            total_languages=result["summary"]["total_languages"],
            total_manifests=result["summary"]["total_manifests"],
            total_dependencies=result["summary"]["total_dependencies"]
        )
    )


# =============================================================================
# 6. SEMGREP IMPORTS SCAN ENDPOINT - Detect imports using Semgrep
# =============================================================================

@app.get("/semgrep-imports-scan", response_model=SemgrepScanResponse)
async def semgrep_imports_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Run Semgrep import detection on the validated source.
    
    Matches the orchestrator's write_semgrep_findings workflow:
    - Runs semgrep rules to detect Python and JavaScript imports
    - Deduplicates findings
    - Filters out local/internal imports using code tokens
    - Extracts unique third-party packages with source file mappings
    
    **Requires:** Completed /packages endpoint (languages detected in session).
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** Scan results, filtered results, and extracted packages.
    """
    from semgrep_scanner import scan_and_dedupe
    
    # Get languages from session (should be set by /packages endpoint)
    languages_detected = session.extra.get("languages_detected")
    
    if not languages_detected:
        from errors import raise_error
        raise_error(
            "NO_LANGUAGES", 
            "No languages detected. Call /packages first.",
            status=400,
            hint="Call /packages endpoint before running semgrep scan"
        )
    
    languages = set(languages_detected)
    
    # Get absolute checkout path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    checkout_path = Path(os.path.join(base_dir, session.local_path))
    
    if not checkout_path.exists():
        from errors import raise_error
        raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404)
    
    # Run import scanning (matches orchestrator's write_semgrep_findings)
    result = scan_and_dedupe(checkout_path, languages)
    
    # Store scan results in session state
    update_session(
        session_token,
        semgrep_scan_results=result["scan_results"]
    )
    
    # Build response with proper models
    from models import LanguageImports, ImportInfo, SemgrepScanSummary
    
    # Convert scan_results to model format
    scan_results_model = {}
    for lang, lang_data in result["scan_results"].items():
        scan_results_model[lang] = LanguageImports(
            third_party=[ImportInfo(**imp) for imp in lang_data.get("third_party", [])],
            builtin=[ImportInfo(**imp) for imp in lang_data.get("builtin", [])],
            relative=[ImportInfo(**imp) for imp in lang_data.get("relative", [])]
        )
    
    return SemgrepScanResponse(
        scan_results=scan_results_model,
        summary=SemgrepScanSummary(
            total_third_party=result["summary"]["total_third_party"],
            total_builtin=result["summary"]["total_builtin"],
            total_relative=result["summary"]["total_relative"]
        )
    )


# =============================================================================
# 7. RESOLVE PACKAGES ENDPOINT - Resolve manifest packages to import names
# =============================================================================

@app.get("/resolve-packages")
async def resolve_packages(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Resolve manifest packages to import names and detect unused libraries.
    
    Prerequisites:
    - /packages must be called first (manifest dependencies)
    - /semgrep-imports-scan must be called first (detected imports)
    
    Resolution Flow (Python only - via PyPI):
    1. Static mapping (known packages like scikit-learn → sklearn)
    2. PyPI wheel download → read top_level.txt
    3. Heuristics fallback (foo-bar → foo_bar)
    
    For JavaScript: Direct comparison (package name = import name)
    
    Compares resolved imports with semgrep-detected imports to find:
    - used_libraries: In manifest AND in code
    - unused_libraries: In manifest but NOT in code
    """
    from package_resolver import resolve_and_compare
    
    # Get packages data from session
    languages = session.extra.get("languages_detected", [])
    dependencies = session.extra.get("dependencies", {})
    
    if not languages and not dependencies:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /packages must be called first"
        )
    
    # Get semgrep scan results from session
    scan_results = session.extra.get("semgrep_scan_results")
    if not scan_results:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /semgrep-imports-scan must be called first"
        )
    
    # Build import_packages format from scan results for comparison
    # Extract third-party packages from scan results
    import_packages = {
        "python_imports": [],
        "javascript_imports": []
    }
    
    if "python" in scan_results:
        for imp in scan_results["python"].get("third_party", []):
            import_packages["python_imports"].append({
                "package": imp.get("base_package", ""),
                "source_files": [imp.get("file", "")]
            })
    
    if "javascript" in scan_results:
        for imp in scan_results["javascript"].get("third_party", []):
            import_packages["javascript_imports"].append({
                "package": imp.get("base_package", ""),
                "source_files": [imp.get("file", "")]
            })
    
    # Run resolution and comparison
    result = resolve_and_compare(
        manifest_packages=dependencies,
        semgrep_imports=import_packages,
        languages=languages
    )
    
    # Store in session for next endpoints
    update_session(
        session_token,
        resolved_packages=result,
        import_packages=import_packages
    )
    
    return {
        "resolved_packages": result["resolved_packages"],
        "used_libraries": result["used_libraries"],
        "unused_libraries": result["unused_libraries"],
        "resolution_summary": result["resolution_summary"]
    }


# =============================================================================
# 8. FILTERED IMPORTS ENDPOINT - Filter local imports, extract packages
# =============================================================================

@app.get("/filtered-imports", response_model=FilteredImportsResponse)
async def filtered_imports(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Filter local/internal imports and extract unique external packages.
    
    Prerequisites:
    - /semgrep-imports-scan must be called first (scan results in session)
    - /resolve-packages must be called first (unused detection)
    
    This endpoint:
    - Filters out imports that match code tokens (local modules)
    - Extracts unique third-party packages with source file mappings
    - Includes unused library information from /resolve-packages
    """
    from semgrep_scanner import filter_local_imports, extract_packages_with_sources
    from models import (
        LanguageImports, ImportInfo, ImportPackage, ImportPackages, 
        FilteredImportsSummary, FilteredImportsResponse
    )
    
    # Get scan results from session
    scan_results = session.extra.get("semgrep_scan_results")
    
    if not scan_results:
        from errors import raise_error
        raise_error(
            "NO_SCAN_RESULTS", 
            "No semgrep scan results found. Call /semgrep-imports-scan first.",
            status=400,
            hint="Call /semgrep-imports-scan endpoint before filtering imports"
        )
    
    # Get code tokens from session
    code_tokens = session.extra.get("code_tokens", [])
    code_tokens_set = set(code_tokens)
    
    # Get languages from session
    languages = set(session.extra.get("languages_detected", []))
    
    # Count before filtering
    total_before = sum(
        len(scan_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    
    # Step 1: Filter local imports
    filtered_results = filter_local_imports(scan_results, code_tokens_set)
    
    # Count after filtering
    total_after = sum(
        len(filtered_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    
    # Step 2: Extract packages with source mappings
    import_packages = extract_packages_with_sources(filtered_results, languages)
    
    # Count unique packages
    unique_packages = (
        len(import_packages.get("python_imports", [])) + 
        len(import_packages.get("javascript_imports", []))
    )
    
    # Get unused libraries from resolve-packages (if called)
    resolved_data = session.extra.get("resolved_packages", {})
    unused_libraries = resolved_data.get("unused_libraries", {"python": [], "javascript": []})
    
    # Store in session
    update_session(
        session_token,
        filtered_imports=filtered_results,
        import_packages=import_packages
    )
    
    return FilteredImportsResponse(
        import_packages=ImportPackages(
            python_imports=[ImportPackage(**pkg) for pkg in import_packages.get("python_imports", [])],
            javascript_imports=[ImportPackage(**pkg) for pkg in import_packages.get("javascript_imports", [])]
        ),
        summary=FilteredImportsSummary(
            total_before_filter=total_before,
            total_after_filter=total_after,
            local_imports_removed=total_before - total_after,
            unique_external_packages=unique_packages
        )
    )


# =============================================================================
# 9. DEPENDENCY GRAPH ENDPOINT - File-to-file import relationships
# =============================================================================

@app.get("/dependency-graph", response_model=DependencyGraphResponse)
async def dependency_graph(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Generate import dependency graph showing file-to-file relationships.
    
    Uses semgrep scan results and code tokens from session.
    No additional file I/O required - builds from session data.
    
    Prerequisites:
    - /semgrep-imports-scan must be called first
    - /code_tokens must be called first
    
    Returns:
    - nodes: Files with import counts
    - edges: Import relationships between files
    - metadata: Summary statistics by language
    """
    from dependency_graph import build_dependency_graph
    from models import GraphNode, GraphEdge, GraphMetadata, LanguageStats
    
    # Get semgrep scan results from session
    semgrep_scan = session.extra.get("semgrep_scan_results")
    if not semgrep_scan:
        raise HTTPException(
            status_code=428,
            detail="semgrep-imports-scan endpoint must be called first"
        )
    
    # Get code tokens from session
    code_tokens = session.extra.get("code_tokens")
    if not code_tokens:
        raise HTTPException(
            status_code=428,
            detail="code_tokens endpoint must be called first"
        )
    
    # Convert code_tokens to set if it's a list
    if isinstance(code_tokens, list):
        code_tokens = set(code_tokens)
    
    # Build dependency graph from session data
    graph = build_dependency_graph(semgrep_scan, code_tokens)
    
    # Store in session
    update_session(session_token, dependency_graph=graph)
    
    # Build response
    return DependencyGraphResponse(
        nodes=[GraphNode(**node) for node in graph["nodes"]],
        edges=[GraphEdge(**edge) for edge in graph["edges"]],
        metadata=GraphMetadata(
            total_files=graph["metadata"]["total_files"],
            total_dependencies=graph["metadata"]["total_dependencies"],
            local_imports=graph["metadata"]["local_imports"],
            external_imports=graph["metadata"]["external_imports"],
            by_language={
                lang: LanguageStats(**stats) 
                for lang, stats in graph["metadata"].get("by_language", {}).items()
            }
        )
    )


# =============================================================================
# 10. LLM VALIDATION ENDPOINT - Classify AI vs non-AI libraries
# =============================================================================

@app.get("/llm-validate", response_model=LLMValidationResponse)
async def llm_validate(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Classify libraries as AI-positive or non-AI using LLM.
    
    Matches the orchestrator's run_llm_validation workflow:
    - Collects unique libraries from manifest dependencies and detected imports
    - Sends to Groq LLM for AI/ML classification
    - Returns AI-positive libraries with source file mappings
    
    **Requires:** Completed /filtered-imports endpoint (import packages in session).
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** AI libraries with source files, non-AI library list, and summary.
    """
    from llm_validator import validate_libraries
    from models import AILibrary, LLMValidationSummary
    
    # Get dependencies from session (set by /packages endpoint)
    dependencies = session.extra.get("dependencies", {})
    
    # Get import packages from session (set by /filtered-imports endpoint)
    import_packages = session.extra.get("import_packages")
    
    if not import_packages:
        from errors import raise_error
        raise_error(
            "NO_IMPORT_PACKAGES", 
            "No import packages found. Call /filtered-imports first.",
            status=400,
            hint="Call /filtered-imports endpoint before LLM validation"
        )
    
    # Get resolved packages if available (better deduplication)
    resolved_packages = session.extra.get("resolved_packages")
    
    # Run LLM validation
    try:
        result = validate_libraries(dependencies, import_packages, resolved_packages)
    except ValueError as e:
        from errors import raise_error
        raise_error(
            "LLM_CONFIG_ERROR",
            str(e),
            status=500,
            hint="Set GROQ_API_KEY in .env file"
        )
    
    if result is None:
        from errors import raise_error
        raise_error(
            "LLM_VALIDATION_FAILED",
            "LLM classification failed. Check API key and model.",
            status=500,
            hint="Verify GROQ_API_KEY is valid and LLM_MODEL is available"
        )
    
    # Store in session
    update_session(
        session_token,
        llm_validation=result,
        ai_libraries=result["ai_libraries"]
    )
    
    # Build response
    return LLMValidationResponse(
        ai_libraries=[AILibrary(**lib) for lib in result["ai_libraries"]],
        non_ai_libraries=result["non_ai_libraries"],
        summary=LLMValidationSummary(
            total_classified=result["total_classified"],
            total_ai_positive=result["total_ai_positive"],
            total_non_ai=result["total_non_ai"],
            model_used=result["model_used"]
        )
    )

# =============================================================================
# 11. LLM AI Library Categorization
# =============================================================================

@app.get("/llm-categorize", response_model=CategorizationResponse)
async def llm_categorize(
    session: SessionData = Depends(require_validated_session()),
):
    """
    Categorize AI-positive libraries into specific types.
    
    Prerequisites:
    - /llm-validate must be called first
    
    Categories:
    - AI_PROVIDER: OpenAI, Anthropic, Google AI, etc.
    - ML_ALGORITHM: scikit-learn, xgboost, etc.
    - DL_ALGORITHM: torch, tensorflow, keras, etc.
    - AI_ORCHESTRATION: langchain, llamaindex, etc.
    - VECTOR_DB: pinecone, chromadb, weaviate, etc.
    - DATA_PROCESSING: pandas, numpy for AI workflows
    """
    from llm_categorizer import run_categorization
    
    # Verify llm_validate was called
    if "llm_validation" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="llm-validate endpoint must be called first"
        )
    
    # Get AI libraries from validation
    validation_data = session.extra["llm_validation"]
    ai_libraries = validation_data.get("ai_libraries", [])
    
    if not ai_libraries:
        # No AI libraries to categorize
        empty_category = CategoryGroup(count=0, libraries=[])
        return CategorizationResponse(
            by_category={
                "ai_provider": empty_category,
                "ml_algorithm": empty_category,
                "dl_algorithm": empty_category,
                "ai_orchestration": empty_category,
                "vector_db": empty_category,
                "data_processing": empty_category,
                "unknown": empty_category
            },
            total_libraries=0,
            model_used=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        )
    
    # Run categorization
    result = run_categorization(ai_libraries)
    
    if not result:
        raise HTTPException(
            status_code=500,
            detail="Categorization failed. Please check API key and model configuration."
        )
    
    # Store categorization in session
    session.extra["llm_categorization"] = result
    
    # Build response
    by_category = {}
    for cat_key, cat_data in result["by_category"].items():
        by_category[cat_key] = CategoryGroup(
            count=cat_data["count"],
            libraries=[CategorizedLibrary(**lib) for lib in cat_data["libraries"]]
        )
    
    return CategorizationResponse(
        by_category=by_category,
        total_libraries=result["total_libraries"],
        model_used=result["model_used"]
    )


# =============================================================================
# 12. AI Branch Tracing - Trace AI dependencies & targeted scans
# =============================================================================

@app.get("/ai-branch-trace", response_model=AIBranchTraceResponse)
async def ai_branch_trace(
    session: SessionData = Depends(require_validated_session()),
):
    """
    Trace AI library dependencies through the codebase.
    
    Prerequisites:
    - /llm-categorize must be called first (provides AI library categorization)
    - /dependency-graph must be called first (provides file relationship graph)
    
    This endpoint:
    1. For each AI library, finds all files that import it (directly or transitively)
    2. Determines appropriate semgrep rules based on language and category
    3. Returns branches showing AI usage flow through the codebase
    
    Note: Actual semgrep scanning is done in the next endpoint (/ai-targeted-scan)
    """
    from ai_branch_tracer import trace_ai_branches, format_branch_summary
    from models import CategoryStats, BranchLanguageStats
    
    # Verify prerequisites
    if "llm_categorization" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /llm-categorize must be called first"
        )
    
    if "dependency_graph" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /dependency-graph must be called first"
        )
    
    # Get required data from session
    categorization_data = session.extra["llm_categorization"]
    dependency_graph = session.extra["dependency_graph"]
    
    # Build checkout path (same pattern as other endpoints)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    checkout_dir = os.path.join(base_dir, session.local_path)
    
    # Run branch tracing
    result = trace_ai_branches(
        checkout_dir=checkout_dir,
        dependency_graph=dependency_graph,
        categorization_data=categorization_data
    )
    
    # Store in session for next endpoints
    session.extra["ai_branch_trace"] = result
    
    # Format branch summary for response
    branch_list = format_branch_summary(result)
    
    # Build typed response
    branches = {
        name: AIBranch(**data) 
        for name, data in result.get("branches", {}).items()
    }
    
    # Build summary with proper types
    summary_data = result.get("summary", {})
    
    by_category = {
        cat: CategoryStats(**stats) 
        for cat, stats in summary_data.get("by_category", {}).items()
    }
    
    by_language = {
        lang: BranchLanguageStats(**stats) 
        for lang, stats in summary_data.get("by_language", {}).items()
    }
    
    summary = BranchTraceSummary(
        total_branches=summary_data.get("total_branches", 0),
        total_source_files=summary_data.get("total_source_files", 0),
        total_traced_files=summary_data.get("total_traced_files", 0),
        by_category=by_category,
        by_language=by_language,
        timestamp=summary_data.get("timestamp", "")
    )
    
    branch_list_typed = [BranchSummaryItem(**item) for item in branch_list]
    
    return AIBranchTraceResponse(
        branches=branches,
        summary=summary,
        branch_list=branch_list_typed
    )


# =============================================================================
# 13. AI Targeted Scan - Run semgrep on traced AI branches
# =============================================================================

@app.get("/ai-targeted-scan")
async def ai_targeted_scan(
    session: SessionData = Depends(require_validated_session())
):
    """
    Run targeted semgrep scans on AI branch traced files.
    
    Prerequisites:
    - /ai-branch-trace must be called first (provides traced files per library)
    
    Scanning Flow:
    1. For each library: Find matching provider rule → run on traced files
    2. If no provider rule: Skip (model detection will cover it)
    3. Model detection: Run ONCE on ALL traced files
    4. API calls: Run ONCE on ALL traced files
    
    Rule: Each file scanned by each rule only ONCE (deduplicated)
    
    Returns:
    - scan_results: Per-library scan findings
    - models_detected: All models with file + line locations
    - distinct_models: Unique model names
    - api_calls_found: All API calls with file + line locations
    """
    from ai_targeted_scanner import scan_ai_branches
    from models import (
        AITargetedScanResponse, LibraryScanResult, ScanFinding, ScanSummary,
        ModelDetection, APICallDetection
    )
    
    # Verify prerequisite
    if "ai_branch_trace" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /ai-branch-trace must be called first"
        )
    
    # Get branch trace from session
    branch_trace = session.extra["ai_branch_trace"]
    
    # Build checkout path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    checkout_dir = os.path.join(base_dir, session.local_path)
    
    # Run targeted scans
    result = scan_ai_branches(
        checkout_dir=checkout_dir,
        branch_trace=branch_trace
    )
    
    # Store in session for AIBOM generation
    session.extra["ai_targeted_scan"] = result
    
    # Build typed response
    scan_results = {}
    for lib_name, data in result.get("scan_results", {}).items():
        findings = [
            ScanFinding(**f) for f in data.get("findings", [])
        ]
        
        # Handle rules_used - could be list of strings or list of dicts
        rules_used = data.get("rules_used", [])
        if rules_used and isinstance(rules_used[0], dict):
            rules_used = [r.get("rule", r.get("name", str(r))) for r in rules_used]
        
        scan_results[lib_name] = LibraryScanResult(
            library=data.get("library", lib_name),
            category=data.get("category", "UNKNOWN"),
            language=data.get("language", "python"),
            scanned=data.get("scanned", False),
            reason=data.get("reason"),
            rules_used=rules_used,
            traced_files_count=data.get("traced_files_count", 0),
            findings_count=data.get("findings_count", 0),
            findings=findings,
            models_detected=data.get("models_detected", []),
            provider_rule_found=data.get("provider_rule_found", False)
        )
    
    # Build models_detected list
    models_detected = [
        ModelDetection(**m) for m in result.get("models_detected", [])
    ]
    
    # Build api_calls_found list
    api_calls_found = [
        APICallDetection(**a) for a in result.get("api_calls_found", [])
    ]
    
    # Build model_detection_findings
    model_detection_findings = [
        ScanFinding(**f) for f in result.get("model_detection_findings", [])
    ]
    
    summary_data = result.get("summary", {})
    summary = ScanSummary(
        total_libraries=summary_data.get("total_libraries", 0),
        libraries_scanned=summary_data.get("libraries_scanned", 0),
        total_findings=summary_data.get("total_findings", 0),
        unique_models_detected=summary_data.get("unique_models_detected", 0),
        all_models=summary_data.get("all_models", []),
        api_calls_count=summary_data.get("api_calls_count", 0),
        errors=summary_data.get("errors", []),
        timestamp=summary_data.get("timestamp", ""),
        language=summary_data.get("language", "python"),
        rules_used=summary_data.get("rules_used", {}),
        rules_available=summary_data.get("rules_available", {})
    )
    
    return AITargetedScanResponse(
        scan_results=scan_results,
        models_detected=models_detected,
        distinct_models=result.get("distinct_models", []),
        api_calls_found=api_calls_found,
        model_detection_findings=model_detection_findings,
        summary=summary
    )


# =============================================================================
# 14. Rule Categories - View available rules
# =============================================================================

@app.get("/available-rules")
async def get_available_rules():
    """
    Get all available semgrep rules organized by category and language.
    
    Returns:
    - provider: Rules for specific AI providers (openai, anthropic, etc.)
    - model_detection: Rules for detecting model names
    - api_calls: Rules for detecting API calls
    
    Each category shows Python and JavaScript rule files.
    """
    from ai_targeted_scanner import get_available_categories
    
    return get_available_categories()


# =============================================================================
# 15. Model Card Handler - Fetch model cards with suffix stripping
# =============================================================================

@app.get("/model-card-handler")
async def model_card_handler(
    session: SessionData = Depends(require_validated_session())
):
    """
    Fetch model cards for detected models with iterative suffix stripping.
    
    **Prerequisites:**
    - `/ai-targeted-scan` must be called first (provides distinct_models list)
    
    **Lookup Order:**
    1. Local cache (7-day expiry)
    2. HuggingFace API (with optional HF_TOKEN)
    3. Azure AI Foundry catalog
    4. If not found: Strip suffix and retry (e.g., gpt-3.5-turbo-16k → gpt-3.5-turbo)
    
    **Suffix Stripping:**
    - Iteratively removes suffixes from right: `-16k`, `-instruct`, `-4b`, etc.
    - Returns suffix meanings (e.g., "16k" = "16,000 token context window")
    - Stops when model card is found or base name reached
    
    **Returns:**
    - models_processed: Number of models looked up
    - found_count: Number with model cards found
    - not_found_count: Number not found in any source
    - results: List of ModelCardResult with:
        - model_card_found: bool
        - original_model_name: Full name as detected
        - base_model_name: Name that matched (may differ if stripped)
        - stripped_suffixes: List of removed suffixes
        - suffix_info: Parsed suffix meanings
        - model_card: Full model card data (or None)
        - lookup_source: cache, huggingface, huggingface_stripped, azure_ai_foundry, etc.
        - iterations_required: Number of attempts before found/giving up
    """
    from model_card_handler import process_models_for_cards
    from models import (
        ModelCardHandlerResponse, ModelCardResult, SuffixInfo, ModelCardSummary
    )
    
    # Verify prerequisite
    if "ai_targeted_scan" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /ai-targeted-scan must be called first"
        )
    
    # Get distinct models from session
    scan_result = session.extra["ai_targeted_scan"]
    distinct_models = scan_result.get("distinct_models", [])
    
    if not distinct_models:
        # No models to look up
        return ModelCardHandlerResponse(
            models_processed=0,
            found_count=0,
            not_found_count=0,
            results=[],
            summary=ModelCardSummary(source_breakdown={}, success_rate="N/A")
        )
    
    # Get HF token from environment
    hf_token = os.environ.get("HF_TOKEN")
    
    # Process all models
    result = process_models_for_cards(
        model_names=distinct_models,
        hf_token=hf_token,
        try_stripping=True,
        try_azure=True
    )
    
    # Store in session for AIBOM generation
    session.extra["model_card_results"] = result
    
    # Build typed response
    results = []
    for r in result.get("results", []):
        suffix_infos = [
            SuffixInfo(
                suffix=s.get("suffix", ""),
                type=s.get("type", "unknown"),
                meaning=s.get("meaning", ""),
                token_count=s.get("token_count"),
                parameter_count=s.get("parameter_count")
            )
            for s in r.get("suffix_info", [])
        ]
        
        results.append(ModelCardResult(
            model_card_found=r.get("model_card_found", False),
            original_model_name=r.get("original_model_name", ""),
            base_model_name=r.get("base_model_name", ""),
            stripped_suffixes=r.get("stripped_suffixes", []),
            suffix_info=suffix_infos,
            model_card=r.get("model_card"),
            lookup_source=r.get("lookup_source"),
            iterations_required=r.get("iterations_required", 0)
        ))
    
    summary_data = result.get("summary", {})
    summary = ModelCardSummary(
        source_breakdown=summary_data.get("source_breakdown", {}),
        success_rate=summary_data.get("success_rate", "0%")
    )
    
    return ModelCardHandlerResponse(
        models_processed=result.get("models_processed", 0),
        found_count=result.get("found_count", 0),
        not_found_count=result.get("not_found_count", 0),
        results=results,
        summary=summary
    )


# =============================================================================
# 16. Model Deprecation Check - Check models against deprecation databases
# =============================================================================

@app.get("/model-deprecation-check")
async def model_deprecation_check(
    session: SessionData = Depends(require_validated_session())
):
    """
    Check detected models against provider deprecation databases.
    
    **Prerequisites:**
    - `/model-card-handler` must be called first (provides model card results)
    
    **Logic:**
    - For models where `model_card_found = False`: Returns "Model not found" message
    - For models where `model_card_found = True`: Checks the `base_model_name` 
      (the name that matched after suffix stripping) against deprecation databases
    
    **Deprecation Check:**
    - Checks OpenAI, Anthropic, Google deprecation databases
    - Returns: deprecated status, severity, shutdown date, replacement chain
    
    **Returns:**
    - models_checked: Number of models checked
    - deprecated_count: Number found in deprecation databases
    - active_count: Number not deprecated
    - not_found_count: Number where model card was not found
    - results: List of ModelDeprecationResult with:
        - model_name: Original model name
        - model_card_found: bool (from model-card-handler)
        - deprecation_found: bool
        - deprecation_info: Full deprecation details (if found)
        - message: Status message
    """
    from model_deprecation_checker import check_model_deprecation
    from models import (
        ModelDeprecationResponse, ModelDeprecationResult, 
        DeprecationInfo, DeprecationSummary
    )
    
    # Verify prerequisite
    if "model_card_results" not in session.extra:
        raise HTTPException(
            status_code=428,
            detail="Prerequisite not met: /model-card-handler must be called first"
        )
    
    # Get model card results from session
    model_card_results = session.extra["model_card_results"]
    card_results = model_card_results.get("results", [])
    
    if not card_results:
        # No models to check
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
    
    # Process each model
    results = []
    deprecated_count = 0
    active_count = 0
    not_found_count = 0
    severity_counts = {}
    
    for card_result in card_results:
        original_name = card_result.get("original_model_name", "")
        model_card_found = card_result.get("model_card_found", False)
        base_name = card_result.get("base_model_name", original_name)
        
        if not model_card_found:
            # Model card was not found - skip deprecation check
            not_found_count += 1
            results.append(ModelDeprecationResult(
                model_name=original_name,
                model_card_found=False,
                deprecation_found=False,
                deprecation_info=None,
                message=f"Model card not found for '{original_name}' - cannot check deprecation"
            ))
            continue
        
        # Check deprecation for the base model name (the one that matched)
        deprecation_result = check_model_deprecation(base_name)
        
        if deprecation_result:
            deprecated_count += 1
            severity = deprecation_result.get("severity", "INFO")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Build deprecation info
            dep_info = DeprecationInfo(
                model_id=deprecation_result.get("model_id", base_name),
                provider=deprecation_result.get("provider", "unknown"),
                status=deprecation_result.get("status", "unknown"),
                is_deprecated=deprecation_result.get("is_deprecated", True),
                severity=severity,
                announcement_date=deprecation_result.get("announcement_date"),
                shutdown_date=deprecation_result.get("shutdown_date"),
                days_until_shutdown=deprecation_result.get("days_until_shutdown"),
                recommended_replacement=deprecation_result.get("recommended_replacement"),
                final_replacement=deprecation_result.get("final_replacement"),
                replacement_chain=deprecation_result.get("replacement_chain", []),
                category=deprecation_result.get("category"),
                type=deprecation_result.get("type"),
                notes=deprecation_result.get("notes", ""),
                deprecated_price=deprecation_result.get("deprecated_price")
            )
            
            # Build message
            shutdown_msg = ""
            if deprecation_result.get("days_until_shutdown") is not None:
                days = deprecation_result["days_until_shutdown"]
                if days <= 0:
                    shutdown_msg = " - ALREADY PAST SHUTDOWN DATE"
                else:
                    shutdown_msg = f" - {days} days until shutdown"
            
            message = f" DEPRECATED: {base_name} ({severity}){shutdown_msg}"
            if deprecation_result.get("recommended_replacement"):
                message += f" → Recommended: {deprecation_result['recommended_replacement']}"
            
            results.append(ModelDeprecationResult(
                model_name=original_name,
                model_card_found=True,
                deprecation_found=True,
                deprecation_info=dep_info,
                message=message
            ))
        else:
            # Model not found in deprecation databases = likely active
            active_count += 1
            results.append(ModelDeprecationResult(
                model_name=original_name,
                model_card_found=True,
                deprecation_found=False,
                deprecation_info=None,
                message=f" Model '{base_name}' is active (not in deprecation databases)"
            ))
    
    # Store in session for AIBOM generation
    session.extra["deprecation_check_results"] = {
        "models_checked": len(card_results),
        "deprecated_count": deprecated_count,
        "active_count": active_count,
        "not_found_count": not_found_count,
        "results": [r.dict() for r in results]
    }
    
    return ModelDeprecationResponse(
        models_checked=len(card_results),
        deprecated_count=deprecated_count,
        active_count=active_count,
        not_found_count=not_found_count,
        results=results,
        summary=DeprecationSummary(
            models_checked=len(card_results),
            deprecated_count=deprecated_count,
            active_count=active_count,
            not_found_count=not_found_count,
            severity_breakdown=severity_counts
        )
    )