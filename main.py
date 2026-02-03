"""
AIBOM Endpoints - FastAPI Application
Main entry point containing all endpoint definitions
"""

import os
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Set
from collections import defaultdict
from fastapi import FastAPI, File, UploadFile, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import from modules
from config import CODE_FILE_EXTENSIONS, SKIP_DIRECTORIES, AI_CATEGORIES
from models import (
    SourceTypeRequest, SourceTypeResponse, FilesResponse, CodeTokensResponse,
    PackagesResponse, SemgrepScanResponse, FilteredImportsResponse, LLMValidationResponse,
    CategorizationResponse, CategorizedLibrary, CategoryGroup,
    DependencyGraphResponse, AIBranchTraceResponse, AIBranch, BranchSummaryItem, BranchTraceSummary,
    RepoPublicRequest, RepoPrivateRequest,
    ManifestsFound, DependenciesFound, PackagesSummary,
    LanguageImports, ImportInfo, SemgrepScanSummary,
    ImportPackage, ImportPackages, FilteredImportsSummary,
    GraphNode, GraphEdge, GraphMetadata, LanguageStats,
    AILibrary, LLMValidationSummary,
    CategoryStats, BranchLanguageStats,
    AITargetedScanResponse, LibraryScanResult, ScanFinding, ScanSummary,
    ModelDetection,
    ModelCardHandlerResponse, ModelCardResult, SuffixInfo, ModelCardSummary,
    ModelDeprecationResponse, ModelDeprecationResult, DeprecationInfo, DeprecationSummary
)
from session import (
    create_session,
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
)
from errors import raise_error

# Import scanner/resolver modules at top-level (avoid per-request import overhead)
from manifest_parser import analyze_packages as do_analyze_packages
from semgrep_scanner import scan_and_dedupe, filter_local_imports, extract_packages_with_sources
from package_resolver import resolve_and_compare
from dependency_graph import build_dependency_graph
from llm_validator import validate_libraries
from llm_categorizer import run_categorization
from ai_branch_tracer import trace_ai_branches, format_branch_summary
from ai_targeted_scanner import scan_ai_branches
from model_card_handler import process_models_for_cards
from model_deprecation_checker import check_model_deprecation
# =============================================================================
# CONSTANTS & HELPERS (computed once at module load)
# =============================================================================

# Cache base directory - computed once, reused everywhere
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_source_path(session: SessionData):
    """Get absolute source path from session. Raises if not found."""
    source_path = os.path.join(BASE_DIR, session.local_path)
    if not os.path.exists(source_path):
        raise_error("SOURCE_NOT_FOUND", "Validated source no longer exists", status=404,
                    hint="The source may have been cleaned up. Please validate again.")
    return source_path


def collect_files(source_path: str) -> List[str]:
    """Walk directory and collect all non-hidden files, skipping common dirs."""
    files_list = []
    for root, dirs, files in os.walk(source_path):
        # In-place filter using slice assignment (efficient)
        dirs[:] = [d for d in dirs if d[0] != '.' and d not in SKIP_DIRECTORIES]
        for file in files:
            if file[0] != '.':
                rel_path = os.path.relpath(os.path.join(root, file), source_path)
                files_list.append(rel_path.replace("\\", "/"))
    return files_list


def get_files_list(session: SessionData) -> List[str]:
    """Get files list from session cache or collect from disk."""
    files_list = session.extra.get("files_list")
    if files_list:
        return files_list
    return collect_files(get_source_path(session))


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
    
    
    return SourceTypeResponse(
        message=f"Source type '{request.source_type}' set successfully.",
        session_token=token,
        source_type=request.source_type
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
    source_path = get_source_path(session)
    all_files = collect_files(source_path)
    
    # Group by extension in single pass
    '''by_extension = defaultdict(list)
    for file_path in all_files:
        ext = Path(file_path).suffix.lower() or "(no extension)"
        by_extension[ext].append(file_path)'''
    
    # Store files list in session for next endpoints
    update_session(session_token, files_list=all_files)
    
    return FilesResponse(
        total_files=len(all_files),
        files=sorted(all_files),
        #by_extension=dict(by_extension)
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
    files_list = get_files_list(session)
    
    # Extract tokens from code files only - use set comprehension for efficiency
    tokens: Set[str] = set()
    code_files_processed = 0
    
    for file_path in files_list:
        p = Path(file_path)
        if p.suffix.lower() not in CODE_FILE_EXTENSIONS:
            continue
        
        code_files_processed += 1
        # Add all folder parts + file stem in one update call
        tokens.update(p.parts[:-1])
        tokens.add(p.stem)
    
    sorted_tokens = sorted(tokens)
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
    
    - Detects languages (Python, JavaScript/TypeScript)
    - Finds manifest files (requirements.txt, package.json, etc.)
    - Extracts dependencies from manifests
    
    **Requires:** Completed validation via one of the /validate/* endpoints.
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** Languages detected, manifests found, and dependencies extracted.
    """
    files_list = get_files_list(session)
    checkout_path = Path(BASE_DIR) / session.local_path
    
    result = do_analyze_packages(checkout_path, files_list)
    
    update_session(
        session_token,
        languages_detected=result["languages_detected"],
        manifests_found=result["manifests_found"],
        dependencies=result["dependencies"]
    )
    
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
    
    - Runs semgrep rules to detect Python and JavaScript imports
    - Deduplicates findings
    - Filters out local/internal imports using code tokens
    - Extracts unique third-party packages with source file mappings
    
    **Requires:** Completed /packages endpoint (languages detected in session).
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** Scan results, filtered results, and extracted packages.
    """
    languages_detected = session.extra.get("languages_detected")
    if not languages_detected:
        raise_error(
            "NO_LANGUAGES", 
            "No languages detected. Call /packages first.",
            status=400,
            hint="Call /packages endpoint before running semgrep scan"
        )
    
    checkout_path = get_source_path(session)
    result = scan_and_dedupe(checkout_path, set(languages_detected))
    
    update_session(session_token, semgrep_scan_results=result["scan_results"])
    
    # Build response - dict comprehension is cleaner
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
    """
    scan_results = session.extra.get("semgrep_scan_results")
    if not scan_results:
        raise_error(
            "NO_SCAN_RESULTS", 
            "No semgrep scan results found. Call /semgrep-imports-scan first.",
            status=400,
            hint="Call /semgrep-imports-scan endpoint before filtering imports"
        )
    
    # Reuse set from session cache if available, else convert once
    code_tokens_set = session.extra.get("code_tokens_set")
    if code_tokens_set is None:
        code_tokens_set = set(session.extra.get("code_tokens", []))
    
    languages = session.extra.get("languages_detected", [])
    
    # Single-pass counting: count before in one iteration
    total_before = sum(
        len(scan_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    
    filtered_results = filter_local_imports(scan_results, code_tokens_set)
    import_packages = extract_packages_with_sources(filtered_results, set(languages))
    
    # Count after + unique packages in single pass
    total_after = sum(
        len(filtered_results.get(lang, {}).get("third_party", []))
        for lang in languages
    )
    py_imports = import_packages.get("python_imports", [])
    js_imports = import_packages.get("javascript_imports", [])
    unique_packages = len(py_imports) + len(js_imports)
    
    update_session(
        session_token,
        filtered_imports=filtered_results,
        import_packages=import_packages
    )
    
    return FilteredImportsResponse(
        import_packages=ImportPackages(
            python_imports=[ImportPackage(**pkg) for pkg in py_imports],
            javascript_imports=[ImportPackage(**pkg) for pkg in js_imports]
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
    Prerequisites:
    - /semgrep-imports-scan must be called first
    - /code_tokens must be called first
    """
    semgrep_scan = session.extra.get("semgrep_scan_results")
    if not semgrep_scan:
        raise_error("NO_SCAN_RESULTS", "Call /semgrep-imports-scan first", status=428)
    
    code_tokens = session.extra.get("code_tokens")
    if not code_tokens:
        raise_error("NO_CODE_TOKENS", "Call /code_tokens first", status=428)
    
    # Session always stores code_tokens as list, convert once
    code_tokens_set = set(code_tokens)
    graph = build_dependency_graph(semgrep_scan, code_tokens_set)
    update_session(session_token, dependency_graph=graph)
    
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
    - Collects unique libraries from manifest dependencies and detected imports
    - Sends to Groq LLM for AI/ML classification
    - Returns AI-positive libraries with source file mappings
    
    **Requires:** Completed /filtered-imports endpoint (import packages in session).
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** AI libraries with source files, non-AI library list, and summary.
    """   
    dependencies = session.extra.get("dependencies", {})
    import_packages = session.extra.get("import_packages")
    
    if not import_packages:
        raise_error(
            "NO_IMPORT_PACKAGES", 
            "No import packages found. Call /filtered-imports first.",
            status=400,
            hint="Call /filtered-imports endpoint before LLM validation"
        )
    
    resolved_packages = session.extra.get("resolved_packages")
    
    try:
        result = validate_libraries(dependencies, import_packages, resolved_packages)
    except ValueError as e:
        raise_error(
            "LLM_CONFIG_ERROR",
            str(e),
            status=500,
            hint="Set GROQ_API_KEY in .env file"
        )
    
    if result is None:
        raise_error(
            "LLM_VALIDATION_FAILED",
            "LLM classification failed. Check API key and model.",
            status=500,
            hint="Verify GROQ_API_KEY is valid and LLM_MODEL is available"
        )
    
    update_session(
        session_token,
        llm_validation=result,
        ai_libraries=result["ai_libraries"]
    )
    
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
    session_token: str = Header(...)
):
    """
    Categorize AI-positive libraries into specific types.
    Prerequisites: /llm-validate must be called first
    """
    if "llm_validation" not in session.extra:
        raise_error("NO_LLM_VALIDATION", "Call /llm-validate first", status=428)
    
    ai_libraries = session.extra["llm_validation"].get("ai_libraries", [])
    
    if not ai_libraries:
        # Single empty category object, dict comprehension builds response
        empty = CategoryGroup(count=0, libraries=[])
        return CategorizationResponse(
            by_category={cat: empty for cat in AI_CATEGORIES},
            total_libraries=0,
            model_used=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        )
    result = run_categorization(ai_libraries)
    if not result:
        raise_error("CATEGORIZATION_FAILED", "Check API key and model config", status=500)
    # Store in session 
    update_session(session_token, llm_categorization=result)
    
    # Build response with dict comprehension
    return CategorizationResponse(
        by_category={
            cat_key: CategoryGroup(
                count=cat_data["count"],
                libraries=[CategorizedLibrary(**lib) for lib in cat_data["libraries"]]
            )
            for cat_key, cat_data in result["by_category"].items()
        },
        total_libraries=result["total_libraries"],
        model_used=result["model_used"]
    )


# =============================================================================
# 12. AI Branch Tracing - Trace AI dependencies & targeted scans
# =============================================================================

@app.get("/ai-branch-trace", response_model=AIBranchTraceResponse)
async def ai_branch_trace(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Trace AI library dependencies through the codebase.
    Prerequisites:
    - /llm-categorize must be called first
    - /dependency-graph must be called first
    """
    if "llm_categorization" not in session.extra:
        raise_error("NO_CATEGORIZATION", "Call /llm-categorize first", status=428)
    
    if "dependency_graph" not in session.extra:
        raise_error("NO_DEPENDENCY_GRAPH", "Call /dependency-graph first", status=428)
    
    result = trace_ai_branches(
        checkout_dir=get_source_path(session),  # Reuse helper instead of duplicating logic
        dependency_graph=session.extra["dependency_graph"],
        categorization_data=session.extra["llm_categorization"]
    )
    
    update_session(session_token, ai_branch_trace=result)  # Proper session update
    
    # Build typed response using dict comprehensions
    summary_data = result.get("summary", {})
    
    return AIBranchTraceResponse(
        branches={name: AIBranch(**data) for name, data in result.get("branches", {}).items()},
        summary=BranchTraceSummary(
            total_branches=summary_data.get("total_branches", 0),
            total_source_files=summary_data.get("total_source_files", 0),
            total_traced_files=summary_data.get("total_traced_files", 0),
            by_category={cat: CategoryStats(**stats) for cat, stats in summary_data.get("by_category", {}).items()},
            by_language={lang: BranchLanguageStats(**stats) for lang, stats in summary_data.get("by_language", {}).items()},
            timestamp=summary_data.get("timestamp", "")
        ),
        branch_list=[BranchSummaryItem(**item) for item in format_branch_summary(result)]
    )


# =============================================================================
# 13. AI Targeted Scan - Run semgrep on traced AI branches
# =============================================================================

@app.get("/ai-targeted-scan")
async def ai_targeted_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Run targeted semgrep scans on AI branch traced files.
    Prerequisites: /ai-branch-trace must be called first
    """
    
    if "ai_branch_trace" not in session.extra:
        raise_error("NO_BRANCH_TRACE", "Call /ai-branch-trace first", status=428)
    
    result = scan_ai_branches(
        checkout_dir=get_source_path(session),  # Reuse helper
        branch_trace=session.extra["ai_branch_trace"]
    )
    
    update_session(session_token, ai_targeted_scan=result)  # Proper session update
    
    # Build scan_results with proper model construction
    scan_results = {}
    for lib_name, data in result.get("scan_results", {}).items():
        rules_used = data.get("rules_used", [])
        # Normalize rules_used format
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
            findings=[ScanFinding(**f) for f in data.get("findings", [])],
            models_detected=data.get("models_detected", []),
            provider_rule_found=data.get("provider_rule_found", False)
        )
    
    summary_data = result.get("summary", {})
    
    return AITargetedScanResponse(
        scan_results=scan_results,
        models_detected=[ModelDetection(**m) for m in result.get("models_detected", [])],
        distinct_models=result.get("distinct_models", []),
       # api_calls_found=[APICallDetection(**a) for a in result.get("api_calls_found", [])],
        model_detection_findings=[ScanFinding(**f) for f in result.get("model_detection_findings", [])],
        summary=ScanSummary(
            total_libraries=summary_data.get("total_libraries", 0),
            libraries_scanned=summary_data.get("libraries_scanned", 0),
            total_findings=summary_data.get("total_findings", 0),
            unique_models_detected=summary_data.get("unique_models_detected", 0),
            all_models=summary_data.get("all_models", []),
           # api_calls_count=summary_data.get("api_calls_count", 0),
            errors=summary_data.get("errors", []),
            timestamp=summary_data.get("timestamp", ""),
            language=summary_data.get("language", "python"),
            rules_used=summary_data.get("rules_used", {})
        )
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
    """

    
    if "ai_targeted_scan" not in session.extra:
        raise HTTPException(status_code=428, detail="Prerequisite not met: /ai-targeted-scan must be called first")
    
    distinct_models = session.extra["ai_targeted_scan"].get("distinct_models", [])
    
    if not distinct_models:
        return ModelCardHandlerResponse(
            models_processed=0, found_count=0, not_found_count=0,
            results=[], summary=ModelCardSummary(source_breakdown={}, success_rate="N/A")
        )
    
    result = process_models_for_cards(
        model_names=distinct_models,
        hf_token=os.environ.get("HF_TOKEN"),
        try_stripping=True,
        try_azure=True
    )
    
    session.extra["model_card_results"] = result
    
    # Build typed response using list comprehension
    results = [
        ModelCardResult(
            model_card_found=r.get("model_card_found", False),
            original_model_name=r.get("original_model_name", ""),
            base_model_name=r.get("base_model_name", ""),
            stripped_suffixes=r.get("stripped_suffixes", []),
            suffix_info=[
                SuffixInfo(
                    suffix=s.get("suffix", ""), type=s.get("type", "unknown"),
                    meaning=s.get("meaning", ""), token_count=s.get("token_count"),
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
        results=results,
        summary=ModelCardSummary(
            source_breakdown=summary_data.get("source_breakdown", {}),
            success_rate=summary_data.get("success_rate", "0%")
        )
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
    
    **Deprecation Check:**
    - Checks OpenAI, Anthropic, Google deprecation databases
    - Returns: deprecated status, severity, shutdown date, replacement chain
    """

    
    if "model_card_results" not in session.extra:
        raise HTTPException(status_code=428, detail="Prerequisite not met: /model-card-handler must be called first")
    
    card_results = session.extra["model_card_results"].get("results", [])
    
    if not card_results:
        empty_summary = DeprecationSummary(
            models_checked=0, deprecated_count=0, active_count=0, 
            not_found_count=0, severity_breakdown={}
        )
        return ModelDeprecationResponse(
            models_checked=0, deprecated_count=0, active_count=0, not_found_count=0,
            results=[], summary=empty_summary
        )
    
    # Process each model - track counts
    results = []
    deprecated_count = active_count = not_found_count = 0
    severity_counts = {}
    
    for card_result in card_results:
        original_name = card_result.get("original_model_name", "")
        model_card_found = card_result.get("model_card_found", False)
        base_name = card_result.get("base_model_name", original_name)
        
        if not model_card_found:
            not_found_count += 1
            results.append(ModelDeprecationResult(
                model_name=original_name, model_card_found=False,
                deprecation_found=False, deprecation_info=None,
                message=f"Model card not found for '{original_name}' - cannot check deprecation"
            ))
            continue
        
        deprecation_result = check_model_deprecation(base_name)
        
        if deprecation_result:
            deprecated_count += 1
            severity = deprecation_result.get("severity", "INFO")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
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
            
            # Build concise message
            days = deprecation_result.get("days_until_shutdown")
            shutdown_msg = " - ALREADY PAST SHUTDOWN DATE" if days is not None and days <= 0 else (f" - {days} days until shutdown" if days else "")
            message = f" DEPRECATED: {base_name} ({severity}){shutdown_msg}"
            if deprecation_result.get("recommended_replacement"):
                message += f" → Recommended: {deprecation_result['recommended_replacement']}"
            
            results.append(ModelDeprecationResult(
                model_name=original_name, model_card_found=True,
                deprecation_found=True, deprecation_info=dep_info, message=message
            ))
        else:
            active_count += 1
            results.append(ModelDeprecationResult(
                model_name=original_name, model_card_found=True,
                deprecation_found=False, deprecation_info=None,
                message=f" Model '{base_name}' is active (not in deprecation databases)"
            ))
    
    # Store in session for AIBOM generation
    session.extra["deprecation_check_results"] = {
        "models_checked": len(card_results), "deprecated_count": deprecated_count,
        "active_count": active_count, "not_found_count": not_found_count,
        "results": [r.dict() for r in results]
    }
    
    return ModelDeprecationResponse(
        models_checked=len(card_results),
        deprecated_count=deprecated_count,
        active_count=active_count,
        not_found_count=not_found_count,
        results=results,
        summary=DeprecationSummary(
            models_checked=len(card_results), deprecated_count=deprecated_count,
            active_count=active_count, not_found_count=not_found_count,
            severity_breakdown=severity_counts
        )
    )

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