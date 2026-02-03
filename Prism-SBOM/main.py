"""
SBOM Endpoints - FastAPI Application
Main entry point containing all endpoint definitions

Run with: uvicorn main:app --reload --port 8000
Test with: http://localhost:8000/docs
"""

import os
import json
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, File, UploadFile, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Import from modules
from src.api.config import ENDPOINT_MAP, TOOL_NAME, TOOL_VERSION, TOOL_VENDOR, RATE_LIMITS
from src.api.models import (
    SourceTypeRequest, SourceTypeResponse,
    RepoPublicRequest, RepoPrivateRequest,
    StartScanResponse
)
from src.api.session import (
    create_session,
    get_session,
    update_session,
    require_source_type,
    require_validated_session,
    require_scan_initialized,
    require_step,
    mark_step_complete,
    SessionData
)
from src.api.validate import (
    validate_github_repo,
    validate_zip_upload,
    validate_local_upload,
    cleanup_temp_dir,
    get_temp_dir
)

# Import orchestrator and rate limiter
from src.core.orchestrator import ScanOrchestrator
from src.utils.rate_limiter import get_rate_limiter


# =============================================================================
# INITIALIZE GLOBALS
# =============================================================================

def init_rate_limiter():
    """Initialize and configure the shared rate limiter."""
    limiter = get_rate_limiter()
    for api_name, config in RATE_LIMITS.items():
        limiter.set_limit(api_name, limit=config['limit'], window=config['window'])
    return limiter


# Initialize rate limiter
rate_limiter = init_rate_limiter()

# Initialize orchestrator
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(parents=True, exist_ok=True)

orchestrator = ScanOrchestrator(
    temp_dir=str(TEMP_DIR),
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
    title="SBOM API",
    description="Software Bill of Materials Generator API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
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
    return {
        "name": f"{TOOL_NAME} SBOM API",
        "version": TOOL_VERSION,
        "vendor": TOOL_VENDOR,
        "docs": "/docs",
        "workflow": [
            "1. POST /source_type - Set source type (repo_public, repo_private, zip, local)",
            "2. POST /validate/{type} - Validate your source",
            "3. POST /start_scan - Initialize scan",
            "4. POST /discover_and_parse - Find manifests and extract packages",
            "5. POST /fetch_depsdev - Enrich from deps.dev",
            "6. POST /registry_enrich - Enrich from PyPI/npm",
            "7. POST /fetch_osv - Fetch vulnerabilities",
            "8. POST /generate_sbom - Generate all SBOM formats"
        ]
    }


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
        validated=True,
        repo_name=result["repository"]
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
    
    # Update session with validated path and PAT
    update_session(
        session_token,
        local_path=result["local_path"],
        file_count=result["file_count"],
        validated=True,
        repo_name=result["repository"],
        pat=request.pat
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
        validated=True,
        repo_name=result["source"].replace('.zip', '').replace('.ZIP', '')
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
        validated=True,
        repo_name="uploaded_project"
    )
    
    return result


# =============================================================================
# 3. START SCAN ENDPOINT - Initialize scan with ID
# =============================================================================

@app.post("/start_scan", response_model=StartScanResponse)
async def start_scan(
    session: SessionData = Depends(require_validated_session()),
    session_token: str = Header(...)
):
    """
    Initialize the scan and assign a scan ID.
    
    **Requires:** Completed validation via one of the /validate/* endpoints.
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** Scan ID and workflow steps.
    """
    # Get next scan ID from orchestrator
    scan_id = orchestrator.get_next_scan_id()
    
    # Update session with scan ID
    update_session(session_token, scan_id=scan_id)
    
    return StartScanResponse(
        message="Scan initialized successfully",
        scan_id=scan_id,
        next_step="POST /discover_and_parse",
        workflow=[
            "/discover_and_parse - Find manifests and extract packages",
            "/fetch_depsdev - Enrich with deps.dev metadata",
            "/registry_enrich - Enrich from PyPI/npm registries",
            "/fetch_osv - Fetch vulnerabilities",
            "/generate_sbom - Generate all SBOM formats",
            "/generate_json - Generate detailed JSON report",
            "/generate_spdx - Generate SPDX SBOM",
            "/generate_cyclonedx - Generate CycloneDX SBOM",
            "/generate_remediation - Generate remediation report"
        ]
    )


# =============================================================================
# 4. DISCOVER AND PARSE ENDPOINT
# =============================================================================

@app.post("/discover_and_parse")
async def discover_and_parse(
    session: SessionData = Depends(require_scan_initialized()),
    session_token: str = Header(...)
):
    """
    Step 1+2 Combined: Discover manifests AND parse them in a single call.
    
    **Requires:** /start_scan to be called first (to get scan ID).
    
    **Headers:** `session-token: <token from /source_type>`
    
    This will:
    1. Scan the workspace for manifest files (requirements.txt, package.json, etc.)
    2. Parse the manifests to extract package dependencies
    """
    from src.registry.language_registry import get_language_for_manifest
    
    # Get absolute path from session's relative path
    # local_path is relative to Prism-SBOM (the project root where main_new.py is)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    workspace = Path(os.path.join(base_dir, session.local_path))
    
    if not workspace.exists():
        raise HTTPException(status_code=404, detail={
            "error": "SOURCE_NOT_FOUND",
            "message": "Validated source no longer exists. Please validate again."
        })
    
    # Check if already parsed
    packages = session.extra.get("packages")
    if packages:
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
            "next_step": "POST /fetch_depsdev"
        }
    
    # Discover manifests
    manifests = orchestrator.discover_manifests(workspace)
    
    # Parse manifests
    packages, cataloger_manifests = orchestrator.run_catalogers(workspace)
    
    # Scan codebase properties
    packages = orchestrator.scan_codebase_properties(workspace, packages)
    
    # Detect license
    license_info = None
    try:
        from src.utils.license_detector import detect_license_files, get_license_summary_for_sbom
        license_info = get_license_summary_for_sbom(workspace)
    except Exception as e:
        license_info = {"declared_license": "NOASSERTION", "error": str(e)}
    
    # Format manifest details
    manifest_details = []
    ecosystems_found = set()
    for m in manifests:
        if isinstance(m, dict):
            path = m.get("path", m.get("file", ""))
            filename = m.get("file", os.path.basename(str(path)))
        else:
            path = str(m)
            filename = os.path.basename(path)
        
        ecosystem = get_language_for_manifest(filename) or "unknown"
        ecosystems_found.add(ecosystem)
        manifest_details.append({"file": filename, "ecosystem": ecosystem, "path": path})
    
    # Group packages by ecosystem
    by_ecosystem = {}
    for p in packages:
        eco = p.get("language", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
    
    # Get codebase properties from first package
    codebase_props = {"executable": "No", "archive": "No", "structured_properties": "No"}
    if packages:
        codebase_props = {
            "executable": packages[0].get("executable", "No"),
            "archive": packages[0].get("archive", "No"),
            "structured_properties": packages[0].get("structured_properties", "No")
        }
    
    # Store in session
    update_session(
        session_token,
        packages=packages,
        manifest_files=manifests,
        ecosystems_detected=list(ecosystems_found),
        repo_license=license_info
    )
    
    # Format packages summary using orchestrator helper
    packages_summary = orchestrator.format_packages_summary(packages, limit=15)
    
    # Mark step as complete
    mark_step_complete(session_token, "discover_and_parse")
    
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
        "next_step": "POST /fetch_depsdev"
    }


# =============================================================================
# 5. FETCH DEPSDEV ENDPOINT
# =============================================================================

@app.post("/fetch_depsdev")
async def fetch_depsdev(
    session: SessionData = Depends(require_step("fetch_depsdev")),
    session_token: str = Header(...)
):
    """
    Step 3: Enrich packages with metadata AND transitive dependencies from deps.dev API.
    
    **Requires:** /discover_and_parse to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    
    Fields fetched:
    - license, homepage, release_date
    - component_dependencies (transitive deps)
    """
    from src.clients.depsdev_client import get_client
    from src.registry.language_registry import get_purl_type
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    # Mark direct dependencies and fetch transitive
    client = get_client()
    transitive_packages = []
    seen_packages = set()
    
    for p in packages:
        p["is_direct_dependency"] = True
        key = f"{p.get('name')}@{p.get('version')}"
        seen_packages.add(key.lower())
    
    # Fetch transitive dependencies
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        lang = (pkg.get("language") or pkg.get("ecosystem") or "").lower()
        
        if not name or not version:
            continue
        
        ecosystem = get_purl_type(lang)
        
        try:
            dep_graph = client.get_dependency_graph(ecosystem, name, version)
            all_deps = dep_graph.get("direct", []) + dep_graph.get("transitive", [])
            component_deps = []
            
            for dep in all_deps:
                dep_name = dep.get("name")
                dep_version = dep.get("version", "unknown")
                key = f"{dep_name}@{dep_version}"
                # Use simple PURL format here - CERT-IN format with real supplier will be applied
                # later in sbom_generator when we have enriched supplier data
                purl = f"pkg:{ecosystem}/{dep_name}@{dep_version}"
                component_deps.append(purl)
                
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
            pkg["component_dependencies"] = []
            pkg["total_dependencies"] = 0
    
    # Add transitive packages
    packages.extend(transitive_packages)
    
    # Enrich all packages with metadata
    packages = orchestrator.enrich_metadata(packages)
    
    # Second pass: fetch license from PyPI/npm for packages with NOASSERTION
    from src.clients.pypi_client import fetch_pypi_meta, extract_license_from_pypi_meta
    
    for p in packages:
        license_val = p.get("license") or p.get("component_license")
        # Check if license needs fallback to PyPI
        if not license_val or license_val in ["NOASSERTION", "non-standard", "unknown", "N/A", ""]:
            pkg_lang = (p.get("language") or "").lower()
            pkg_name = p.get("name")
            pkg_version = p.get("version")
            
            if pkg_lang == "python" and pkg_name:
                try:
                    meta = fetch_pypi_meta(pkg_name, pkg_version)
                    if meta:
                        pypi_license = extract_license_from_pypi_meta(meta)
                        if pypi_license and pypi_license not in ["NOASSERTION", ""]:
                            p["license"] = pypi_license
                            p["component_license"] = pypi_license
                except Exception:
                    pass
    
    # Update session
    update_session(session_token, packages=packages)
    
    # Build name->supplier mapping from enriched packages for CERT-IN PURL conversion
    from src.config import config
    supplier_map = {}
    for p in packages:
        pkg_name = p.get("name", "").lower()
        pkg_supplier = p.get("supplier") or p.get("component_supplier") or p.get("name")
        pkg_version = p.get("version", "")
        pkg_lang = (p.get("language") or "").lower()
        ecosystem = get_purl_type(pkg_lang) if pkg_lang else "pypi"
        # Generate CERT-IN PURL for this package
        cert_in_purl = config.generate_cert_in_identifier(ecosystem, p.get("name"), pkg_version, pkg_supplier)
        supplier_map[f"{pkg_name}@{pkg_version}".lower()] = cert_in_purl
        supplier_map[pkg_name] = {"supplier": pkg_supplier, "ecosystem": ecosystem}
    
    # Update component_dependencies to use CERT-IN format
    for p in packages:
        comp_deps = p.get("component_dependencies", [])
        if comp_deps:
            updated_deps = []
            for dep_purl in comp_deps:
                # Parse simple PURL like "pkg:pypi/flask@3.0.0"
                if "/" in dep_purl and "@" in dep_purl:
                    parts = dep_purl.split("/")[-1]  # "flask@3.0.0"
                    dep_name = parts.split("@")[0]
                    dep_version = parts.split("@")[1] if "@" in parts else ""
                    key = f"{dep_name}@{dep_version}".lower()
                    # Look up CERT-IN PURL from our mapping
                    if key in supplier_map:
                        updated_deps.append(supplier_map[key])
                    elif dep_name.lower() in supplier_map:
                        # Generate CERT-IN PURL using supplier info
                        info = supplier_map[dep_name.lower()]
                        cert_purl = config.generate_cert_in_identifier(
                            info["ecosystem"], dep_name, dep_version, info["supplier"]
                        )
                        updated_deps.append(cert_purl)
                    else:
                        updated_deps.append(dep_purl)  # Keep original if not found
                else:
                    updated_deps.append(dep_purl)
            p["component_dependencies"] = updated_deps
    
    # Use orchestrator helper methods for counting
    source_counts = orchestrator.count_by_metadata_source(packages)
    stats = orchestrator.calculate_statistics(packages)
    
    # Build complete package list with deps.dev fields for response
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
            "component_license": license_val,
            "homepage": p.get("homepage") or "N/A",
            "release_date": p.get("release_date") or "N/A",
            "component_dependencies": comp_deps
        })

    # Mark step as complete
    mark_step_complete(session_token, "fetch_depsdev")
    
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
        "next_step": "POST /registry_enrich"
    }


# =============================================================================
# 6. REGISTRY ENRICH ENDPOINT
# =============================================================================

@app.post("/registry_enrich")
async def registry_enrich(
    session: SessionData = Depends(require_step("registry_enrich")),
    session_token: str = Header(...)
):
    """
    Step 4: Enrich packages with registry data (PyPI/npm APIs).
    
    **Requires:** /fetch_depsdev to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    
    Fields fetched:
    - component_description, component_supplier, hashes, unique_identifier
    """
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    # Use orchestrator's registry_enrich method
    packages = orchestrator.registry_enrich(packages)
    
    # Update session
    update_session(session_token, packages=packages)
    
    # Use orchestrator helper methods for counting
    registry_counts = orchestrator.count_by_registry(packages)
    stats = orchestrator.calculate_statistics(packages)
    
    # Build packages list with registry fields for response
    all_packages = []
    for p in packages:
        lang = (p.get("language") or "").lower()
        registry = "PyPI" if lang in ["python", "pip"] else "npm" if lang in ["javascript", "npm", "node"] else "unknown"
        is_direct = p.get("is_direct_dependency", True)
        
        # Format hashes as array of {alg, content}
        hashes_list = []
        hashes = p.get("hashes", {})
        if isinstance(hashes, dict):
            for alg, content in hashes.items():
                if content:
                    hashes_list.append({"alg": alg.upper(), "content": content})
        elif isinstance(hashes, list):
            hashes_list = hashes
        
        all_packages.append({
            "component_name": p.get("name"),
            "version": p.get("version"),
            "is_direct_dependency": is_direct,
            "dependency_type": "direct" if is_direct else "transitive",
            "registry": registry,
            "component_description": p.get("component_description") or "N/A",
            "component_supplier": p.get("component_supplier") or "N/A",
            "hashes": hashes_list if hashes_list else "N/A",
            "unique_identifier": p.get("unique_identifier") or f"pkg:{registry.lower()}/{p.get('name')}@{p.get('version')}",
            "eol_status": p.get("eol_status", "Active"),
            "is_deprecated": p.get("is_deprecated", False)
        })
    
    # Mark step as complete
    mark_step_complete(session_token, "registry_enrich")
    
    return {
        "message": "Registry enrichment complete (includes EOL/deprecation check)",
        "scan_id": session.scan_id,
        "total_packages": stats["scan_summary"]["total_components"],
        "pypi_packages": registry_counts["pypi"],
        "npm_packages": registry_counts["npm"],
        "deprecated_packages": stats["scan_summary"]["deprecated_packages"],
        "fields_added": ["component_description", "component_supplier", "hashes", "unique_identifier", "eol_status", "is_deprecated"],
        "packages": all_packages,
        "next_step": "POST /fetch_osv"
    }


# =============================================================================
# 7. FETCH OSV ENDPOINT
# =============================================================================

@app.post("/fetch_osv")
async def fetch_osv(
    session: SessionData = Depends(require_step("fetch_osv")),
    session_token: str = Header(...)
):
    """
    Step 5: Fetch vulnerabilities from OSV database.
    
    **Requires:** /registry_enrich to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    
    Fields fetched:
    - vulnerabilities (id, severity, summary, fixed_in, etc.)
    - patch_status, criticality (derived)
    """
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    # Fetch vulnerabilities
    packages, vuln_count = orchestrator.fetch_vulnerabilities(packages)
    
    # Update session
    update_session(session_token, packages=packages)
    
    # Use orchestrator's centralized statistics calculation
    stats = orchestrator.calculate_statistics(packages)
    
    # Build vulnerable packages list for response (formatted for display)
    vulnerable_packages = orchestrator.format_vulnerable_packages(packages)
    
    # Mark step as complete
    mark_step_complete(session_token, "fetch_osv")
    
    return {
        "message": "Vulnerability scan complete",
        "scan_id": session.scan_id,
        "packages_scanned": stats["scan_summary"]["total_components"],
        "packages_affected": stats["vulnerability_summary"]["packages_affected"],
        "vulnerabilities_found": stats["vulnerability_summary"]["total"],
        "severity_breakdown": stats["vulnerability_summary"]["by_severity"],
        "patchable": stats["vulnerability_summary"]["patchable"],
        "unpatchable": stats["vulnerability_summary"]["unpatchable"],
        "fields_fetched": ["id", "severity", "severity_level", "summary", "fixed_in", "url", "aliases", "details"],
        "fields_derived": ["patch_status", "criticality"],
        "vulnerable_packages": vulnerable_packages,
        "next_step": "POST /generate_sbom"
    }


# =============================================================================
# 8. GENERATE SBOM ENDPOINT
# =============================================================================

@app.post("/generate_sbom")
async def generate_sbom(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Step 6: Generate all SBOM reports (JSON, SPDX, CycloneDX).
    
    **Requires:** /fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    
    **Returns:** All generated SBOM data.
    """
    from src.core.sbom_generator import generate_json_sbom, generate_spdx_sbom, generate_cyclonedx_sbom, generate_remediation_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    # Build catalog
    catalog = orchestrator.build_catalog(
        packages=packages,
        manifests=manifests,
        project_name=project_name,
        source=project_name,
        scan_id=scan_id
    )
    
    # Add license_detection to catalog from session
    license_detection = session.extra.get("repo_license")
    if license_detection:
        catalog["license_detection"] = license_detection
    
    # Store catalog in session
    update_session(session_token, catalog=catalog)
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    # Generate all formats (no file saving)
    json_sbom = generate_json_sbom(catalog, metadata)
    spdx_sbom = generate_spdx_sbom(catalog, metadata)
    cyclonedx_sbom = generate_cyclonedx_sbom(catalog, metadata)
    remediation_sbom = generate_remediation_sbom(catalog, metadata)
    
    # Calculate statistics using orchestrator's centralized method
    stats = orchestrator.calculate_statistics(packages)
    
    # Components summary (sample)
    components_preview = []
    for p in packages[:5]:  # Show first 5 as preview
        components_preview.append({
            "name": p.get("name"),
            "version": p.get("version"),
            "license": p.get("component_license") or p.get("license") or "NOASSERTION",
            "vulnerabilities_count": len(p.get("vulnerabilities", []))
        })
    
    return {
        "message": "SBOM generation complete",
        "scan_id": scan_id,
        "project_name": project_name,
        "scan_summary": {
            **stats["scan_summary"],
            "ecosystems": session.extra.get("ecosystems_detected", [])
        },
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


# =============================================================================
# 9. GENERATE JSON SBOM ONLY
# =============================================================================

@app.post("/generate_json")
async def generate_json_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate JSON SBOM format only.
    
    **Requires:** /fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    """
    from src.core.sbom_generator import generate_json_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    # Build catalog if not exists
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
        update_session(session_token, catalog=catalog)
    
    # Add license_detection to catalog from session
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
    
    # Calculate statistics using orchestrator's centralized method
    stats = orchestrator.calculate_statistics(packages)
    
    # Return response directly (no file saved)
    return {
        "message": "JSON SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "full_report": json_sbom
    }


# =============================================================================
# 10. GENERATE SPDX SBOM ONLY
# =============================================================================

@app.post("/generate_spdx")
async def generate_spdx_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate SPDX SBOM format only.
    
    **Requires:** /fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    """
    from src.core.sbom_generator import generate_spdx_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    # Build catalog if not exists
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
        update_session(session_token, catalog=catalog)
    
    # Add license_detection to catalog from session
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
    
    # Calculate statistics using orchestrator's centralized method
    stats = orchestrator.calculate_statistics(packages)
    
    # Return response directly (no file saved)
    return {
        "message": "SPDX SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "full_report": spdx_sbom
    }


# =============================================================================
# 11. GENERATE CYCLONEDX SBOM ONLY
# =============================================================================

@app.post("/generate_cyclonedx")
async def generate_cyclonedx_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate CycloneDX SBOM format only.
    
    **Requires:** /fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    """
    from src.core.sbom_generator import generate_cyclonedx_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    # Build catalog if not exists
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
        update_session(session_token, catalog=catalog)
    
    # Add license_detection to catalog from session
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
    
    # Calculate statistics using orchestrator's centralized method
    stats = orchestrator.calculate_statistics(packages)
    
    # Return response directly (no file saved)
    return {
        "message": "CycloneDX SBOM generated",
        "scan_id": scan_id,
        "scan_summary": stats["scan_summary"],
        "vulnerability_summary": stats["vulnerability_summary"],
        "license_summary": stats["license_summary"],
        "full_report": cyclonedx_sbom
    }


# =============================================================================
# 12. GENERATE REMEDIATION REPORT ONLY
# =============================================================================

@app.post("/generate_remediation")
async def generate_remediation_endpoint(
    session: SessionData = Depends(require_step("generate")),
    session_token: str = Header(...)
):
    """
    Generate remediation report only.
    
    **Requires:** /fetch_osv to be called first.
    
    **Headers:** `session-token: <token from /source_type>`
    """
    from src.core.sbom_generator import generate_remediation_sbom
    
    packages = session.extra.get("packages")
    if not packages:
        raise HTTPException(status_code=400, detail={
            "error": "NO_PACKAGES",
            "message": "No packages found. Run /discover_and_parse first."
        })
    
    scan_id = session.scan_id
    project_name = session.repo_name or f"project_{scan_id}"
    manifests = session.extra.get("manifest_files", [])
    
    # Build catalog if not exists
    catalog = session.extra.get("catalog")
    if not catalog:
        catalog = orchestrator.build_catalog(
            packages=packages,
            manifests=manifests,
            project_name=project_name,
            source=project_name,
            scan_id=scan_id
        )
        update_session(session_token, catalog=catalog)
    
    metadata = {
        "timestamp": catalog.get("timestamp"),
        "tool": catalog.get("tool", {}),
        "source": catalog.get("source"),
        "scan_id": scan_id
    }
    
    remediation_sbom = generate_remediation_sbom(catalog, metadata)
    
    # Return response directly (no file saved)
    # Remediation only returns fix data, no vulnerability_summary or license_summary
    return {
        "message": "Remediation report generated",
        "scan_id": scan_id,
        "full_report": remediation_sbom
    }



# =============================================================================
# Run with: uvicorn main:app --port 8000
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
