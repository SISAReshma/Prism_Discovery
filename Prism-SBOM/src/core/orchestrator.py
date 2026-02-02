"""
Scan Orchestrator - Unified pipeline manager for SBOM scanning.

This is the SINGLE ENTRY POINT for all scanning operations.
It coordinates all steps in the correct order:

    1. Prepare Workspace (git clone / extract ZIP / use local path)
    2. Discover Manifests (requirements.txt, package.json, etc.)
    3. Run Catalogers (Python, npm)
    4. Enrich Metadata (deps.dev for license, homepage, release date)
    5. Fetch Vulnerabilities (OSV primary, NVD fallback)
    6. Add Exploit Intelligence (EPSS scores, CISA KEV)
    7. Generate SBOM Reports (SPDX, CycloneDX, JSON)
    8. Generate Remediation Report
    9. Generate Executive Summary
    10. Cleanup Temporary Files

Usage:
    from src.core.orchestrator import ScanOrchestrator
    
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(
        source="https://github.com/user/repo",
        source_type="repo",
        token="ghp_xxxx"  # Optional for private repos
    )
"""

from __future__ import annotations
import uuid
import json
import shutil
from pathlib import Path
import os
import stat
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import time

# Import rate limiter for registry API calls
from src.utils.rate_limiter import get_rate_limiter
from src.registry.language_registry import get_purl_type

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiter for registry APIs
_registry_rate_limiter = get_rate_limiter()


def _rate_limited_request(url: str, api_name: str, timeout: int = 5) -> Optional[Any]:
    """
    Make a rate-limited HTTP request.
    
    Args:
        url: URL to fetch
        api_name: API identifier for rate limiting (pypi, npm, osv)
        timeout: Request timeout in seconds
    
    Returns:
        Response object or None if rate limited/failed
    """
    import requests
    
    # Check rate limit
    usage = _registry_rate_limiter.get_current_usage(api_name)
    if usage['remaining'] <= 0:
        logger.warning(f"[RATE LIMIT] {api_name}: Rate limit exceeded, skipping request")
        return None
    
    # Record the call
    _registry_rate_limiter.record_call(api_name)
    
    # Add small delay between requests (100ms) to avoid bursts
    time.sleep(0.1)
    
    try:
        return requests.get(url, timeout=timeout)
    except Exception as e:
        logger.debug(f"[{api_name}] Request failed: {e}")
        return None


class SourceType(str, Enum):
    """Source types for scanning"""
    REPO = "repo"       # Git repository URL
    LOCAL = "local"     # Local folder path
    ZIP = "zip"         # ZIP file path


class ScanStatus(str, Enum):
    """Scan status states"""
    PENDING = "pending"
    PREPARING = "preparing"
    CATALOGING = "cataloging"
    ENRICHING = "enriching"
    VULNERABILITIES = "vulnerabilities"
    REPORTS = "reports"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanProgress:
    """Track scan progress for API status updates"""
    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    current_step: str = ""
    steps_completed: int = 0
    total_steps: int = 10
    started_at: str = ""
    completed_at: str = ""
    error: str = ""
    packages_found: int = 0
    vulnerabilities_found: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "current_step": self.current_step,
            "progress_percent": int((self.steps_completed / self.total_steps) * 100),
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "packages_found": self.packages_found,
            "vulnerabilities_found": self.vulnerabilities_found
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    success: bool
    packages: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities_count: int = 0
    reports: Dict[str, str] = field(default_factory=dict)  # format -> path
    remediation_path: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "success": self.success,
            "packages_count": len(self.packages),
            "vulnerabilities_count": self.vulnerabilities_count,
            "reports": self.reports,
            "remediation_path": self.remediation_path,
            "errors": self.errors,
            "warnings": self.warnings,
            "duration_seconds": self.duration_seconds
        }


class ScanOrchestrator:
    """
    Unified orchestrator for SBOM scanning pipeline.
    
    This class manages the complete scan workflow in a single place,
    making it easy to understand, debug, and extend.
    """
    
    def __init__(
        self,
        reports_dir: Optional[str] = None,
        temp_dir: Optional[str] = None,
        nvd_api_key: Optional[str] = None
    ):
        """
        Initialize the orchestrator.
        
        Args:
            reports_dir: Directory for output reports
            temp_dir: Directory for temporary files
            nvd_api_key: Optional NVD API key for vulnerability lookup
        """
        from src.config.config import REPORTS_DIR, TEMP_DIR
        
        self.reports_dir = Path(reports_dir or REPORTS_DIR)
        self.temp_dir = Path(temp_dir or TEMP_DIR)
        self.nvd_api_key = nvd_api_key
        
        # Ensure directories exist
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Track active scans for status queries
        self._active_scans: Dict[str, ScanProgress] = {}
        
        # Initialize sequential scan ID counter
        self._scan_counter_file = self.reports_dir / "scan_counter.json"
        self._load_scan_counter()
    
    def _load_scan_counter(self):
        """Load or initialize the sequential scan ID counter"""
        # If a counter file exists, load it. If not, derive next ID
        # from existing numeric report directories to avoid accidental
        # resets when the counter file is missing or corrupted.
        try:
            if self._scan_counter_file.exists():
                with open(self._scan_counter_file, 'r') as f:
                    data = json.load(f)
                    loaded = int(data.get('next_scan_number', 1))
            else:
                loaded = None

            # Compute highest numeric folder under reports and use that to
            # ensure the next scan number is always greater than existing ones.
            existing_nums = []
            for child in self.reports_dir.iterdir():
                if child.is_dir():
                    name = child.name
                    if name.isdigit():
                        try:
                            existing_nums.append(int(name))
                        except Exception:
                            pass

            max_existing = max(existing_nums) if existing_nums else 0

            if loaded is None:
                # No counter file: start at max_existing + 1
                self._next_scan_number = max_existing + 1
            else:
                # Ensure counter is at least max_existing + 1
                self._next_scan_number = max(loaded, max_existing + 1)

            # Persist corrected counter (in case we bumped it)
            self._save_scan_counter()

        except Exception as e:
            logger.warning(f"Failed to initialize scan counter: {e}. Starting from 1.")
            self._next_scan_number = 1
            try:
                self._save_scan_counter()
            except Exception:
                pass
    
    def _save_scan_counter(self):
        """Save the sequential scan ID counter"""
        try:
            with open(self._scan_counter_file, 'w') as f:
                json.dump({'next_scan_number': self._next_scan_number}, f)
        except Exception as e:
            logger.warning(f"Failed to save scan counter: {e}")
    
    def _get_next_scan_id(self) -> str:
        """Get the next sequential scan ID (1, 2, 3, ...)"""
        scan_id = str(self._next_scan_number)
        self._next_scan_number += 1
        self._save_scan_counter()
        return scan_id
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of an active or completed scan."""
        if scan_id in self._active_scans:
            return self._active_scans[scan_id].to_dict()
        
        # Check if scan completed (has reports)
        scan_dir = self.reports_dir / scan_id
        if scan_dir.exists():
            # Check for SBOM JSON report to determine completion
            sbom_json_path = scan_dir / f"{scan_id}.json.json"
            if sbom_json_path.exists():
                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "progress_percent": 100
                }
        
        return None

    # ========================================================================
    # PUBLIC STEP-BY-STEP API
    # ========================================================================
    # These methods expose individual pipeline steps for fine-grained control.
    # Use these when you need to run steps independently or integrate with
    # external workflows.
    
    def prepare_workspace(
        self,
        source: str,
        source_type: str,
        scan_id: str,
        token: Optional[str] = None,
        username: Optional[str] = None
    ) -> Path:
        """
        Step 1: Prepare workspace from source.
        
        Public wrapper for workspace preparation.
        
        Args:
            source: Repository URL, ZIP path, or local path
            source_type: "repo", "zip", or "local"
            scan_id: Unique scan identifier
            token: Optional auth token for private repos
            username: Optional username for auth
            
        Returns:
            Path to prepared workspace
        """
        return self._prepare_workspace(source, source_type, scan_id, token, username)
    
    def discover_manifests(self, workspace: Path) -> List[str]:
        """
        Step 2: Discover manifest files in workspace.
        
        Args:
            workspace: Path to workspace directory
            
        Returns:
            List of manifest file paths
        """
        return self._discover_manifests(workspace)
    
    def run_catalogers(self, workspace: Path) -> Tuple[List[Dict], List[str]]:
        """
        Step 3: Run language catalogers to extract packages.
        
        Args:
            workspace: Path to workspace directory
            
        Returns:
            Tuple of (packages list, manifest paths)
        """
        return self._run_catalogers(workspace)
    
    def enrich_metadata(self, packages: List[Dict]) -> List[Dict]:
        """
        Step 4: Enrich packages with metadata from deps.dev.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Enriched packages list
        """
        return self._enrich_metadata(packages)
    
    def registry_enrich(self, packages: List[Dict]) -> List[Dict]:
        """
        Step 4b: Registry enrichment for description, supplier, hashes, and unique_identifier fields.
        
        Uses registry APIs (PyPI, npm) to fetch metadata that deps.dev doesn't provide.
        
        NOTE: executable, archive, structured_properties are now detected via codebase scanning
        (see scan_codebase_properties method).
        
        Supported ecosystems: Python and npm only.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Packages with description, supplier, hashes, unique_identifier fields
        """
        return self._registry_enrich(packages)
    
    def scan_codebase_properties(self, workspace: Path, packages: List[Dict]) -> List[Dict]:
        """
        Step 4c: Scan codebase for CERT-IN required properties.
        
        Scans the actual repository/codebase to detect:
        - Executable files (.exe, .dll, .sh, .bat, .ps1, etc.)
        - Archive files (.zip, .tar.gz, .jar, .whl, etc.)
        - Structured files (.json, .xml, .yaml, .toml, .sql, etc.)
        - Bundled dependency directories (vendor/, dist/, etc.)
        
        These properties are applied to ALL components since they describe
        what the CODEBASE contains, not individual packages.
        
        Args:
            workspace: Path to the codebase/repository
            packages: List of package dictionaries
            
        Returns:
            Packages with executable, archive, structured_properties fields set
        """
        return self._scan_codebase_properties(workspace, packages)
    
    def fetch_vulnerabilities(self, packages: List[Dict]) -> Tuple[List[Dict], int]:
        """
        Step 5: Fetch vulnerabilities from OSV and NVD.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Tuple of (enriched packages, vulnerability count)
        """
        return self._fetch_vulnerabilities(packages)
    
    def add_exploit_intel(self, packages: List[Dict]) -> Tuple[List[Dict], int]:
        """
        Step 6: Add EPSS scores (CISA KEV disabled - V2 feature).
        
        NOTE: CISA KEV support removed. This method is kept for API compatibility.
        
        Args:
            packages: List of package dictionaries with vulnerabilities
            
        Returns:
            Tuple of (packages unchanged, 0)
        """
        # V2 TODO: Re-enable exploit intelligence
        return packages, 0
    
    def build_catalog(
        self,
        packages: List[Dict],
        manifests: List[str],
        project_name: str,
        source: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Step 7: Build the final catalog structure.
        
        Args:
            packages: List of enriched packages
            manifests: List of manifest file paths
            project_name: Name of the project
            source: Source URL or path
            scan_id: Unique scan identifier
            
        Returns:
            Complete catalog dictionary
        """
        return self._build_catalog(packages, manifests, project_name, source, scan_id)
    
    def generate_sbom_reports(
        self,
        catalog: Dict[str, Any],
        scan_id: str
    ) -> Dict[str, str]:
        """
        Step 8: Generate SBOM reports in multiple formats.
        
        Args:
            catalog: Complete catalog dictionary
            scan_id: Unique scan identifier
            
        Returns:
            Dict mapping format name to file path
        """
        return self._generate_sbom_reports(catalog, scan_id)
    
    def generate_remediation_report(
        self,
        catalog: Dict[str, Any],
        scan_id: str,
        source: str
    ) -> str:
        """
        Step 9: Generate remediation report.
        
        Args:
            catalog: Complete catalog dictionary
            scan_id: Unique scan identifier
            source: Source URL or path
            
        Returns:
            Path to generated remediation report
        """
        return self._generate_remediation_report(catalog, scan_id, source)
    
    # NOTE: generate_executive_summary removed - executive summary not needed
    
    def get_next_scan_id(self) -> str:
        """
        Get the next sequential scan ID.
        
        Returns:
            New unique scan ID
        """
        return self._get_next_scan_id()
    
    def cleanup_workspace(self, workspace: Path):
        """
        Cleanup temporary workspace after scan.
        
        Args:
            workspace: Path to workspace to clean up
        """
        self._cleanup_workspace(workspace)

    # ========================================================================
    # MAIN ORCHESTRATION METHOD
    # ========================================================================

    def run_scan(
        self,
        source: str,
        source_type: str = "repo",
        scan_id: Optional[str] = None,
        token: Optional[str] = None,
        username: Optional[str] = None,
        project_name: Optional[str] = None,
        cleanup_after: bool = True,
        progress_callback: Optional[callable] = None
    ) -> ScanResult:
        """
        Run complete scan pipeline.
        
        Args:
            source: Repository URL, local path, or ZIP path
            source_type: "repo", "local", or "zip"
            scan_id: Optional custom scan ID (auto-generated if not provided)
            token: Optional auth token for private repos
            username: Optional username for auth
            project_name: Optional project name for reports
            cleanup_after: Whether to cleanup temp files after scan
            progress_callback: Optional callback function(step_num, step_name, progress_percent)
            
        Returns:
            ScanResult with all scan data
        """
        self._progress_callback = progress_callback
        import time
        start_time = time.time()
        
        # Generate sequential scan ID (1, 2, 3, ...)
        # Don't use custom scan_id parameter - always use sequential IDs
        scan_id = self._get_next_scan_id()
        
        # Initialize progress tracking
        progress = ScanProgress(
            scan_id=scan_id,
            started_at=datetime.now(timezone.utc).isoformat()
        )
        self._active_scans[scan_id] = progress
        
        # Initialize result
        result = ScanResult(scan_id=scan_id, success=False)
        
        workspace = None
        
        try:
            # ================================================================
            # STEP 1: Prepare Workspace
            # ================================================================
            self._update_progress(progress, ScanStatus.PREPARING, "Preparing workspace...", 1)
            
            workspace = self._prepare_workspace(
                source=source,
                source_type=source_type,
                scan_id=scan_id,
                token=token,
                username=username
            )
            
            if not workspace or not workspace.exists():
                raise ValueError(f"Failed to prepare workspace from: {source}")
            
            logger.info(f"[STEP 1/10] Workspace prepared: {workspace}")
            
            # Infer project name if not provided
            if not project_name:
                project_name = workspace.name
            
            # ================================================================
            # STEP 2: Discover Manifests
            # ================================================================
            self._update_progress(progress, ScanStatus.CATALOGING, "Discovering manifests...", 2)
            
            manifests = self._discover_manifests(workspace)
            logger.info(f"[STEP 2/10] Found {len(manifests)} manifest files")
            
            # ================================================================
            # STEP 3: Run Catalogers (Python, npm)
            # ================================================================
            self._update_progress(progress, ScanStatus.CATALOGING, "Running catalogers...", 3)
            
            packages, cataloger_manifests = self._run_catalogers(workspace)
            
            # Merge manifests
            all_manifests = list(set(manifests + cataloger_manifests))
            
            progress.packages_found = len(packages)
            logger.info(f"[STEP 3/10] Catalogers found {len(packages)} packages")
            
            # ================================================================
            # STEP 4: Enrich Metadata (deps.dev)
            # ================================================================
            self._update_progress(progress, ScanStatus.ENRICHING, "Enriching metadata...", 4)

            # Expand transitive dependencies (CLI path)
            packages, transitive_count = self._expand_transitive_dependencies(packages)
            if transitive_count:
                logger.info(f"[STEP 4/10] Added {transitive_count} transitive dependencies")

            packages = self._enrich_metadata(packages)
            logger.info(f"[STEP 4/10] Metadata enrichment complete")
            
            # ================================================================
            # STEP 4b: Registry Enrichment (description, supplier, hashes)
            # ================================================================
            packages = self._registry_enrich(packages)
            logger.info(f"[STEP 4b/10] Registry enrichment complete")
            
            # ================================================================
            # STEP 4c: Codebase Property Scanning (CERT-IN: executable, archive, structured)
            # ================================================================
            packages = self._scan_codebase_properties(workspace, packages)
            logger.info(f"[STEP 4c/10] Codebase property scanning complete")
            
            # ================================================================
            # STEP 5: Fetch Vulnerabilities (OSV + NVD)
            # ================================================================
            self._update_progress(progress, ScanStatus.VULNERABILITIES, "Fetching vulnerabilities...", 5)
            
            packages, vuln_count = self._fetch_vulnerabilities(packages)
            
            progress.vulnerabilities_found = vuln_count
            logger.info(f"[STEP 5/10] Found {vuln_count} vulnerabilities")
            
            # ================================================================
            # STEP 6: Build Catalog (KEV/EPSS removed - V2 feature)
            # ================================================================
            self._update_progress(progress, ScanStatus.REPORTS, "Building catalog...", 6)
            
            # NOTE: CISA KEV and EPSS exploit intelligence is disabled (V2 feature)
            logger.info(f"[STEP 6/10] Exploit intelligence skipped (V2 feature)")
            
            # ================================================================
            # STEP 7: Build Catalog
            # ================================================================
            self._update_progress(progress, ScanStatus.REPORTS, "Building catalog...", 7)
            
            catalog = self._build_catalog(
                packages=packages,
                manifests=all_manifests,
                project_name=project_name,
                source=source,
                scan_id=scan_id
            )
            logger.info(f"[STEP 7/10] Catalog built")
            
            # ================================================================
            # STEP 8: Generate SBOM Reports (SPDX, CycloneDX, JSON)
            # ================================================================
            self._update_progress(progress, ScanStatus.REPORTS, "Generating SBOM reports...", 8)
            
            report_paths = self._generate_sbom_reports(catalog, scan_id)
            
            result.reports = report_paths
            logger.info(f"[STEP 8/9] SBOM reports generated: {list(report_paths.keys())}")
            
            # ================================================================
            # STEP 9: Generate Remediation Report (FINAL STEP)
            # ================================================================
            self._update_progress(progress, ScanStatus.REPORTS, "Generating remediation report...", 9)
            
            remediation_path = self._generate_remediation_report(catalog, scan_id, source)
            
            result.remediation_path = remediation_path
            logger.info(f"[STEP 9/9] Remediation report generated")
            
            # NOTE: Executive summary generation removed - not needed
            
            # ================================================================
            # COMPLETE
            # ================================================================
            result.success = True
            result.packages = packages
            result.vulnerabilities_count = vuln_count
            result.duration_seconds = time.time() - start_time
            
            self._update_progress(
                progress, 
                ScanStatus.COMPLETED, 
                "Scan completed successfully", 
                10
            )
            progress.completed_at = datetime.now(timezone.utc).isoformat()
            
            logger.info(f"Scan {scan_id} completed in {result.duration_seconds:.2f}s")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            import traceback
            traceback.print_exc()
            
            result.errors.append(str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            progress.completed_at = datetime.now(timezone.utc).isoformat()
        
        finally:
            # Always cleanup temp workspace after scan (success or failure)
            if workspace and workspace.exists():
                try:
                    # Only cleanup if workspace is in temp directory
                    if str(workspace).startswith(str(self.temp_dir)):
                        logger.info(f"Cleaning up workspace: {workspace}")
                        self._cleanup_workspace(workspace)
                        logger.info(f"Workspace cleanup successful")
                except Exception as e:
                    logger.warning(f"Cleanup failed: {e}")
                    result.warnings.append(f"Cleanup failed: {e}")
        
        return result
    
    # ========================================================================
    # PRIVATE METHODS - Individual Pipeline Steps
    # ========================================================================
    
    def _update_progress(
        self, 
        progress: ScanProgress, 
        status: ScanStatus, 
        step: str, 
        step_num: int
    ):
        """Update progress tracking."""
        progress.status = status
        progress.current_step = step
        progress.steps_completed = step_num
        print(f"[{step_num}/10] {step}")
        
        # Call progress callback if provided
        if hasattr(self, '_progress_callback') and self._progress_callback:
            try:
                # Calculate progress percentage (step 1-10 maps to 10-100%)
                progress_percent = step_num * 10
                self._progress_callback(step_num, step, progress_percent)
            except Exception:
                pass  # Don't let callback errors affect the scan
    
    def _prepare_workspace(
        self,
        source: str,
        source_type: str,
        scan_id: str,
        token: Optional[str] = None,
        username: Optional[str] = None
    ) -> Path:
        """
        Step 1: Prepare workspace from source.
        
        Handles:
        - Git clone (with optional auth)
        - ZIP extraction
        - Local path validation
        """
        from src.utils.git_utils import git_clone
        from src.utils.file_utils import extract_zip
        
        source_type = source_type.lower()
        
        if source_type == "repo":
            # Clone repository
            workspace = self.temp_dir / scan_id
            workspace.mkdir(parents=True, exist_ok=True)
            
            git_clone(
                repo=source,
                dst=workspace,
                token=token,
                username=username
            )
            return workspace
            
        elif source_type == "zip":
            # Extract ZIP
            workspace = self.temp_dir / scan_id
            workspace.mkdir(parents=True, exist_ok=True)
            
            extract_zip(source, workspace)
            return workspace
            
        elif source_type == "local":
            # Use local path directly
            local_path = Path(source).resolve()
            if not local_path.exists():
                raise ValueError(f"Local path does not exist: {source}")
            return local_path
            
        else:
            raise ValueError(f"Invalid source type: {source_type}")
    
    def _discover_manifests(self, workspace: Path) -> List[str]:
        """
        Step 2: Discover all manifest files in workspace.
        """
        from src.core.scanner import _discover_manifests
        return _discover_manifests(workspace)
    
    def _run_catalogers(self, workspace: Path) -> Tuple[List[Dict], List[str]]:
        """
        Step 3: Run catalogers (Python, npm).
        
        Returns:
            Tuple of (packages list, manifest paths list)
        """
        from src.core.scanner import _run_catalogers
        
        packages, manifests, _ = _run_catalogers(workspace, nvd_api_key=self.nvd_api_key)
        return packages, manifests
    
    def _enrich_metadata(self, packages: List[Dict]) -> List[Dict]:
        """
        Step 4: Enrich packages with metadata from deps.dev.
        
        Adds:
        - License information
        - Release date
        - Homepage
        - Dependency graph
        - metadata_source field for tracking
        """
        try:
            from src.clients.depsdev_client import get_client
            
            client = get_client()
            
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")
                lang = (pkg.get("language") or "").lower()
                
                if not name or not version or version == "UNKNOWN":
                    pkg["metadata_source"] = "fallback"
                    continue
                
                # Map language to deps.dev ecosystem
                ecosystem = get_purl_type(lang)
                
                try:
                    # Fetch metadata
                    metadata = client.get_metadata(ecosystem, name, version)
                    
                    if metadata:
                        # Mark source as deps.dev
                        pkg["metadata_source"] = "deps.dev"
                        
                        # License - avoid deps.dev non-standard/unknown values
                        license_val = metadata.get("license", "NOASSERTION")
                        bad_license = {"", "noassertion", "non-standard", "unknown"}
                        if str(license_val).strip().lower() not in bad_license:
                            if not pkg.get("license") or pkg.get("license") in ["NOASSERTION", "non-standard", "unknown"]:
                                pkg["license"] = license_val
                            if not pkg.get("component_license") or pkg.get("component_license") in ["NOASSERTION", "non-standard", "unknown"]:
                                pkg["component_license"] = license_val
                        else:
                            # Fallback to PyPI license if deps.dev is non-standard
                            try:
                                from src.utils.package_metadata_utils import fetch_pypi_meta, extract_license_from_pypi_meta
                                meta = fetch_pypi_meta(name, version)
                                pypi_license = extract_license_from_pypi_meta(meta) if meta else "NOASSERTION"
                                if pypi_license and pypi_license != "NOASSERTION":
                                    pkg["license"] = pypi_license
                                    pkg["component_license"] = pypi_license
                            except Exception:
                                pass
                        
                        # Release date - use published_at from deps.dev
                        published = metadata.get("published_at", "")
                        if published and (not pkg.get("release_date")):
                            pkg["release_date"] = published
                        
                        # Homepage
                        homepage = metadata.get("homepage", "")
                        if homepage and (not pkg.get("homepage")):
                            pkg["homepage"] = homepage
                    else:
                        pkg["metadata_source"] = "fallback"
                        
                except Exception as e:
                    logger.debug(f"Failed to enrich {name}: {e}")
                    pkg["metadata_source"] = "fallback"
                    
        except ImportError:
            logger.warning("deps.dev client not available for metadata enrichment")
            for pkg in packages:
                pkg["metadata_source"] = "fallback"
        
        return packages

    def _expand_transitive_dependencies(self, packages: List[Dict]) -> Tuple[List[Dict], int]:
        """
        Expand transitive dependencies using deps.dev graph.

        Returns:
            (packages_with_transitives, transitive_count)
        """
        try:
            from src.clients.depsdev_client import get_client

            client = get_client()
            transitive_packages: List[Dict] = []
            seen_packages = set()

            # Mark direct dependencies
            for p in packages:
                p["is_direct_dependency"] = True
                key = f"{p.get('name')}@{p.get('version')}"
                seen_packages.add(key.lower())

            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")
                lang = (pkg.get("language") or pkg.get("ecosystem") or "").lower()

                if not name or not version:
                    continue

                ecosystem = get_purl_type(lang)

                try:
                    dep_graph = client.get_dependency_graph(ecosystem, name, version)
                    if not dep_graph:
                        continue

                    component_deps = []
                    for dep in dep_graph.get("direct", []) + dep_graph.get("transitive", []):
                        dep_name = dep.get("name")
                        dep_version = dep.get("version", "unknown")
                        key = f"{dep_name}@{dep_version}"

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
                    logger.debug(f"[deps.dev] Failed dep graph for {name}@{version}: {e}")
                    pkg["component_dependencies"] = []
                    pkg["total_dependencies"] = 0

            if transitive_packages:
                packages.extend(transitive_packages)

            return packages, len(transitive_packages)

        except Exception as e:
            logger.warning(f"deps.dev transitive expansion failed: {e}")
            return packages, 0
    
    def _registry_enrich(self, packages: List[Dict]) -> List[Dict]:
        """
        Registry enrichment: fills description, supplier, hashes, and unique_identifier fields.
        
        Uses API FIRST, then cache as fallback (on rate limit or error):
        - description: Package summary/description (deps.dev doesn't provide this)
        - supplier: Package author/maintainer (deps.dev doesn't provide this)
        - hashes: SHA-256/SHA-512 checksums (deps.dev doesn't provide this)
        - unique_identifier: PURL format identifier
        
        NOTE: executable, archive, structured_properties are now detected via codebase scanning
        (see _scan_codebase_properties method) per CERT-IN guidelines.
        
        Flow:
        1. Call API first (PyPI/npm registry)
        2. If API succeeds - use and cache the response
        3. If rate limited or error - fallback to cache
        
        Supported ecosystems: Python (PyPI) and npm only.
        """
        # Import cache functions
        try:
            from src.utils.cache_manager import get_pypi_cache, set_pypi_cache, get_npm_cache, set_npm_cache
            cache_available = True
        except ImportError:
            cache_available = False
            logger.warning("Cache manager not available for registry enrichment")
        
        for pkg in packages:
            lang = (pkg.get("language") or "").lower()
            name = pkg.get("name")
            version = pkg.get("version")
            
            if not name:
                continue
            
            # Registry enrichment - API FIRST, cache fallback on rate limit
            # Supported ecosystems: Python (PyPI) and npm only
            if lang == "python":
                api_success = False
                try:
                    # Call API first
                    logger.debug(f"[API CALL] PyPI: {name}@{version}")
                    resp = _rate_limited_request(f"https://pypi.org/pypi/{name}/json", "pypi", timeout=5)
                    
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        info = data.get("info", {})
                        api_success = True
                        
                        # === Fields deps.dev doesn't provide ===
                        # Description (from summary field)
                        if not pkg.get("component_description") or pkg.get("component_description") == "No description available":
                            pkg["component_description"] = info.get("summary") or "No description available"
                            pkg["description"] = pkg["component_description"]
                        
                        # Supplier (from author/maintainer or their email fields)
                        if not pkg.get("supplier") or pkg.get("supplier") == "Unknown":
                            supplier = info.get("author") or info.get("maintainer")
                            # If no author/maintainer, try to extract from email fields
                            if not supplier:
                                # Format: "Name <email>" or just "email"
                                email_field = info.get("author_email") or info.get("maintainer_email") or ""
                                if email_field:
                                    # Extract name from "Name <email>" format
                                    if "<" in email_field:
                                        supplier = email_field.split("<")[0].strip()
                                    else:
                                        # Just email, use domain part
                                        supplier = email_field.split("@")[0] if "@" in email_field else email_field
                            if supplier:
                                supplier = supplier.strip().strip('"').strip("'")
                            pkg["supplier"] = supplier or "Unknown"
                            pkg["component_supplier"] = pkg["supplier"]
                        
                        # Hashes (SHA-256 from digests)
                        if not pkg.get("hashes"):
                            hashes = []
                            for url_info in data.get("urls", []) or []:
                                digests = url_info.get("digests", {}) or {}
                                sha256 = digests.get("sha256", "")
                                if sha256:
                                    hashes.append({"alg": "SHA-256", "content": sha256})
                                    break  # Only first one
                            pkg["hashes"] = hashes
                        
                        # Cache the response for future fallback
                        if cache_available:
                            set_pypi_cache(name, data, version)
                            
                    elif resp and resp.status_code == 429:
                        # Rate limited - fallback to cache
                        logger.warning(f"[RATE LIMITED] PyPI: {name}@{version} - falling back to cache")
                        api_success = False
                    else:
                        # Package not found or other error
                        logger.debug(f"[API ERROR] PyPI: {name}@{version} - status {resp.status_code if resp else 'None'}")
                        api_success = False
                        
                except Exception as e:
                    logger.debug(f"[API EXCEPTION] PyPI: {name}@{version} - {str(e)}")
                    api_success = False
                
                # Fallback to cache if API failed
                if not api_success and cache_available:
                    cached_data = get_pypi_cache(name, version)
                    if cached_data:
                        logger.debug(f"[CACHE FALLBACK] PyPI: {name}@{version}")
                        self._apply_cached_registry_data(pkg, cached_data)
                    
            elif lang in ["javascript", "node", "js", "npm"]:
                api_success = False
                try:
                    # Call API first
                    logger.debug(f"[API CALL] npm: {name}@{version}")
                    resp = _rate_limited_request(f"https://registry.npmjs.org/{name}", "npm", timeout=5)
                    
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        latest_version = data.get("dist-tags", {}).get("latest", version)
                        version_data = data.get("versions", {}).get(version) or data.get("versions", {}).get(latest_version, {})
                        api_success = True
                    
                        # === Fields deps.dev doesn't provide ===
                        # Description
                        if not pkg.get("component_description") or pkg.get("component_description") == "No description available":
                            pkg["component_description"] = version_data.get("description") or data.get("description") or "No description available"
                            pkg["description"] = pkg["component_description"]
                        
                        # Supplier (author)
                        if not pkg.get("supplier") or pkg.get("supplier") == "Unknown":
                            author = version_data.get("author") or data.get("author") or {}
                            if isinstance(author, dict):
                                supplier_name = author.get("name") or "Unknown"
                                supplier_name = str(supplier_name).strip().strip('"').strip("'")
                                pkg["supplier"] = supplier_name or "Unknown"
                            else:
                                supplier_name = str(author) if author else "Unknown"
                                supplier_name = supplier_name.strip().strip('"').strip("'")
                                pkg["supplier"] = supplier_name or "Unknown"
                            pkg["component_supplier"] = pkg["supplier"]
                        
                        # Hashes (SHA-512 integrity or SHA-1 shasum)
                        if not pkg.get("hashes"):
                            hashes = []
                            dist = version_data.get("dist", {})
                            if dist.get("integrity"):
                                integrity = dist["integrity"]
                                if integrity.startswith("sha512-"):
                                    hashes.append({"alg": "SHA-512", "content": integrity.replace("sha512-", "")})
                            elif dist.get("shasum"):
                                hashes.append({"alg": "SHA-1", "content": dist["shasum"]})
                            pkg["hashes"] = hashes
                        
                        # Cache the response for future fallback
                        if cache_available:
                            set_npm_cache(name, data, version)
                            
                    elif resp and resp.status_code == 429:
                        # Rate limited - fallback to cache
                        logger.warning(f"[RATE LIMITED] npm: {name}@{version} - falling back to cache")
                        api_success = False
                    else:
                        # Package not found or other error
                        logger.debug(f"[API ERROR] npm: {name}@{version} - status {resp.status_code if resp else 'None'}")
                        api_success = False
                        
                except Exception as e:
                    logger.debug(f"[API EXCEPTION] npm: {name}@{version} - {str(e)}")
                    api_success = False
                
                # Fallback to cache if API failed
                if not api_success and cache_available:
                    cached_data = get_npm_cache(name, version)
                    if cached_data:
                        logger.debug(f"[CACHE FALLBACK] npm: {name}@{version}")
                        self._apply_cached_registry_data(pkg, cached_data)
            
            # Unique identifier (PURL) - generate for all ecosystems
            ecosystem = get_purl_type(lang or "unknown")
            purl = f"pkg:{ecosystem}/{name}@{version}"
            pkg["unique_identifier"] = purl
        
        return packages
    
    def _scan_codebase_properties(self, workspace: Path, packages: List[Dict]) -> List[Dict]:
        """
        Scan codebase for CERT-IN required properties and apply to all packages.
        
        Per CERT-IN guidelines, these properties describe what the CODEBASE contains:
        1. EXECUTABLE - Does the codebase contain executable files?
        2. ARCHIVE - Does the codebase contain archive/compressed files or bundled deps?
        3. STRUCTURED - Does the codebase contain structured configuration files?
        
        The same values are applied to ALL components since they describe the codebase,
        not individual packages from registries.
        
        Args:
            workspace: Path to the codebase/repository
            packages: List of package dictionaries
            
        Returns:
            Packages with executable, archive, structured_properties fields set
        """
        from src.utils.file_analysis import scan_codebase_properties
        
        # Scan the codebase once
        logger.info(f"[CODEBASE SCAN] Scanning {workspace} for CERT-IN properties...")
        analysis = scan_codebase_properties(workspace)
        
        # Get the summary strings
        executable_value = analysis.executable_summary
        archive_value = analysis.archive_summary
        structured_value = analysis.structured_summary
        
        logger.info(f"[CODEBASE SCAN] Executable: {executable_value[:80]}...")
        logger.info(f"[CODEBASE SCAN] Archive: {archive_value[:80]}...")
        logger.info(f"[CODEBASE SCAN] Structured: {structured_value[:80]}...")
        
        # Apply to ALL packages (same value for all since it's codebase-level)
        for pkg in packages:
            pkg["executable"] = executable_value
            pkg["archive"] = archive_value
            pkg["structured_properties"] = structured_value
        
        return packages
    
    def _apply_cached_registry_data(self, pkg: Dict, cached: Dict) -> None:
        """
        Apply cached registry data to a package (used as fallback when API fails).
        
        Only applies description, supplier, and hashes from cache.
        executable, archive, structured_properties are set via codebase scanning.
        
        Args:
            pkg: Package dict to update
            cached: Cached data from PyPI/npm cache
        """
        # Basic fields only - executable/archive/structured_properties come from codebase scan
        if not pkg.get("component_description") or pkg.get("component_description") == "No description available":
            pkg["component_description"] = cached.get("description") or "No description available"
            pkg["description"] = pkg["component_description"]
        
        if not pkg.get("supplier") or pkg.get("supplier") == "Unknown":
            pkg["supplier"] = cached.get("supplier") or "Unknown"
            pkg["component_supplier"] = pkg["supplier"]
        
        if not pkg.get("hashes"):
            pkg["hashes"] = cached.get("hashes") or []
    
    def _fetch_vulnerabilities(self, packages: List[Dict]) -> Tuple[List[Dict], int]:
        """
        Step 5: Fetch vulnerabilities from OSV and NVD.
        
        Returns:
            Tuple of (enriched packages, total vulnerability count)
        """
        from src.core.vulnerability_provider import enrich_catalog_with_vulns
        
        # Build temporary catalog for enrichment
        catalog = {"packages": packages}
        
        # Enrich with vulnerabilities
        catalog = enrich_catalog_with_vulns(catalog, nvd_api_key=self.nvd_api_key)
        
        # Count vulnerabilities
        vuln_count = sum(
            len(pkg.get("vulnerabilities", []))
            for pkg in catalog.get("packages", [])
        )
        
        return catalog["packages"], vuln_count
    
    # NOTE: _add_exploit_intel method removed - CISA KEV/EPSS is a V2 feature
    
    def _build_catalog(
        self,
        packages: List[Dict],
        manifests: List[str],
        project_name: str,
        source: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Step 7: Build the final catalog structure.
        """
        from src.config.config import TOOL_NAME, TOOL_VENDOR, TOOL_VERSION
        
        return {
            "scan_id": scan_id,
            "project_name": project_name,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": {
                "name": TOOL_NAME,
                "vendor": TOOL_VENDOR,
                "version": TOOL_VERSION
            },
            "manifests": manifests,
            "packages": packages,
            "package_count": len(packages),
            "vulnerability_count": sum(len(p.get("vulnerabilities", [])) for p in packages)
        }
    
    def _generate_sbom_reports(
        self,
        catalog: Dict[str, Any],
        scan_id: str
    ) -> Dict[str, str]:
        """
        Step 8: Generate SBOM reports in multiple formats.
        
        Returns:
            Dict mapping format name to file path
        """
        from src.core.sbom_generator import generate_all
        from src.report.report_writer import write_reports
        
        output_dir = self.reports_dir / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Build metadata for SBOM generation
        metadata = {
            "timestamp": catalog.get("timestamp"),
            "tool": catalog.get("tool", {}),
            "source": catalog.get("source"),
            "scan_id": scan_id
        }
        
        # Generate SBOM in all formats (returns {"sbom": {"spdx": ..., "cyclonedx": ..., "json": ...}})
        sbom_artifacts = generate_all(catalog, metadata)
        
        # Write reports to disk
        write_reports(
            artifacts=sbom_artifacts,
            reports_dir=self.reports_dir,
            scan_id=scan_id
        )
        
        # Return paths
        return {
            "spdx": str(output_dir / f"{scan_id}.spdx.json"),
            "cyclonedx": str(output_dir / f"{scan_id}.cyclonedx.json"),
            "json": str(output_dir / f"{scan_id}.json.json")
        }
    
    def _generate_remediation_report(
        self,
        catalog: Dict[str, Any],
        scan_id: str,
        source: str
    ) -> str:
        """
        Step 9: Generate remediation report.
        """
        from src.report.remediation_reporter import RemediationReporter
        
        # Build import map (empty for now - can be enhanced later)
        import_map = {}
        
        metadata = {
            "repository": source,
            "scan_type": "full"
        }
        
        reporter = RemediationReporter(scan_id, str(self.reports_dir))
        return reporter.generate_report(catalog, import_map, metadata)
    
    # NOTE: _generate_executive_summary method removed - executive summary not needed
    
    def _cleanup_workspace(self, workspace: Path):
        """Cleanup temporary workspace."""
        def _on_rm_error(func, path, exc_info):
            """Error handler for shutil.rmtree.

            Attempts to change file permissions and retry the operation.
            This helps on Windows where read-only or locked files can
            prevent deletion.
            """
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception as e:
                logger.warning(f"Retry delete failed for {path}: {e}")

        try:
            if workspace.exists():
                shutil.rmtree(workspace, onerror=_on_rm_error)
                logger.info(f"Cleaned up workspace: {workspace}")
        except Exception as e:
            logger.warning(f"Failed to cleanup {workspace}: {e}")


# =============================================================================
# Convenience Functions
# =============================================================================

def scan(
    source: str,
    source_type: str = "repo",
    scan_id: Optional[str] = None,
    token: Optional[str] = None
) -> ScanResult:
    """
    Convenience function for quick scanning.
    
    Example:
        from src.core.orchestrator import scan
        
        result = scan("https://github.com/user/repo")
        print(f"Found {result.vulnerabilities_count} vulnerabilities")
    """
    orchestrator = ScanOrchestrator()
    return orchestrator.run_scan(
        source=source,
        source_type=source_type,
        scan_id=scan_id,
        token=token
    )
