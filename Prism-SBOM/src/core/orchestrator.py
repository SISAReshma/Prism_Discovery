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

from src.registry.language_registry import get_purl_type

# Import registry clients for enrichment
from src.clients.pypi_client import PyPIClient
from src.clients.npm_client import NpmClient
# Note: EOLClient not needed - EOL/deprecation now checked via PyPI/npm APIs directly

# Configure logging
logger = logging.getLogger(__name__)

# Initialize registry clients
_pypi_client = PyPIClient()
_npm_client = NpmClient()


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
        Also enriches with EOL status for runtime awareness.
        
        NOTE: executable, archive, structured_properties are now detected via codebase scanning
        (see scan_codebase_properties method).
        
        Supported ecosystems: Python and npm only.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Packages with description, supplier, hashes, unique_identifier, eol_status fields
        """
        packages = self._registry_enrich(packages)
        packages = self._enrich_eol(packages)
        return packages
    
    def enrich_eol(self, packages: List[Dict]) -> List[Dict]:
        """
        Step 4d: Enrich packages with End-of-Life (EOL) status.
        
        NOTE: EOL API tracks RUNTIMES (Python, Node.js, Java), not individual packages.
        For library-level EOL tracking, we'd need package-specific deprecation data.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Packages with eol_status, eol_date, is_eol fields
        """
        return self._enrich_eol(packages)
    
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
    
    def calculate_statistics(self, packages: List[Dict]) -> Dict[str, Any]:
        """
        Calculate comprehensive statistics for packages.
        
        This centralizes all statistics calculations that were previously
        duplicated across endpoints.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Dict containing:
            - scan_summary: total components, direct/transitive counts
            - vulnerability_summary: total vulns, severity breakdown, affected packages
            - license_summary: unique licenses count, breakdown by license
            - patchable_summary: patchable vs unpatchable vulnerabilities
        """
        # Count dependencies by type
        direct_deps = sum(1 for p in packages if p.get("is_direct_dependency", False))
        transitive_deps = len(packages) - direct_deps
        
        # Count vulnerabilities and severity breakdown
        total_vulns = 0
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        patchable_count = 0
        unpatchable_count = 0
        packages_affected = 0
        
        for p in packages:
            vulns = p.get("vulnerabilities", [])
            if vulns:
                packages_affected += 1
                total_vulns += len(vulns)
                
                for v in vulns:
                    # Severity breakdown
                    sev = v.get("severity_level", "UNKNOWN").upper()
                    if sev in severity_breakdown:
                        severity_breakdown[sev] += 1
                    else:
                        severity_breakdown["UNKNOWN"] += 1
                    
                    # Patchable check
                    fixed_in = v.get("fixed_in") or v.get("fixed_version")
                    if fixed_in and fixed_in not in ["Unknown", "N/A", "", None]:
                        patchable_count += 1
                    else:
                        unpatchable_count += 1
        
        # License summary
        licenses = {}
        for p in packages:
            lic = p.get("component_license") or p.get("license") or "NOASSERTION"
            licenses[lic] = licenses.get(lic, 0) + 1
        
        # Deprecated packages count
        deprecated_count = sum(1 for p in packages if p.get("is_deprecated", False))
        
        return {
            "scan_summary": {
                "total_components": len(packages),
                "direct_dependencies": direct_deps,
                "transitive_dependencies": transitive_deps,
                "deprecated_packages": deprecated_count
            },
            "vulnerability_summary": {
                "total": total_vulns,
                "by_severity": severity_breakdown,
                "packages_affected": packages_affected,
                "patchable": patchable_count,
                "unpatchable": unpatchable_count
            },
            "license_summary": {
                "unique_licenses": len(licenses),
                "breakdown": licenses
            }
        }
    
    def format_vulnerable_packages(self, packages: List[Dict]) -> List[Dict]:
        """
        Format vulnerable packages list for API response.
        
        Args:
            packages: List of enriched packages with vulnerabilities
            
        Returns:
            List of packages with vulnerabilities, formatted for display
        """
        vulnerable_packages = []
        
        for p in packages:
            pkg_vulns = p.get("vulnerabilities", [])
            if not pkg_vulns:
                continue
            
            is_direct = p.get("is_direct_dependency", True)
            
            # Build formatted vulnerability list
            formatted_vulns = []
            for v in pkg_vulns:
                severity = v.get("severity", "UNKNOWN")
                severity_level = v.get("severity_level", "UNKNOWN").upper()
                
                # Determine patch status
                fixed_in = v.get("fixed_in") or v.get("fixed_version")
                has_patch = fixed_in and fixed_in not in ["Unknown", "N/A", "", None]
                patch_status = "can_be_patched" if has_patch else "no_patch_available"
                
                # Calculate criticality
                base_criticality_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
                criticality = base_criticality_map.get(severity_level, "unknown")
                if is_direct and severity_level in ["CRITICAL", "HIGH"]:
                    criticality = "critical" if severity_level == "CRITICAL" else "high"
                
                formatted_vuln = {
                    "id": v.get("id", "Unknown"),
                    "severity": severity,
                    "severity_level": severity_level,
                    "summary": v.get("summary", "No summary available"),
                    "fixed_in": fixed_in if has_patch else None,
                    "url": v.get("url") or f"https://osv.dev/vulnerability/{v.get('id', '')}",
                    "modified": v.get("modified"),
                    "published": v.get("published"),
                    "aliases": v.get("aliases", []),
                    "details": v.get("details", "N/A"),
                    "patch_status": patch_status,
                    "criticality": criticality
                }
                formatted_vulns.append(formatted_vuln)
            
            vulnerable_packages.append({
                "component_name": p.get("name"),
                "version": p.get("version"),
                "vulnerabilities": formatted_vulns
            })
        
        return vulnerable_packages
    
    def format_packages_summary(self, packages: List[Dict], limit: int = 15) -> List[Dict]:
        """
        Format packages list for API response preview.
        
        Args:
            packages: List of packages
            limit: Maximum number of packages to include in summary
            
        Returns:
            List of package summaries for display
        """
        packages_summary = [{
            "component_name": p.get("name"),
            "version": p.get("version"),
            "language": p.get("language") or p.get("ecosystem") or "unknown",
            "is_direct_dependency": p.get("is_direct_dependency", p.get("is_direct", True))
        } for p in packages[:limit]]
        
        if len(packages) > limit:
            packages_summary.append({"note": f"...and {len(packages) - limit} more"})
        
        return packages_summary
    
    def count_by_registry(self, packages: List[Dict]) -> Dict[str, int]:
        """
        Count packages by registry type.
        
        Args:
            packages: List of packages
            
        Returns:
            Dict with counts for each registry (pypi, npm, etc.)
        """
        counts = {"pypi": 0, "npm": 0, "other": 0}
        
        for p in packages:
            lang = (p.get("language") or p.get("ecosystem") or "").lower()
            if lang in ["python", "pip", "pypi"]:
                counts["pypi"] += 1
            elif lang in ["javascript", "npm", "node"]:
                counts["npm"] += 1
            else:
                counts["other"] += 1
        
        return counts
    
    def count_by_metadata_source(self, packages: List[Dict]) -> Dict[str, int]:
        """
        Count packages by metadata source (deps.dev vs fallback).
        
        Args:
            packages: List of enriched packages
            
        Returns:
            Dict with counts for deps.dev and fallback sources
        """
        depsdev_count = sum(1 for p in packages if p.get("metadata_source", "").lower() == "deps.dev")
        fallback_count = len(packages) - depsdev_count
        
        return {
            "depsdev": depsdev_count,
            "fallback": fallback_count
        }
    
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
            packages = self._enrich_eol(packages)  # Add EOL/deprecation status
            logger.info(f"[STEP 4b/10] Registry enrichment complete (includes EOL check)")
            
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
                                from src.clients.pypi_client import fetch_pypi_meta, extract_license_from_pypi_meta
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
        
        Uses dedicated registry clients (PyPIClient, NpmClient) with built-in:
        - Rate limiting
        - Caching with fallback
        
        Fields enriched (that deps.dev doesn't provide):
        - description: Package summary/description
        - supplier: Package author/maintainer
        - hashes: SHA-256/SHA-512 checksums
        - unique_identifier: PURL format identifier
        
        NOTE: executable, archive, structured_properties are detected via codebase scanning
        (see _scan_codebase_properties method) per CERT-IN guidelines.
        
        Supported ecosystems: Python (PyPI) and npm only.
        """
        for pkg in packages:
            lang = (pkg.get("language") or "").lower()
            name = pkg.get("name")
            version = pkg.get("version")
            
            if not name:
                continue
            
            # Registry enrichment using dedicated clients
            if lang == "python":
                info = _pypi_client.get_package_info(name, version)
                if info["success"] or info.get("from_cache"):
                    self._apply_registry_info(pkg, info)
                    
            elif lang in ["javascript", "node", "js", "npm"]:
                info = _npm_client.get_package_info(name, version)
                if info["success"] or info.get("from_cache"):
                    self._apply_registry_info(pkg, info)
            
            # Unique identifier (PURL) - use CERT-IN format with supplier
            from src.config import config
            supplier = pkg.get("component_supplier") or pkg.get("supplier") or ""
            ecosystem = get_purl_type(lang or "unknown")
            purl = config.generate_cert_in_identifier(ecosystem, name, version, supplier)
            pkg["unique_identifier"] = purl
        
        return packages
    
    def _apply_registry_info(self, pkg: Dict, info: Dict) -> None:
        """
        Apply registry info to a package dict.
        
        Args:
            pkg: Package dict to update
            info: Registry info from PyPIClient or NpmClient
        """
        # Description
        if not pkg.get("component_description") or pkg.get("component_description") == "No description available":
            pkg["component_description"] = info.get("description") or "No description available"
            pkg["description"] = pkg["component_description"]
        
        # Supplier
        if not pkg.get("supplier") or pkg.get("supplier") == "Unknown":
            pkg["supplier"] = info.get("supplier") or "Unknown"
            pkg["component_supplier"] = pkg["supplier"]
        
        # Hashes
        if not pkg.get("hashes"):
            pkg["hashes"] = info.get("hashes") or []
    
    def _enrich_eol(self, packages: List[Dict]) -> List[Dict]:
        """
        Enrich packages with End-of-Life (EOL) / deprecation status.
        
        For libraries, we check:
        - PyPI: yanked versions, Development Status classifiers (Inactive/Deprecated)
        - npm: deprecated field on versions
        
        Fields added:
        - eol_status: "Active", "Deprecated", "Yanked", or specific message
        - eol_date: Deprecation date if available
        - is_deprecated: Boolean indicating if package is deprecated/yanked
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            Packages with deprecation/EOL information
        """
        from src.clients.pypi_client import fetch_pypi_meta
        
        for pkg in packages:
            lang = (pkg.get("language") or "").lower()
            name = pkg.get("name")
            version = pkg.get("version")
            
            # Default values
            pkg["eol_status"] = "Active"
            pkg["eol_date"] = None
            pkg["is_deprecated"] = False
            
            if not name:
                continue
            
            try:
                if lang == "python":
                    # Check PyPI for deprecation
                    meta = fetch_pypi_meta(name, version)
                    if meta:
                        info = meta.get("info", {})
                        
                        # Check if version is yanked
                        # Need to check specific version in releases
                        releases = meta.get("releases", {})
                        if version and version in releases:
                            version_files = releases[version]
                            if version_files and isinstance(version_files, list):
                                # Check if all files are yanked
                                all_yanked = all(f.get("yanked", False) for f in version_files if isinstance(f, dict))
                                if all_yanked and version_files:
                                    yanked_reason = version_files[0].get("yanked_reason", "No reason provided") if version_files else ""
                                    pkg["eol_status"] = f"Yanked: {yanked_reason}" if yanked_reason else "Yanked"
                                    pkg["is_deprecated"] = True
                                    continue
                        
                        # Check Development Status classifiers
                        classifiers = info.get("classifiers", []) or []
                        for classifier in classifiers:
                            if "Development Status :: 7 - Inactive" in classifier:
                                pkg["eol_status"] = "Inactive (no longer maintained)"
                                pkg["is_deprecated"] = True
                                break
                            elif "Development Status :: 1 - Planning" in classifier:
                                pkg["eol_status"] = "Pre-release (Planning stage)"
                                break
                        
                elif lang in ["javascript", "npm", "node", "js"]:
                    # Check npm for deprecation
                    # The raw_data from npm includes deprecated field
                    info = _npm_client.get_package_info(name, version)
                    if info.get("success") and info.get("raw_data"):
                        data = info["raw_data"]
                        versions = data.get("versions", {})
                        
                        # Check if specific version is deprecated
                        if version and version in versions:
                            version_data = versions[version]
                            deprecated = version_data.get("deprecated")
                            if deprecated:
                                pkg["eol_status"] = f"Deprecated: {deprecated}" if isinstance(deprecated, str) else "Deprecated"
                                pkg["is_deprecated"] = True
                        else:
                            # Check if entire package is deprecated (latest version)
                            latest = data.get("dist-tags", {}).get("latest")
                            if latest and latest in versions:
                                deprecated = versions[latest].get("deprecated")
                                if deprecated:
                                    pkg["eol_status"] = f"Deprecated: {deprecated}" if isinstance(deprecated, str) else "Deprecated"
                                    pkg["is_deprecated"] = True
                                    
            except Exception as e:
                logger.debug(f"[EOL] Failed to check deprecation for {name}: {e}")
        
        deprecated_count = sum(1 for p in packages if p.get("is_deprecated"))
        logger.info(f"[EOL] Processed {len(packages)} packages, {deprecated_count} deprecated/yanked")
        
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
