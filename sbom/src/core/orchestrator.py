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
    from sbom.src.core.orchestrator import ScanOrchestrator
    
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

from sbom.src.registry.language_registry import get_purl_type

# Import registry clients for enrichment
from sbom.src.clients.pypi_client import PyPIClient
from sbom.src.clients.npm_client import NpmClient
# Note: EOLClient not needed - EOL/deprecation now checked via PyPI/npm APIs directly

from core.log_sanitizer import sanitize_sensitive

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
        from sbom.src.config.config import REPORTS_DIR, TEMP_DIR
        
        self.reports_dir = Path(reports_dir or REPORTS_DIR)
        self.temp_dir = Path(temp_dir or TEMP_DIR)
        self.nvd_api_key = nvd_api_key
        
        # Only create temp_dir (for cloning repos), not reports_dir
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Track active scans for status queries
        self._active_scans: Dict[str, ScanProgress] = {}
        
        # Initialize sequential scan ID counter (in-memory only, no file persistence)
        self._next_scan_number = 1
    
    def _get_next_scan_id(self) -> str:
        """Get the next sequential scan ID (1, 2, 3, ...)"""
        scan_id = str(self._next_scan_number)
        self._next_scan_number += 1
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
    
    def run_catalogers(self, workspace: Path) -> Tuple[List[Dict], List[str], Dict[str, Dict]]:
        """
        Step 3: Run language catalogers to extract packages.
        
        Args:
            workspace: Path to workspace directory
            
        Returns:
            Tuple of (packages list, manifest paths, lock_data dict)
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
    
    def expand_transitive_dependencies(self, packages: List[Dict], lock_data: Dict[str, Dict] = None) -> Tuple[List[Dict], int]:
        """
        Step 3b: Expand transitive dependencies.
        
        Priority:
        1. If lock_data available → Use it (more accurate, actual installed versions)
        2. Otherwise → Use deps.dev API (fallback)
        
        Args:
            packages: List of direct dependency packages
            lock_data: OPTIMIZED dict format: {pkg_name: {version, hashes, dependencies}}
            
        Returns:
            Tuple of (packages with transitive, transitive_count)
        """
        return self._expand_transitive_dependencies(packages, lock_data)
    
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
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        patchable_count = 0
        unpatchable_count = 0
        packages_affected = 0
        
        for p in packages:
            vulns = p.get("vulnerabilities", [])
            if vulns:
                packages_affected += 1
                total_vulns += len(vulns)
                
                for v in vulns:
                    # Severity breakdown — normalise NONE→LOW, unexpected→HIGH (conservative)
                    sev = v.get("severity_level", "HIGH").upper()
                    if sev == "NONE":
                        sev = "LOW"
                    elif sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        sev = "HIGH"
                    severity_breakdown[sev] += 1
                    
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
                
                # Calculate criticality — prefer numeric cvss_score for precision,
                # fall back to severity_level keyword when no score is available.
                cvss = v.get("cvss_score")
                if cvss is not None and isinstance(cvss, (int, float)) and cvss >= 0:
                    # Use actual CVSS score thresholds (NIST/FIRST standard)
                    if cvss >= 9.0:
                        criticality = "critical"
                    elif cvss >= 7.0:
                        criticality = "high"
                    elif cvss >= 4.0:
                        criticality = "medium"
                    else:
                        criticality = "low"
                    # Direct dependencies with high CVSS get elevated criticality
                    if is_direct and cvss >= 7.0:
                        criticality = "critical" if cvss >= 9.0 else "high"
                else:
                    # Fall back to severity_level keyword
                    base_criticality_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
                    criticality = base_criticality_map.get(severity_level, "high")
                    if is_direct and severity_level in ["CRITICAL", "HIGH"]:
                        criticality = "critical" if severity_level == "CRITICAL" else "high"
                
                formatted_vuln = {
                    "id": v.get("id", "Unknown"),
                    "severity": severity,
                    "severity_level": severity_level,
                    "cvss_score": v.get("cvss_score"),
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
        def _pkg_summary(p: Dict) -> Dict:
            resolved = p.get("version_resolved", False)
            entry = {
                "component_name": p.get("name"),
                "version": p.get("version"),
                "language": p.get("language") or p.get("ecosystem") or "unknown",
                "is_direct_dependency": p.get("is_direct_dependency", p.get("is_direct", True)),
                "version_resolved": resolved,
                "version_source": p.get("version_source", "unknown"),
            }
            # Surface constraint details only for unresolved (range/inequality) packages
            if not resolved and p.get("version_constraint"):
                entry["version_constraint"] = p["version_constraint"]
                entry["version_warning"] = p.get(
                    "version_warning",
                    "Version is a range constraint — actual installed version may differ."
                )
            return entry

        packages_summary = [_pkg_summary(p) for p in packages[:limit]]
        
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
        counts = {"pypi": 0, "npm": 0, "nuget": 0, "rubygems": 0, "maven": 0, "go": 0, "cargo": 0, "packagist": 0, "cocoapods": 0, "conda": 0, "conan": 0, "other": 0}
        
        for p in packages:
            lang = (p.get("language") or p.get("ecosystem") or "").lower()
            if lang in ["python", "pip", "pypi"]:
                counts["pypi"] += 1
            elif lang in ["javascript", "npm", "node", "js"]:
                counts["npm"] += 1
            elif lang in ["dotnet", ".net", "csharp", "c#", "nuget", "fsharp"]:
                counts["nuget"] += 1
            elif lang in ["ruby", "gem", "bundler", "rubygems"]:
                counts["rubygems"] += 1
            elif lang in ["java", "maven", "gradle"]:
                counts["maven"] += 1
            elif lang in ["go", "golang"]:
                counts["go"] += 1
            elif lang in ["rust", "cargo", "crate", "crates"]:
                counts["cargo"] += 1
            elif lang in ["php", "composer", "packagist"]:
                counts["packagist"] += 1
            elif lang in ["swift", "cocoapods", "pods"]:
                counts["cocoapods"] += 1
            elif lang in ["conda", "anaconda"]:
                counts["conda"] += 1
            elif lang in ["cpp", "c", "c++", "cc", "conan", "vcpkg", "cmake"]:
                counts["conan"] += 1
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
            
            packages, cataloger_manifests, lock_data = self._run_catalogers(workspace)
            
            # Merge manifests
            all_manifests = list(set(manifests + cataloger_manifests))
            
            progress.packages_found = len(packages)
            logger.info(f"[STEP 3/10] Catalogers found {len(packages)} packages")
            
            # ================================================================
            # STEP 4: Enrich Metadata (deps.dev)
            # ================================================================
            self._update_progress(progress, ScanStatus.ENRICHING, "Enriching metadata...", 4)

            # Expand transitive dependencies (CLI path)
            # Priority: lock_data if available, else deps.dev API
            packages, transitive_count = self._expand_transitive_dependencies(packages, lock_data)
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
            # Sanitize error to prevent credential/sensitive data leakage
            sanitized_error = sanitize_sensitive(str(e))
            logger.error("Scan failed", extra={"scan_id": scan_id, "error": sanitized_error})
            import traceback
            traceback.print_exc()
            
            result.errors.append(sanitized_error)
            progress.status = ScanStatus.FAILED
            progress.error = sanitized_error
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
        from sbom.src.utils.git_utils import git_clone
        from sbom.src.utils.file_utils import extract_zip
        
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
        from sbom.src.core.scanner import _discover_manifests
        return _discover_manifests(workspace)
    
    def _run_catalogers(self, workspace: Path) -> Tuple[List[Dict], List[str], Dict[str, Dict]]:
        """
        Step 3: Run catalogers (Python, npm).
        
        Returns:
            Tuple of (packages list, manifest paths list, lock_data dict)
            lock_data is OPTIMIZED format: {pkg_name: {version, hashes, dependencies}}
        """
        from sbom.src.core.scanner import _run_catalogers
        
        packages, manifests, _, lock_data = _run_catalogers(workspace, nvd_api_key=self.nvd_api_key)
        return packages, manifests, lock_data
    
    def _enrich_metadata(self, packages: List[Dict]) -> List[Dict]:
        """
        Step 4: Enrich packages with metadata from deps.dev.
        
        Fallback chain for each field:
        1. deps.dev API (primary)
        2. Registry API (PyPI for python, npm for js) — on empty/missing
        3. Cache — on rate limit
        4. Empty / NOASSERTION — absolute last resort (set by caller)
        
        Adds:
        - License information
        - Release date
        - Homepage
        - metadata_source field for tracking
        """
        try:
            from sbom.src.clients.depsdev_client import get_client
            
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
                    # Fetch metadata from deps.dev
                    metadata = client.get_metadata(ecosystem, name, version)
                    
                    if metadata and metadata.get("source") == "deps.dev":
                        pkg["metadata_source"] = "deps.dev"
                        
                        # --- License ---
                        # deps.dev now returns "" for missing (not NOASSERTION)
                        license_val = metadata.get("license", "")
                        bad_license = {"", "noassertion", "non-standard", "unknown"}
                        
                        # Extra safeguard: normalize again if still long
                        if license_val and len(str(license_val)) > 80:
                            try:
                                from sbom.src.clients.depsdev_client import normalize_license
                                license_val = normalize_license(str(license_val))
                            except ImportError:
                                license_val = ""
                        if license_val and len(str(license_val)) > 80:
                            license_val = ""
                        
                        if str(license_val).strip().lower() not in bad_license:
                            if not pkg.get("license") or pkg.get("license") in ["NOASSERTION", "non-standard", "unknown"]:
                                pkg["license"] = license_val
                            if not pkg.get("component_license") or pkg.get("component_license") in ["NOASSERTION", "non-standard", "unknown"]:
                                pkg["component_license"] = license_val
                        # NOTE: License fallback to PyPI/npm is now handled by the caller
                        # (main.py fetch-depsdev endpoint) to avoid double-fetching
                        
                        # --- Release date ---
                        published = metadata.get("published_at", "")
                        if published and (not pkg.get("release_date")):
                            pkg["release_date"] = published
                        
                        # --- Homepage ---
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

    def _expand_transitive_dependencies(self, packages: List[Dict], lock_data: Dict[str, Dict] = None) -> Tuple[List[Dict], int]:
        """
        Expand transitive dependencies.
        
        Priority:
        1. If lock_data available → Use it (more accurate, actual installed versions)
           OPTIMIZED: lock_data is dict lookup {pkg_name: {version, hashes, dependencies}}
        2. Otherwise → Use deps.dev API (fallback)

        Returns:
            (packages_with_transitives, transitive_count)
        """
        transitive_packages: List[Dict] = []
        seen_packages = set()
        direct_names = set()

        # Mark direct dependencies and collect their names
        for p in packages:
            p["is_direct_dependency"] = True
            key = f"{p.get('name')}@{p.get('version')}"
            seen_packages.add(key.lower())
            direct_names.add(p.get("name", "").lower())

        # PRIORITY 1: Use lock_data if available (OPTIMIZED dict lookup)
        if lock_data:
            logger.info(f"[TRANSITIVE] Using lock data ({len(lock_data)} packages) for transitive resolution")
            
            for name_lower, pkg_info in lock_data.items():
                version = pkg_info.get("version", "")
                
                if not version or version in ("UNKNOWN", ""):
                    continue
                
                key = f"{name_lower}@{version}".lower()
                
                # Skip if exact name@version already seen OR same name as direct dependency
                if key in seen_packages or name_lower in direct_names:
                    continue
                
                seen_packages.add(key)
                
                # Get language from existing packages or default
                lang = ""
                if packages:
                    lang = (packages[0].get("language") or packages[0].get("ecosystem") or "").lower()
                
                transitive_packages.append({
                    "name": name_lower,
                    "version": version,
                    "language": lang,
                    "ecosystem": get_purl_type(lang) if lang else "unknown",
                    "is_direct_dependency": False,
                    "transitive_source": "lock_file",
                    "purl": f"pkg:{get_purl_type(lang)}/{name_lower}@{version}" if lang else f"pkg:pypi/{name_lower}@{version}",
                    "hashes": pkg_info.get("hashes", []),
                    "component_dependencies": pkg_info.get("dependencies", [])
                })
            
            if transitive_packages:
                packages.extend(transitive_packages)
                logger.info(f"[TRANSITIVE] Added {len(transitive_packages)} transitive dependencies from lock data")
                return packages, len(transitive_packages)

            logger.info("[TRANSITIVE] Lock data present but no transitives resolved — falling back to deps.dev")
        
        # PRIORITY 2: Fallback to deps.dev API
        logger.info("[TRANSITIVE] No lock file packages - using deps.dev API for transitive resolution")
        
        try:
            from sbom.src.clients.depsdev_client import get_client

            client = get_client()
            transitive_packages_api: List[Dict] = []

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
                            transitive_packages_api.append({
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

            if transitive_packages_api:
                packages.extend(transitive_packages_api)

            return packages, len(transitive_packages_api)

        except Exception as e:
            logger.warning(f"deps.dev transitive expansion failed: {e}")
            return packages, 0
    
    def _registry_enrich(self, packages: List[Dict]) -> List[Dict]:
        """
        Registry enrichment: fills description, supplier, hashes, and unique_identifier fields.
        
        Uses dedicated registry clients (PyPIClient, NpmClient, Packagist, etc.) with built-in:
        - Rate limiting
        - Caching with fallback
        
        Fields enriched (that deps.dev doesn't provide):
        - description: Package summary/description
        - supplier: Package author/maintainer
        - hashes: SHA-256/SHA-512 checksums
        - unique_identifier: PURL format identifier
        
        Lock-file optimisation:
        Packages whose cataloger already extracted description, supplier AND hashes directly
        from the lock file (e.g. PHP packages from composer.lock which embeds authors,
        description and dist.shasum) will have their metadata promoted to component_* fields
        and be marked as _registry_enriched WITHOUT making a live registry API call.
        This avoids redundant Packagist/RubyGems/etc. calls for transitive lock-file packages
        that already carry complete metadata.
        
        NOTE: executable, archive, structured_properties are detected via codebase scanning
        (see _scan_codebase_properties method) per CERT-IN guidelines.
        """
        for pkg in packages:
            lang = (pkg.get("language") or "").lower()
            name = pkg.get("name")
            version = pkg.get("version")
            
            if not name:
                continue
            
            # ---- Skip live registry API call if lock-file cataloger already provided metadata ----
            # Applies to ecosystems whose lock files embed description, supplier and hashes
            # (e.g. PHP/composer.lock carries authors, description, dist.shasum).
            # JavaScript/npm lock files do NOT carry description/supplier → still need live call.
            _BAD_STR = {"", "No description available", "N/A", "No description available."}
            _BAD_SUP = {"", "Unknown", "N/A", "unknown"}
            _lock_has_meta = (
                pkg.get("version_source") == "lock_file"
                and (pkg.get("description") or "").strip() not in _BAD_STR
                and (pkg.get("supplier") or "").strip() not in _BAD_SUP
                and bool(pkg.get("hashes"))
            )

            # Registry enrichment using dedicated clients
            if _lock_has_meta:
                # Lock-file cataloger already supplied description, supplier, hashes — no API call needed.
                # Promote raw fields to component_* variants and mark as enriched.
                pkg.setdefault("component_description", pkg.get("description", ""))
                pkg.setdefault("component_supplier", pkg.get("supplier", ""))
                pkg["_registry_enriched"] = True
                logger.debug(
                    f"[REGISTRY] {name}@{version}: lock-file metadata present — "
                    "skipping live registry API call"
                )

            elif lang == "python":
                info = _pypi_client.get_package_info(name, version)
                if info["success"] or info.get("from_cache"):
                    self._apply_registry_info(pkg, info)
                    
            elif lang in ["javascript", "node", "js", "npm"]:
                info = _npm_client.get_package_info(name, version)
                if info["success"] or info.get("from_cache"):
                    self._apply_registry_info(pkg, info)
            
            elif lang in ["dotnet", ".net", "csharp", "c#", "nuget", "fsharp"]:
                # NuGet registry enrichment
                try:
                    from sbom.src.clients.nuget_client import fetch_nuget_meta, extract_license_from_nuget_meta
                    meta = fetch_nuget_meta(name, version)
                    if meta:
                        info = {
                            "success": True,
                            "description": meta.get("description") or "",
                            "supplier": meta.get("authors") or "",
                            "hashes": meta.get("hashes", []),
                        }
                        self._apply_registry_info(pkg, info)
                        # Also set license if not already set
                        if not pkg.get("license") or pkg.get("license") == "NOASSERTION":
                            nuget_license = extract_license_from_nuget_meta(meta)
                            if nuget_license and nuget_license != "NOASSERTION":
                                pkg["license"] = nuget_license
                                pkg["component_license"] = nuget_license
                except ImportError:
                    logger.debug("NuGet client not available")

            elif lang in ["ruby", "gem", "rubygems", "bundler"]:
                # RubyGems registry enrichment
                try:
                    from sbom.src.clients.rubygems_client import fetch_rubygems_meta
                    meta = fetch_rubygems_meta(name, version)
                    if meta:
                        info = {
                            "success": True,
                            "description": meta.get("info") or meta.get("summary") or "",
                            "supplier": meta.get("authors") or "",
                            "hashes": [],
                        }
                        sha = meta.get("sha")
                        if sha:
                            info["hashes"] = [{"alg": "SHA-256", "content": sha}]
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"RubyGems enrichment failed for {name}")

            elif lang in ["php", "composer", "packagist"]:
                # Packagist registry enrichment
                try:
                    from sbom.src.clients.packagist_client import fetch_packagist_meta, extract_authors_from_packagist
                    meta = fetch_packagist_meta(name, version)
                    if meta:
                        info = {
                            "success": True,
                            "description": meta.get("description") or "",
                            "supplier": extract_authors_from_packagist(meta),
                            "hashes": [],
                        }
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"Packagist enrichment failed for {name}")

            elif lang in ["go", "golang"]:
                # Go proxy / deps.dev enrichment
                try:
                    from sbom.src.clients.go_client import fetch_go_meta
                    meta = fetch_go_meta(name, version)
                    if meta:
                        info = {
                            "success": True,
                            "description": "",
                            "supplier": "Unknown",
                            "hashes": [],
                        }
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"Go enrichment failed for {name}")

            elif lang in ["java", "maven", "gradle"]:
                # Maven Central enrichment
                try:
                    from sbom.src.clients.maven_client import fetch_maven_meta
                    # Java cataloger stores groupId/artifactId (camelCase) and group_id (snake_case)
                    group_id = pkg.get("groupId") or pkg.get("group_id") or ""
                    artifact_id = pkg.get("artifactId") or pkg.get("artifact_id") or ""
                    if not group_id and ":" in (name or ""):
                        parts = name.split(":")
                        group_id = parts[0]
                        artifact_id = parts[1] if len(parts) > 1 else ""
                    elif not artifact_id and ":" in (name or ""):
                        parts = name.split(":")
                        artifact_id = parts[1] if len(parts) > 1 else name
                    elif not artifact_id:
                        artifact_id = name
                    logger.info(f"[ENRICH] Maven enrichment for {group_id}:{artifact_id}:{version}")
                    meta = fetch_maven_meta(group_id, artifact_id, version)
                    if meta:
                        # developers is a list — take first name, or fall back to organization
                        devs = meta.get("developers") or []
                        supplier = devs[0] if isinstance(devs, list) and devs else (
                            meta.get("developer") or meta.get("organization") or "Unknown"
                        )
                        info = {
                            "success": True,
                            "description": meta.get("description") or "",
                            "supplier": supplier,
                            "hashes": meta.get("hashes") or [],
                        }
                        logger.info(f"[ENRICH] Maven POM data for {artifact_id}: desc='{(info['description'] or '')[:60]}', supplier='{supplier}', hashes={len(info['hashes'])}")
                        self._apply_registry_info(pkg, info)
                    else:
                        logger.warning(f"[ENRICH] Maven fetch returned None for {group_id}:{artifact_id}:{version}")
                except Exception as e:
                    logger.warning(f"[ENRICH] Maven enrichment failed for {name}: {e}")

            elif lang in ["rust", "cargo", "crate", "crates"]:
                # crates.io enrichment
                try:
                    from sbom.src.clients.cargo_client import fetch_cargo_meta
                    meta = fetch_cargo_meta(name, version)
                    if meta:
                        crate = meta.get("crate", {})
                        ver_info = meta.get("version", {})
                        info = {
                            "success": True,
                            "description": crate.get("description") or "",
                            "supplier": (ver_info.get("authors") or ["Unknown"])[0] if ver_info.get("authors") else "Unknown",
                            "hashes": [],
                        }
                        cksum = ver_info.get("checksum")
                        if cksum:
                            info["hashes"] = [{"alg": "SHA-256", "content": cksum}]
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"Cargo enrichment failed for {name}")

            elif lang in ["swift", "cocoapods", "pods"]:
                # CocoaPods enrichment
                try:
                    import requests
                    from sbom.src.config.config import COCOAPODS_API, API_TIMEOUT
                    url = f"{COCOAPODS_API}/pods/{name}"
                    resp = requests.get(url, timeout=API_TIMEOUT)
                    if resp.status_code == 200:
                        data = resp.json()
                        authors = data.get("authors", {})
                        supplier = ", ".join(authors.keys()) if isinstance(authors, dict) and authors else "Unknown"
                        info = {
                            "success": True,
                            "description": data.get("summary") or "",
                            "supplier": supplier,
                            "hashes": [],
                        }
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"CocoaPods enrichment failed for {name}")

            elif lang in ["conda", "anaconda"]:
                # Anaconda enrichment
                try:
                    from sbom.src.clients.anaconda_client import AnacondaClient
                    client = AnacondaClient()
                    channel = pkg.get("channel", "conda-forge")
                    meta = client.get_package_info(name, channel)
                    if meta:
                        info = {
                            "success": True,
                            "description": meta.get("summary") or meta.get("description") or "",
                            "supplier": meta.get("owner") or "Unknown",
                            "hashes": [],
                        }
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"Conda enrichment failed for {name}")

            elif lang in ["cpp", "c", "c++", "cc", "conan", "vcpkg", "cmake"]:
                # Conan Center / vcpkg enrichment
                try:
                    from sbom.src.clients.conan_client import fetch_conan_meta
                    meta = fetch_conan_meta(name, version)
                    if meta:
                        info = {
                            "success": True,
                            "description": meta.get("description") or "",
                            "supplier": meta.get("author") or meta.get("owner") or "Unknown",
                            "hashes": [],
                        }
                        self._apply_registry_info(pkg, info)
                except Exception:
                    logger.debug(f"Conan/vcpkg enrichment failed for {name}")
            
            # Unique identifier (PURL) - use CERT-IN format with supplier
            from sbom.src.config import config
            supplier = pkg.get("component_supplier") or pkg.get("supplier") or ""
            ecosystem = get_purl_type(lang or "unknown")
            # Sanitize version — strip NuGet-style ranges like [2.14.1, )
            clean_ver = version or ""
            if clean_ver and any(c in clean_ver for c in "[](),*"):
                import re as _re
                stripped = clean_ver.strip("[]() ")
                parts = [p.strip() for p in stripped.split(",") if p.strip()]
                for p in parts:
                    if _re.match(r'^\d', p):
                        clean_ver = p
                        break
            purl = config.generate_cert_in_identifier(ecosystem, name, clean_ver, supplier)
            pkg["unique_identifier"] = purl
        
        return packages
    
    def _apply_registry_info(self, pkg: Dict, info: Dict) -> None:
        """
        Apply registry info to a package dict.
        
        Args:
            pkg: Package dict to update
            info: Registry info from PyPIClient or NpmClient
        """
        _BAD_DESC = {"", "No description available", "N/A", "No description available."}
        _BAD_SUPPLIER = {"", "Unknown", "N/A", "unknown"}
        
        # Description — clean markdown/HTML, collapse newlines
        cur_desc = (pkg.get("component_description") or "").strip()
        if not cur_desc or cur_desc in _BAD_DESC:
            desc = info.get("description") or "No description available"
            desc = self._clean_text(desc, max_len=300)
            pkg["component_description"] = desc
            pkg["description"] = desc
        
        # Supplier
        cur_supplier = (pkg.get("supplier") or pkg.get("component_supplier") or "").strip()
        if not cur_supplier or cur_supplier in _BAD_SUPPLIER:
            pkg["supplier"] = info.get("supplier") or "Unknown"
            pkg["component_supplier"] = pkg["supplier"]
        
        # Hashes
        if not pkg.get("hashes"):
            pkg["hashes"] = info.get("hashes") or []
        
        # Mark this package as already enriched by registry_enrich step.
        # Used by enrich_python_pkg / enrich_npm_pkg in sbom_utils to skip
        # redundant API calls during generate-sbom (prevents triple-fetching).
        pkg["_registry_enriched"] = True
    
    @staticmethod
    def _clean_text(text: str, max_len: int = 300) -> str:
        """Strip markdown/HTML tags, collapse whitespace, truncate."""
        if not text:
            return ""
        import re
        # Strip HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Strip markdown headers (# ## ###)
        text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)
        # Strip markdown links [text](url) → text
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        # Collapse multiple newlines/whitespace into single space
        text = re.sub(r'\s*\n\s*', ' ', text)
        text = re.sub(r'\s{2,}', ' ', text)
        text = text.strip()
        if len(text) > max_len:
            text = text[:max_len].rsplit(' ', 1)[0] + '...'
        return text
    
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
        from sbom.src.clients.pypi_client import fetch_pypi_meta
        
        for pkg in packages:
            lang = (pkg.get("language") or "").lower()
            name = pkg.get("name")
            version = pkg.get("version")
            
            # Default values (unknown until confirmed by registry)
            pkg["eol_status"] = "Unknown"
            pkg["eol_date"] = None
            pkg["is_deprecated"] = False
            
            if not name:
                continue
            
            try:
                has_registry_info = False
                status_set = False
                if lang == "python":
                    # Check PyPI for deprecation
                    meta = fetch_pypi_meta(name, version)
                    if meta:
                        has_registry_info = True
                        status_set = False
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
                                    status_set = True
                                    continue
                        
                        # Check Development Status classifiers
                        classifiers = info.get("classifiers", []) or []
                        for classifier in classifiers:
                            if "Development Status :: 7 - Inactive" in classifier:
                                pkg["eol_status"] = "Inactive (no longer maintained)"
                                pkg["is_deprecated"] = True
                                status_set = True
                                break
                            elif "Development Status :: 1 - Planning" in classifier:
                                pkg["eol_status"] = "Pre-release (Planning stage)"
                                status_set = True
                                break
                        # If we got registry info but no deprecation found, it's Active
                        if has_registry_info and not status_set:
                            pkg["eol_status"] = "Active"
                        
                elif lang in ["javascript", "npm", "node", "js"]:
                    # Check npm for deprecation
                    # The raw_data from npm includes deprecated field
                    info = _npm_client.get_package_info(name, version)
                    if info.get("success") and info.get("raw_data"):
                        has_registry_info = True
                        status_set = False
                        data = info["raw_data"]
                        versions = data.get("versions", {})
                        
                        # Check if specific version is deprecated
                        if version and version in versions:
                            version_data = versions[version]
                            deprecated = version_data.get("deprecated")
                            if deprecated:
                                pkg["eol_status"] = f"Deprecated: {deprecated}" if isinstance(deprecated, str) else "Deprecated"
                                pkg["is_deprecated"] = True
                                status_set = True
                        else:
                            # Check if entire package is deprecated (latest version)
                            latest = data.get("dist-tags", {}).get("latest")
                            if latest and latest in versions:
                                deprecated = versions[latest].get("deprecated")
                                if deprecated:
                                    pkg["eol_status"] = f"Deprecated: {deprecated}" if isinstance(deprecated, str) else "Deprecated"
                                    pkg["is_deprecated"] = True
                                    status_set = True
                        # If we got registry info but no deprecation found, it's Active
                        if has_registry_info and not status_set:
                            pkg["eol_status"] = "Active"

                elif lang in ["dotnet", "nuget", ".net", "c#", "csharp"]:
                    # Check NuGet for deprecation
                    from sbom.src.clients.nuget_client import fetch_nuget_meta as fetch_nuget_meta_eol

                    meta = fetch_nuget_meta_eol(name, version)
                    if meta:
                        has_registry_info = True
                        status_set = False

                        deprecation = meta.get("deprecation")
                        if isinstance(deprecation, dict) and deprecation:
                            message = deprecation.get("message") or ""
                            reasons = deprecation.get("reasons") or []
                            reason_text = ", ".join(reasons) if isinstance(reasons, list) else ""
                            detail = message or reason_text
                            pkg["eol_status"] = f"Deprecated: {detail}" if detail else "Deprecated"
                            pkg["is_deprecated"] = True
                            status_set = True

                        listed = meta.get("listed")
                        if listed is False and not status_set:
                            pkg["eol_status"] = "Unlisted"
                            status_set = True

                        if has_registry_info and not status_set:
                            pkg["eol_status"] = "Active"

                elif lang in ["ruby", "gem", "rubygems", "bundler"]:
                    # RubyGems: check if gem is yanked
                    try:
                        from sbom.src.clients.rubygems_client import fetch_rubygems_meta
                        meta = fetch_rubygems_meta(name, version)
                        if meta:
                            has_registry_info = True
                            pkg["eol_status"] = "Active"
                        elif meta is None and version:
                            pkg["eol_status"] = "Unknown (version not found)"
                    except Exception:
                        pass
                    if has_registry_info and not pkg.get("is_deprecated"):
                        pkg["eol_status"] = pkg.get("eol_status") or "Active"

                elif lang in ["php", "composer", "packagist"]:
                    # Packagist: check if package is abandoned
                    try:
                        from sbom.src.clients.packagist_client import fetch_packagist_meta
                        meta = fetch_packagist_meta(name, version)
                        if meta:
                            has_registry_info = True
                            abandoned = meta.get("abandoned")
                            if abandoned:
                                replacement = abandoned if isinstance(abandoned, str) else ""
                                detail = f"Abandoned (use {replacement})" if replacement else "Abandoned"
                                pkg["eol_status"] = detail
                                pkg["is_deprecated"] = True
                            else:
                                pkg["eol_status"] = "Active"
                    except Exception:
                        pass

                elif lang in ["go", "golang"]:
                    # Go: check if module is retracted
                    try:
                        from sbom.src.clients.go_client import fetch_go_meta
                        meta = fetch_go_meta(name, version)
                        if meta:
                            has_registry_info = True
                            pkg["eol_status"] = "Active"
                    except Exception:
                        pass

                elif lang in ["java", "maven", "gradle"]:
                    # Maven: no standard deprecation; mark as Active if found
                    try:
                        from sbom.src.clients.maven_client import fetch_maven_meta
                        group_id = pkg.get("group_id", "")
                        artifact_id = pkg.get("artifact_id", "")
                        if not group_id and ":" in (name or ""):
                            parts = name.split(":")
                            group_id = parts[0]
                            artifact_id = parts[1] if len(parts) > 1 else ""
                        elif not artifact_id:
                            artifact_id = name
                        meta = fetch_maven_meta(group_id, artifact_id, version)
                        if meta:
                            has_registry_info = True
                            pkg["eol_status"] = "Active"
                    except Exception:
                        pass

                elif lang in ["rust", "cargo", "crate", "crates"]:
                    # Crates.io: check if crate or version is yanked
                    try:
                        from sbom.src.clients.cargo_client import fetch_cargo_meta
                        meta = fetch_cargo_meta(name, version)
                        if meta:
                            has_registry_info = True
                            ver_info = meta.get("version", {})
                            if ver_info.get("yanked"):
                                pkg["eol_status"] = "Yanked"
                                pkg["is_deprecated"] = True
                            else:
                                pkg["eol_status"] = "Active"
                    except Exception:
                        pass

                elif lang in ["swift", "cocoapods", "pods"]:
                    # CocoaPods: check if pod exists
                    try:
                        import requests
                        from sbom.src.config.config import COCOAPODS_API, API_TIMEOUT
                        url = f"{COCOAPODS_API}/pods/{name}"
                        resp = requests.get(url, timeout=API_TIMEOUT)
                        if resp.status_code == 200:
                            has_registry_info = True
                            data = resp.json()
                            if data.get("deprecated"):
                                pkg["eol_status"] = "Deprecated"
                                pkg["is_deprecated"] = True
                            else:
                                pkg["eol_status"] = "Active"
                    except Exception:
                        pass

                elif lang in ["conda", "anaconda"]:
                    # Conda: no standard deprecation mechanism
                    try:
                        from sbom.src.clients.anaconda_client import AnacondaClient
                        client = AnacondaClient()
                        channel = pkg.get("channel", "conda-forge")
                        meta = client.get_package_info(name, channel)
                        if meta:
                            has_registry_info = True
                            pkg["eol_status"] = "Active"
                    except Exception:
                        pass
                                    
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
        from sbom.src.utils.file_analysis import scan_codebase_properties
        
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
        from sbom.src.core.vulnerability_provider import enrich_catalog_with_vulns
        
        # Build temporary catalog for enrichment
        catalog = {"packages": packages}
        
        # Enrich with vulnerabilities
        catalog = enrich_catalog_with_vulns(catalog, nvd_api_key=self.nvd_api_key)
        
        # Clean vulnerability details text (strip markdown/HTML, collapse whitespace)
        for pkg in catalog.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                if vuln.get("details"):
                    vuln["details"] = self._clean_text(vuln["details"], max_len=500)
                if vuln.get("summary"):
                    vuln["summary"] = self._clean_text(vuln["summary"], max_len=300)
        
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
        from sbom.src.config.config import TOOL_NAME, TOOL_VENDOR, TOOL_VERSION
        
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
        from sbom.src.core.sbom_generator import generate_all
        from sbom.src.report.report_writer import write_reports
        
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
        from sbom.src.report.remediation_reporter import RemediationReporter
        
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
        from sbom.src.core.orchestrator import scan
        
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
