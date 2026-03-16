"""
SBOM Pydantic Models
Request and Response models for the SBOM API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel


# =============================================================================
# REPOSITORY REQUEST MODELS
# =============================================================================

class SetRepositoryRequest(BaseModel):
    """Request model for /set_repository endpoint"""
    repo_url: str
    pat: Optional[str] = None


class SetRepositoryResponse(BaseModel):
    """Response model for /set_repository endpoint"""
    message: str
    session_token: str
    valid: bool
    repository: str
    branch: str
    file_count: int
    local_path: str


# =============================================================================
# VALIDATION RESPONSE MODELS
# =============================================================================

class ValidationResponse(BaseModel):
    """Base response for all validation endpoints"""
    valid: bool
    file_count: int
    local_path: str


class RepoValidationResponse(ValidationResponse):
    """Response for GitHub repository validation"""
    repository: str
    branch: str


class ZipValidationResponse(ValidationResponse):
    """Response for ZIP file validation"""
    message: str
    source: str


class LocalValidationResponse(ValidationResponse):
    """Response for local file upload validation"""
    message: str


# =============================================================================
# SCAN MODELS
# =============================================================================

class StartScanResponse(BaseModel):
    """Response for /start_scan endpoint"""
    message: str
    scan_id: str
    next_step: str
    workflow: List[str]


class ManifestInfo(BaseModel):
    """Information about a discovered manifest file"""
    file: str
    ecosystem: str
    path: str


class PackageInfo(BaseModel):
    """Summary information about a package"""
    component_name: str
    version: str
    language: str
    is_direct_dependency: bool


class DiscoverParseResponse(BaseModel):
    """Response for /discover_and_parse endpoint"""
    message: str
    scan_id: str
    manifests_found: int
    ecosystems_detected: List[str]
    manifests: List[ManifestInfo]
    packages_found: int
    by_ecosystem: Dict[str, int]
    packages: List[Any]  # Can include PackageInfo or {"note": "..."} 
    codebase_properties: Dict[str, str]
    license_detection: Optional[Dict[str, Any]]
    next_step: str


class DepsDevPackage(BaseModel):
    """Package with deps.dev enrichment"""
    component_name: str
    version: str
    is_direct_dependency: bool
    dependency_type: str
    component_license: str
    homepage: str
    release_date: str
    component_dependencies: List[str]


class FetchDepsDevResponse(BaseModel):
    """Response for /fetch_depsdev endpoint"""
    message: str
    scan_id: str
    direct_dependencies: int
    transitive_dependencies_added: int
    total_packages: int
    successfully_enriched: int
    not_found_in_depsdev: int
    fields_added: List[str]
    packages: List[DepsDevPackage]
    next_step: str


class HashInfo(BaseModel):
    """Hash information for a package"""
    alg: str
    content: str


class RegistryPackage(BaseModel):
    """Package with registry enrichment"""
    component_name: str
    version: str
    is_direct_dependency: bool
    dependency_type: str
    registry: str
    component_description: str
    component_supplier: str
    hashes: List[HashInfo]
    unique_identifier: str


class RegistryEnrichResponse(BaseModel):
    """Response for /registry_enrich endpoint"""
    message: str
    scan_id: str
    packages_processed: int
    by_registry: Dict[str, int]
    fields_added: List[str]
    packages: List[RegistryPackage]
    next_step: str


class VulnerabilityInfo(BaseModel):
    """Vulnerability information"""
    id: str
    severity: str
    severity_level: str
    summary: str
    details: str
    fixed_in: str
    url: str
    aliases: List[str]
    patch_status: str
    criticality: str


class VulnerablePackage(BaseModel):
    """Package with vulnerabilities"""
    component_name: str
    version: str
    vulnerabilities: List[VulnerabilityInfo]


class FetchOsvResponse(BaseModel):
    """Response for /fetch_osv endpoint"""
    message: str
    scan_id: str
    packages_scanned: int
    packages_affected: int
    vulnerabilities_found: int
    severity_breakdown: Dict[str, int]
    fields_fetched: List[str]
    fields_derived: List[str]
    vulnerable_packages: List[VulnerablePackage]
    next_step: str


class ScanSummary(BaseModel):
    """Scan summary for SBOM generation"""
    total_components: int
    total_vulnerabilities: int
    ecosystems: List[str]


class GenerateSbomResponse(BaseModel):
    """Response for /generate_sbom endpoint"""
    message: str
    scan_id: str
    project_name: str
    newly_generated: List[str]
    already_existed: List[str]
    scan_summary: ScanSummary
    reports: Dict[str, str]
    next_step: str


class RemediationAction(BaseModel):
    """Remediation action for a package"""
    package: str
    current_version: str
    fix_version: str
    severity: str
    severity_level: str
    urgency: str
    action: str
    cves_fixed: List[str]


class GenerateRemediationResponse(BaseModel):
    """Response for /generate_remediation endpoint"""
    message: str
    scan_id: str
    report_path: str
    total_actions: int
    report: Optional[Dict[str, Any]]
