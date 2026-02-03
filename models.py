"""
AIBOM Pydantic Models
Request and Response models for the AIBOM API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from config import SOURCE_TYPES


# =============================================================================
# SOURCE TYPE MODELS
# =============================================================================

class SourceTypeRequest(BaseModel):
    """Request model for /source_type endpoint"""
    source_type: SOURCE_TYPES


class SourceTypeResponse(BaseModel):
    """Response model for /source_type endpoint"""
    message: str
    session_token: str
    source_type: str


# =============================================================================
# VALIDATION REQUEST MODELS
# =============================================================================

class RepoPublicRequest(BaseModel):
    """Request model for /validate/repo_public endpoint"""
    repo_url: str


class RepoPrivateRequest(BaseModel):
    """Request model for /validate/repo_private endpoint"""
    repo_url: str
    pat: str


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
# FILES ENDPOINT MODELS
# =============================================================================

class FileInfo(BaseModel):
    """Information about a single file"""
    path: str
    size_bytes: Optional[int] = None


class FilesResponse(BaseModel):
    """Response for /files endpoint"""
    total_files: int
    files: List[str]
    


class CodeTokensResponse(BaseModel):
    """Response for /code_tokens endpoint"""
    token_count: int
    tokens: List[str]
    code_files_processed: int


class ManifestsFound(BaseModel):
    """Manifests found per language"""
    python: List[str] = []
    javascript: List[str] = []


class DependenciesFound(BaseModel):
    """Dependencies found per language"""
    python: List[str] = []
    javascript: List[str] = []


class PackagesSummary(BaseModel):
    """Summary of package analysis"""
    total_languages: int
    total_manifests: int
    total_dependencies: int


class PackagesResponse(BaseModel):
    """Response for /packages endpoint"""
    languages_detected: List[str]
    manifests_found: ManifestsFound
    dependencies: DependenciesFound
    summary: PackagesSummary


# =============================================================================
# SEMGREP SCAN MODELS
# =============================================================================

class ImportInfo(BaseModel):
    """Single import detection result"""
    file: str
    line: int
    module: Optional[str] = None
    imported_item: Optional[str] = None
    base_package: str
    is_builtin: bool
    is_relative: bool
    import_type: str
    language: str


class LanguageImports(BaseModel):
    """Import results for a single language"""
    third_party: List[ImportInfo] = []
    builtin: List[ImportInfo] = []
    relative: List[ImportInfo] = []


class ImportPackage(BaseModel):
    """Package with source file mappings"""
    package: str
    source_files: List[str] = []


class ImportPackages(BaseModel):
    """Filtered external packages"""
    python_imports: List[ImportPackage] = []
    javascript_imports: List[ImportPackage] = []


class SemgrepScanSummary(BaseModel):
    """Summary of semgrep scan results"""
    total_third_party: int
    total_builtin: int
    total_relative: int


class SemgrepScanResponse(BaseModel):
    """Response for /semgrep-imports-scan endpoint - raw scan results"""
    scan_results: Dict[str, LanguageImports]
    summary: SemgrepScanSummary


class FilteredImportsSummary(BaseModel):
    """Summary of filtered imports"""
    total_before_filter: int
    total_after_filter: int
    local_imports_removed: int
    unique_external_packages: int


class FilteredImportsResponse(BaseModel):
    """Response for /filtered-imports endpoint - unique packages only"""
    import_packages: ImportPackages
    summary: FilteredImportsSummary


# =============================================================================
# LLM VALIDATION MODELS
# =============================================================================

class AILibrary(BaseModel):
    """AI-positive library with source file mappings"""
    library: str
    confidence: str  # HIGH, MEDIUM, LOW
    reason: str
    source_files: List[str] = []
    language: Optional[str] = None


class LLMValidationSummary(BaseModel):
    """Summary of LLM validation results"""
    total_classified: int
    total_ai_positive: int
    total_non_ai: int
    model_used: str


class LLMValidationResponse(BaseModel):
    """Response for /llm-validate endpoint"""
    ai_libraries: List[AILibrary]
    non_ai_libraries: List[str]
    summary: LLMValidationSummary


# =============================================================================
# LLM CATEGORIZATION MODELS
# =============================================================================

class CategorizedLibrary(BaseModel):
    """Categorized AI library"""
    library: str
    confidence: str
    reason: str
    source_files: List[str] = []
    language: Optional[str] = None


class CategoryGroup(BaseModel):
    """Group of libraries in a category"""
    count: int
    libraries: List[CategorizedLibrary]


class CategorizationResponse(BaseModel):
    """Response for /llm-categorize endpoint"""
    by_category: Dict[str, CategoryGroup]
    total_libraries: int
    model_used: str


# =============================================================================
# PACKAGE RESOLUTION MODELS
# =============================================================================

class UnifiedPackage(BaseModel):
    """Unified package from manifest or imports"""
    library: str
    language: str
    source: str  # "import" or "manifest"
    source_files: List[str] = []
    resolution_method: str
    resolved_imports: Optional[List[str]] = None


class ResolutionSummary(BaseModel):
    """Summary of package resolution"""
    total_manifest_deps: int
    total_import_packages: int
    duplicates_removed: int
    resolution_methods: Dict[str, int]


class ResolvePackagesResponse(BaseModel):
    """Response for /resolve-packages endpoint"""
    unified_packages: List[UnifiedPackage]
    resolution_summary: ResolutionSummary
    skipped: bool = False
    skip_reason: Optional[str] = None


# =============================================================================
# DEPENDENCY GRAPH MODELS
# =============================================================================

class GraphNode(BaseModel):
    """Node in the dependency graph (represents a file)"""
    id: str
    file: str
    language: str
    local_import_count: int
    external_import_count: int
    external_imports: List[str]


class GraphEdge(BaseModel):
    """Edge in the dependency graph (represents an import relationship)"""
    source: str
    target: str
    type: str = "import"


class LanguageStats(BaseModel):
    """Per-language statistics"""
    files: int
    local: int
    external: int


class GraphMetadata(BaseModel):
    """Metadata about the dependency graph"""
    total_files: int
    total_dependencies: int
    local_imports: int
    external_imports: int
    by_language: Dict[str, LanguageStats]


class DependencyGraphResponse(BaseModel):
    """Response for /dependency-graph endpoint"""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: GraphMetadata


# =============================================================================
# AI BRANCH TRACE MODELS
# =============================================================================

class AIBranch(BaseModel):
    """Single AI library branch with traced files"""
    library: str
    category: str
    language: str = "python"
    semgrep_rule: Optional[str] = None
    source_files: List[str]
    traced_files: List[str]
    branch_size: int
    error: Optional[str] = None


class CategoryStats(BaseModel):
    """Statistics for a category in branch trace"""
    count: int
    total_files: int


class BranchLanguageStats(BaseModel):
    """Statistics for a language in branch trace"""
    count: int
    total_files: int


class BranchTraceSummary(BaseModel):
    """Summary statistics for branch trace"""
    total_branches: int
    total_source_files: int
    total_traced_files: int
    by_category: Dict[str, CategoryStats]
    by_language: Dict[str, BranchLanguageStats]
    timestamp: str


class BranchSummaryItem(BaseModel):
    """Summary item for a single branch (for branch_list)"""
    library: str
    category: str
    language: str
    branch_size: int
    source_files: List[str]
    traced_files: List[str]
    semgrep_rule: Optional[str] = None
    error: Optional[str] = None


class AIBranchTraceResponse(BaseModel):
    """Response for /ai-branch-trace endpoint"""
    branches: Dict[str, AIBranch]
    summary: BranchTraceSummary
    branch_list: List[BranchSummaryItem]  # Sorted summary for easy display


# =============================================================================
# AI TARGETED SCAN MODELS
# =============================================================================

class ScanFinding(BaseModel):
    """Single deduplicated scan finding"""
    file: str
    line: int
    end_line: int = 0
    rule_id: str
    message: str
    severity: str = "INFO"
    code_snippet: str = ""
    model_value: Optional[str] = None
    rule_category: str = ""
    api_method: Optional[str] = None  # For api_calls findings
    api_url: Optional[str] = None     # For api_calls findings


class ModelDetection(BaseModel):
    """A detected model with source location"""
    model: str
    file: str
    line: int
    library: str = "detected"



class LibraryScanResult(BaseModel):
    """Scan result for a single library"""
    library: str
    category: str
    language: str
    scanned: bool
    reason: Optional[str] = None
    rules_used: List[str] = []
    traced_files_count: int = 0
    findings_count: int = 0
    findings: List[ScanFinding] = []
    models_detected: List[str] = []
    provider_rule_found: bool = False


class ScanSummary(BaseModel):
    """Summary of all scans"""
    total_libraries: int
    libraries_scanned: int
    total_findings: int
    unique_models_detected: int
    all_models: List[str] = []
    api_calls_count: int = 0
    errors: List[str] = []
    timestamp: str
    language: str = "python"
    rules_used: Dict[str, Any] = {}
    rules_available: Dict[str, Any] = {}


class AITargetedScanResponse(BaseModel):
    """Response for /ai-targeted-scan endpoint"""
    scan_results: Dict[str, LibraryScanResult]
    models_detected: List[ModelDetection] = []
    distinct_models: List[str] = []
    model_detection_findings: List[ScanFinding] = []
    summary: ScanSummary


# =============================================================================
# ERROR RESPONSE MODELS
# =============================================================================

class ErrorDetail(BaseModel):
    """Standard error response detail"""
    error: str
    message: str
    hint: Optional[str] = None


class EndpointLockedError(BaseModel):
    """Error response when endpoint is locked"""
    error: str = "ENDPOINT_LOCKED"
    message: str
    current_source_type: str
    available_endpoint: str
    hint: str


# =============================================================================
# MODEL CARD HANDLER MODELS
# =============================================================================

class SuffixInfo(BaseModel):
    """Parsed suffix information"""
    suffix: str
    type: str  # known, token_window, parameter_count, version, unknown
    meaning: str
    token_count: Optional[int] = None
    parameter_count: Optional[str] = None


class ModelCardResult(BaseModel):
    """Result for a single model card lookup"""
    model_card_found: bool
    original_model_name: str
    base_model_name: str
    stripped_suffixes: List[str] = []
    suffix_info: List[SuffixInfo] = []
    model_card: Optional[Dict[str, Any]] = None
    lookup_source: Optional[str] = None  # cache, huggingface, huggingface_stripped, azure_ai_foundry, etc.
    iterations_required: int = 0


class ModelCardSummary(BaseModel):
    """Summary of model card lookup results"""
    source_breakdown: Dict[str, int] = {}
    success_rate: str = "0%"


class ModelCardHandlerRequest(BaseModel):
    """Request model for /model-card-handler endpoint (optional override)"""
    model_names: Optional[List[str]] = None  # Override distinct_models from session
    try_stripping: bool = True  # Whether to try suffix stripping
    try_azure: bool = True  # Whether to try Azure AI Foundry


class ModelCardHandlerResponse(BaseModel):
    """Response for /model-card-handler endpoint"""
    models_processed: int
    found_count: int
    not_found_count: int
    results: List[ModelCardResult]
    summary: ModelCardSummary


# =============================================================================
# MODEL DEPRECATION CHECKER MODELS
# =============================================================================

class DeprecationInfo(BaseModel):
    """Deprecation information for a single model"""
    model_id: str
    provider: str
    status: str  # deprecated, shutdown, legacy
    is_deprecated: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    announcement_date: Optional[str] = None
    shutdown_date: Optional[str] = None
    days_until_shutdown: Optional[int] = None
    recommended_replacement: Optional[str] = None
    final_replacement: Optional[str] = None
    replacement_chain: List[str] = []
    category: Optional[str] = None
    type: Optional[str] = None
    notes: str = ""
    deprecated_price: Optional[str] = None


class ModelDeprecationResult(BaseModel):
    """Result for a single model deprecation check"""
    model_name: str
    model_card_found: bool  # From model-card-handler
    deprecation_found: bool
    deprecation_info: Optional[DeprecationInfo] = None
    message: str = ""


class DeprecationSummary(BaseModel):
    """Summary of deprecation check results"""
    models_checked: int
    deprecated_count: int
    active_count: int
    not_found_count: int
    severity_breakdown: Dict[str, int] = {}


class ModelDeprecationResponse(BaseModel):
    """Response for /model-deprecation-check endpoint"""
    models_checked: int
    deprecated_count: int
    active_count: int
    not_found_count: int
    results: List[ModelDeprecationResult]
    summary: DeprecationSummary

