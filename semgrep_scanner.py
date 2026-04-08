"""
AIBOM Semgrep Scanner
Simplified semgrep-based import detection for the AIBOM API.
Runs semgrep rules to detect Python and JavaScript imports.
"""

import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional

from config import (
    SEMGREP_MAX_MEMORY_MB,
    SEMGREP_TIMEOUT_SECONDS,
    SEMGREP_RULE_FILES,
    PYTHON_BUILTINS,
    JS_BUILTINS,
    LANGUAGE_EXTENSIONS,
)

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
SEMGREP_RULES_DIR = BASE_DIR / "semgrep"


# =============================================================================
# SEMGREP RUNNER
# =============================================================================

def run_semgrep(checkout: Path, rule_file: Path, language: str) -> List[Dict]:
    """Run Semgrep with specific rule file and return findings."""
    if not rule_file.exists():
        print(f"[SEMGREP] ERROR: Rule file not found: {rule_file}")
        logger.error(f"[SEMGREP] Rule file not found: {rule_file}")
        return []
    
    # Count files that will be scanned using config-defined extensions
    exts = LANGUAGE_EXTENSIONS.get(language, frozenset())
    file_count = sum(1 for ext in exts for _ in checkout.rglob(f"*{ext}"))
    print(f"[SEMGREP] Scanning {file_count} {language} files in {checkout}")
    print(f"[SEMGREP] Using rule: {rule_file}")
    logger.info(f"[SEMGREP] Scanning {file_count} {language} files with {rule_file.name}")
    
    if file_count == 0:
        print(f"[SEMGREP] WARNING: No {language} files found!")
        logger.warning(f"[SEMGREP] No {language} files found in {checkout}")
        return []
    
    cmd = [
        "semgrep",
        "--config", str(rule_file),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--optimizations", "all",
        "--max-memory", str(SEMGREP_MAX_MEMORY_MB),
        str(checkout)
    ]
    
    try:
        print(f"[SEMGREP] Running: semgrep --config {rule_file.name} ...")
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=SEMGREP_TIMEOUT_SECONDS,
            cwd=str(checkout)
        )
        
        if result.returncode != 0:
            print(f"[SEMGREP] Warning: Exit code {result.returncode}")
            logger.warning(f"[SEMGREP] Non-zero exit code: {result.returncode}")
            if result.stderr:
                print(f"[SEMGREP] Stderr: {result.stderr[:300]}")
                logger.debug(f"[SEMGREP] Stderr: {result.stderr[:500]}")
        
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                print(f"[SEMGREP] Found {len(findings)} import findings for {language}")
                logger.info(f"[SEMGREP] Found {len(findings)} import findings for {language}")
                return findings
            except json.JSONDecodeError as e:
                print(f"[SEMGREP] ERROR: JSON parse failed: {e}")
                logger.error(f"[SEMGREP] JSON parse error: {e}")
                return []
        
        print(f"[SEMGREP] No findings (empty output) for {language}")
        logger.info(f"[SEMGREP] No findings (empty output) for {language}")
        return []
    
    except subprocess.TimeoutExpired:
        print(f"[SEMGREP] ERROR: Timeout after {SEMGREP_TIMEOUT_SECONDS}s")
        logger.error(f"[SEMGREP] Timeout after {SEMGREP_TIMEOUT_SECONDS}s")
        return []
    except FileNotFoundError:
        print("[SEMGREP] ERROR: semgrep command not found - is it installed?")
        logger.error("[SEMGREP] semgrep command not found - is it installed?")
        return []
    except Exception as e:
        print(f"[SEMGREP] ERROR: Unexpected error: {e}")
        logger.error(f"[SEMGREP] Unexpected error: {e}")
        return []


# =============================================================================
# IMPORT EXTRACTION
# =============================================================================

def extract_python_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module and imported item from Python import finding.
    
    Semgrep OSS doesn't export metavars in JSON, so we parse from message.
    Message formats from python_imports.yml:
      - "Python import: <module>"                      (direct-import)
      - "Python import: from <module> import <item>"   (from-import)
      - "Python relative import: from .<module> import <item>" (relative-import)
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    module = ""
    item = ""
    
    # Try metavars first (works in some semgrep versions)
    metavars = extra.get("metavars", {})
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
        item = metavars.get("$ITEM", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        # Handle relative import message format
        if "Python relative import:" in message:
            # "Python relative import: from .module import item"
            content = message.split("Python relative import:", 1)[-1].strip()
            if content.startswith("from "):
                parts = content.split(" import ", 1)
                if len(parts) >= 2:
                    module = parts[0].replace("from ", "").strip()
                    item = parts[1].strip()
                    # Handle "from . import item" case where module might be empty/just dots
                    if module in (".", "..", "..."):
                        item = parts[1].strip()
                        module = module  # Keep the dots
        
        # Handle regular import message format
        elif "Python import:" in message:
            # "Python import: from module import item" or "Python import: module"
            content = message.split("Python import:", 1)[-1].strip()
            
            if content.startswith("from "):
                # "from module import item" pattern
                parts = content.split(" import ", 1)
                if len(parts) >= 2:
                    module = parts[0].replace("from ", "").strip()
                    item = parts[1].strip()
            else:
                # Direct import: just the module name
                module = content.strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Reject invalid module names that contain " import " - these are parsing errors
    # from semgrep matching the wrong pattern (e.g., direct-import matching from-import)
    if " import " in module:
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    is_relative = metadata.get("is_relative", False) or module.startswith(".")
    
    # Clean relative import prefix for base_package extraction
    module_clean = module.lstrip(".")
    base_package = module_clean.split(".")[0] if module_clean else module
    is_builtin = base_package.lower() in PYTHON_BUILTINS
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": item or None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "python",
    }


def extract_js_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module from JavaScript/TypeScript import finding.
    
    Semgrep OSS doesn't export metavars, so we parse from message.
    Message formats from javascript_imports.yml:
      - "JavaScript named import from <module>"
      - "JavaScript default import from <module>"
      - "JavaScript namespace import from <module>"
      - "JavaScript require: <module>"
      - "JavaScript dynamic import: <module>"
    """
    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    # Skip if marked by semgrep rule (e.g., path aliases)
    if metadata.get("skip"):
        return None
    
    module = ""
    
    # Try metavars first (works in some semgrep versions)
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        # Pattern: "JavaScript X import from <module>" or "JavaScript require: <module>"
        if " from " in message:
            # Named/default/namespace import: extract after "from "
            module = message.split(" from ", 1)[-1].strip()
        elif "require:" in message:
            # Require pattern: "JavaScript require: <module>"
            module = message.split("require:", 1)[-1].strip()
        elif "dynamic import:" in message:
            # Dynamic import: "JavaScript dynamic import: <module>"
            module = message.split("dynamic import:", 1)[-1].strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    is_relative = metadata.get("is_relative", False) or module.startswith(".") or module.startswith("/")
    
    # Python-only: derive base_package (scoped packages need special handling)
    if module.startswith("@"):
        # Scoped package: @anthropic-ai/sdk → @anthropic-ai/sdk
        parts = module.split("/")
        base_package = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else module
    else:
        # Regular package: langchain/embeddings → langchain
        base_package = module.split("/")[0]
    
    # Python-only: check against builtin set
    is_builtin = base_package in JS_BUILTINS or module in JS_BUILTINS
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "javascript",
    }


# Map language to extractor function
IMPORT_EXTRACTORS = {
    "python": extract_python_import_info,
    "javascript": extract_js_import_info,
}


# =============================================================================
# MAIN SCANNING FUNCTIONS
# =============================================================================

def make_path_relative(file_path: str, checkout: Path) -> str:
    """Convert absolute file path to relative path from checkout root."""
    try:
        return str(Path(file_path).relative_to(checkout)).replace("\\", "/")
    except ValueError:
        # Path already relative or outside checkout
        return file_path.replace("\\", "/")


def scan_imports(checkout: Path, languages: Set[str]) -> Dict:
    """
    Scan for imports in all detected languages.
    
    Returns dict with results per language:
    {
        "python": {"third_party": [...], "builtin": [...], "relative": [...]},
        "javascript": {"third_party": [...], "builtin": [...], "relative": [...]}
    }
    """
    results = {}
    
    for lang in languages:
        # Check if we have a rule file configured for this language
        if lang in SEMGREP_RULE_FILES:
            rule_file = SEMGREP_RULES_DIR / SEMGREP_RULE_FILES[lang]
            findings = run_semgrep(checkout, rule_file, lang)
            results[lang] = categorize_imports(findings, lang, checkout)
        else:
            # Language not configured - return empty results
            results[lang] = {"third_party": [], "builtin": [], "relative": []}
    
    return results


def categorize_imports(findings: List[Dict], language: str, checkout: Path) -> Dict:
    """Categorize imports into third_party, builtin, and relative."""
    result = {
        "third_party": [],
        "builtin": [],
        "relative": []
    }
    
    # Get extractor function for this language dynamically
    extractor = IMPORT_EXTRACTORS.get(language)
    if not extractor:
        print(f"[CATEGORIZE] No extractor for language: {language}")
        return result
    
    null_count = 0
    for finding in findings:
        import_info = extractor(finding)
        
        if import_info is None:
            null_count += 1
            # Debug: Print first few failures with full finding structure
            if null_count <= 3:
                metavars = finding.get("extra", {}).get("metavars", {})
                check_id = finding.get("check_id", "unknown")
                extra_keys = list(finding.get("extra", {}).keys())
                print(f"[CATEGORIZE] Extraction returned None.")
                print(f"[CATEGORIZE]   check_id: {check_id}")
                print(f"[CATEGORIZE]   extra keys: {extra_keys}")
                print(f"[CATEGORIZE]   metavars: {metavars}")
                # Print first finding fully for debugging
                if null_count == 1:
                    import json
                    print(f"[CATEGORIZE] FULL FINDING: {json.dumps(finding, indent=2, default=str)[:1000]}")
            continue
        
        # Make file path relative
        import_info["file"] = make_path_relative(import_info["file"], checkout)
        
        # Categorize
        if import_info.get("is_relative"):
            result["relative"].append(import_info)
        elif import_info.get("is_builtin"):
            result["builtin"].append(import_info)
        else:
            result["third_party"].append(import_info)
    
    # Debug summary
    if null_count > 0:
        print(f"[CATEGORIZE] {null_count} of {len(findings)} findings had extraction failures")
    print(f"[CATEGORIZE] Results for {language}: third_party={len(result['third_party'])}, builtin={len(result['builtin'])}, relative={len(result['relative'])}")
    
    return result


def deduplicate_imports(imports: List[Dict]) -> List[Dict]:
    """Remove duplicate imports based on file, line, and module."""
    seen = set()
    unique = []
    
    for imp in imports:
        key = (
            imp.get("file", ""),
            imp.get("line", 0),
            imp.get("module", ""),
            imp.get("imported_item", "")
        )
        if key not in seen:
            seen.add(key)
            unique.append(imp)
    
    return unique


def filter_local_imports(scan_results: Dict, code_tokens: Set[str]) -> Dict:
    """Filter out local/internal imports by matching against code tokens."""
    filtered = {}
    
    for lang, lang_data in scan_results.items():
        filtered[lang] = {
            "third_party": [],
            "builtin": lang_data.get("builtin", []),
            "relative": lang_data.get("relative", [])
        }
        
        for imp in lang_data.get("third_party", []):
            base_package = imp.get("base_package", "")
            
            # Fast check: base_package is most likely match
            if base_package and base_package in code_tokens:
                continue
            
            imported_item = imp.get("imported_item", "")
            if imported_item and imported_item in code_tokens:
                continue
            
            module = imp.get("module", "")
            if module:
                # Only split if base_package check failed (lazy evaluation)
                module_parts = module.split(".")
                if any(part in code_tokens for part in module_parts):
                    continue
            
            # Not local - keep it
            filtered[lang]["third_party"].append(imp)
    
    return filtered


def extract_packages_with_sources(filtered_results: Dict, languages: Set[str]) -> Dict:
    """Extract unique packages with their source file mappings."""
    # Use sets internally for O(1) deduplication, convert to list at end
    packages = {lang: {} for lang in languages}
    
    for lang in languages:
        if lang not in filtered_results:
            continue
        
        for imp in filtered_results[lang].get("third_party", []):
            base = imp.get("base_package", "")
            if not base:
                continue
            
            source_file = imp.get("file", "")
            
            if base not in packages[lang]:
                packages[lang][base] = set()  # Use set for O(1) add
            
            if source_file:
                packages[lang][base].add(source_file)
    
    # Convert to list format with sorted source_files
    result = {}
    for lang in languages:
        result[f"{lang}_imports"] = [
            {"package": pkg, "source_files": sorted(packages[lang][pkg])}
            for pkg in sorted(packages.get(lang, {}).keys())
        ]
    
    # Ensure expected keys exist for response model compatibility
    if "python_imports" not in result:
        result["python_imports"] = []
    if "javascript_imports" not in result:
        result["javascript_imports"] = []
    
    return result


# =============================================================================
# SCAN FUNCTIONS (Used by endpoints)
# =============================================================================

def scan_and_dedupe(checkout, languages: Set[str]) -> Dict:
    """
    Scan for imports and deduplicate results.
    
    Matches orchestrator's write_semgrep_findings workflow:
    1. Run semgrep import detection
    2. Deduplicate imports per category
    
    Returns scan results with summary (no filtering).
    """
    # Ensure checkout is a Path object
    checkout_path = Path(checkout) if isinstance(checkout, str) else checkout
    
    # Step 1: Run semgrep scan
    scan_results = scan_imports(checkout_path, languages)
    
    # Step 2: Deduplicate each category
    for lang in scan_results.keys():
        for category in ["third_party", "builtin", "relative"]:
            if category in scan_results[lang]:
                scan_results[lang][category] = deduplicate_imports(
                    scan_results[lang][category]
                )
    
    # Build summary
    summary = {
        "total_third_party": sum(
            len(scan_results.get(lang, {}).get("third_party", []))
            for lang in languages
        ),
        "total_builtin": sum(
            len(scan_results.get(lang, {}).get("builtin", []))
            for lang in languages
        ),
        "total_relative": sum(
            len(scan_results.get(lang, {}).get("relative", []))
            for lang in languages
        )
    }
    
    return {
        "scan_results": scan_results,
        "summary": summary
    }


# =============================================================================
# COMBINED ANALYSIS FUNCTION (Legacy - for backward compatibility)
# =============================================================================

def analyze_imports(checkout: Path, languages: Set[str], code_tokens: Set[str]) -> Dict:
    """
    Complete import analysis: scan, deduplicate, filter, extract packages.
    
    Matches orchestrator's write_semgrep_findings workflow:
    1. Run semgrep import detection
    2. Deduplicate imports
    3. Filter out local imports using code tokens
    4. Extract unique packages with source file mappings
    
    Returns combined result with all import information.
    """
    # Step 1: Run semgrep scan
    scan_results = scan_imports(checkout, languages)
    
    # Step 2: Deduplicate each category (matches orchestrator's write_semgrep_findings)
    for lang in scan_results.keys():
        for category in ["third_party", "builtin", "relative"]:
            if category in scan_results[lang]:
                scan_results[lang][category] = deduplicate_imports(
                    scan_results[lang][category]
                )
    
    # Step 3: Filter local imports
    filtered_results = filter_local_imports(scan_results, code_tokens)
    
    # Step 4: Extract packages with source mappings (pass languages for dynamic keys)
    import_packages = extract_packages_with_sources(filtered_results, languages)
    
    # Build summary
    summary = {
        "total_third_party": sum(
            len(scan_results.get(lang, {}).get("third_party", []))
            for lang in languages
        ),
        "total_builtin": sum(
            len(scan_results.get(lang, {}).get("builtin", []))
            for lang in languages
        ),
        "total_relative": sum(
            len(scan_results.get(lang, {}).get("relative", []))
            for lang in languages
        ),
        "filtered_external_packages": (
            len(import_packages["python_imports"]) + 
            len(import_packages["javascript_imports"])
        )
    }
    
    return {
        "scan_results": scan_results,
        "filtered_results": filtered_results,
        "import_packages": import_packages,
        "summary": summary
    }
