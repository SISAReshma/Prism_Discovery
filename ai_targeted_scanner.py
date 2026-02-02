"""
AI Targeted Scanner Module
Runs targeted semgrep scans on AI branch traced files.

Flow:
1. For each library: Find matching provider rule → run on library's traced files
2. If no provider rule: Skip (model detection covers it)
3. Model detection: Run ONCE on ALL traced files for that language
4. API calls: Run ONCE on ALL traced files for that language

Rule: Each file scanned by each rule only ONCE (deduplicate)
"""

import json
import subprocess
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logger = logging.getLogger("ai_targeted_scanner")


def setup_logging(level: int = logging.DEBUG) -> None:
    """Configure logging for the scanner module."""
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%H:%M:%S'
        ))
        logger.addHandler(handler)
    logger.setLevel(level)


# Initialize logging on module load
setup_logging()


# =============================================================================
# CONFIGURATION
# =============================================================================

def get_semgrep_dir() -> Path:
    """Get the semgrep rules directory path dynamically."""
    module_dir = Path(__file__).parent.resolve()
    
    candidates = [
        module_dir / "semgrep",
        module_dir.parent / "Prism-AIBOM" / "semgrep",
        module_dir.parent / "semgrep",
        Path.cwd().parent / "Prism-AIBOM" / "semgrep"
    ]
    
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    
    return candidates[0]


# Provider keyword mapping for dynamic rule discovery
PROVIDER_KEYWORDS = {
    "openai": ["openai", "gpt", "chatgpt"],
    "anthropic": ["anthropic", "claude"],
    "google": ["google", "gemini", "palm", "vertex", "generativeai"],
    "huggingface": ["huggingface", "transformers", "hf"],
    "langchain": ["langchain"],
    "pinecone": ["pinecone"],
    "cohere": ["cohere"],
    "replicate": ["replicate"],
    "ai_sdk": ["ai-sdk", "@ai-sdk", "ai", "@ai"]
}


# =============================================================================
# RULE DISCOVERY
# =============================================================================

def find_provider_rule(
    semgrep_dir: Path, 
    library_name: str, 
    language: str
) -> Optional[Path]:
    """
    Dynamically find a provider rule matching the library name.
    
    Args:
        semgrep_dir: Path to semgrep rules directory
        library_name: Name of the library (e.g., "replicate", "langchain")
        language: "python" or "javascript"
    
    Returns:
        Path to matching rule file, or None if not found
    """
    lib_lower = library_name.lower().replace("@", "").replace("-", "_").replace("/", "_")
    lang_folder = semgrep_dir / language
    
    if not lang_folder.exists():
        return None
    
    # Strategy 1: Direct name match
    # e.g., library "replicate" → replicate_provider_rules.yml or replicate_provider_rules_js.yml
    for rule_file in lang_folder.glob("*_provider_rules*.yml"):
        rule_name = rule_file.stem.lower()
        
        # Check if library name is in rule name
        if lib_lower in rule_name:
            return rule_file
        
        # Check provider keywords
        for provider, keywords in PROVIDER_KEYWORDS.items():
            if provider in rule_name:
                for keyword in keywords:
                    if keyword.replace("-", "_").replace("@", "") in lib_lower:
                        return rule_file
    
    # Strategy 2: Check if library matches any provider keyword
    for provider, keywords in PROVIDER_KEYWORDS.items():
        for keyword in keywords:
            keyword_clean = keyword.replace("-", "_").replace("@", "")
            if keyword_clean in lib_lower or lib_lower in keyword_clean:
                # Look for provider rule
                for rule_file in lang_folder.glob(f"*{provider}*_provider_rules*.yml"):
                    return rule_file
    
    return None


def get_model_detection_rule(semgrep_dir: Path, language: str) -> Optional[Path]:
    """Get the model detection rule for a language."""
    lang_folder = semgrep_dir / language
    
    if not lang_folder.exists():
        return None
    
    # Look for *_model_detection.yml
    for rule_file in lang_folder.glob("*_model_detection.yml"):
        return rule_file
    
    # Also check exact names
    candidates = [
        lang_folder / f"{language}_model_detection.yml",
        lang_folder / "model_detection.yml"
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    return None


def get_api_calls_rule(semgrep_dir: Path, language: str) -> Optional[Path]:
    """Get the API calls rule for a language."""
    api_calls_folder = semgrep_dir / "api_calls"
    
    if not api_calls_folder.exists():
        return None
    
    # Look for language-specific API calls rule
    candidates = [
        api_calls_folder / f"{language}_api_calls.yml",
        api_calls_folder / f"{language}.yml"
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    return None


def discover_all_rules(semgrep_dir: Path) -> Dict[str, Dict[str, List[str]]]:
    """
    Discover all available rules organized by category and language.
    Used for reporting what rules are available.
    """
    result = {
        "provider": {"python": [], "javascript": []},
        "model_detection": {"python": [], "javascript": []},
        "api_calls": {"python": [], "javascript": []}
    }
    
    # Provider rules in language folders
    for lang in ["python", "javascript"]:
        lang_folder = semgrep_dir / lang
        if lang_folder.exists():
            for rule_file in lang_folder.glob("*_provider_rules*.yml"):
                result["provider"][lang].append(rule_file.name)
            for rule_file in lang_folder.glob("*_model_detection*.yml"):
                result["model_detection"][lang].append(rule_file.name)
    
    # API calls folder
    api_folder = semgrep_dir / "api_calls"
    if api_folder.exists():
        for rule_file in api_folder.glob("*.yml"):
            if "python" in rule_file.name:
                result["api_calls"]["python"].append(rule_file.name)
            elif "javascript" in rule_file.name:
                result["api_calls"]["javascript"].append(rule_file.name)
    
    return result


# =============================================================================
# SEMGREP EXECUTION
# =============================================================================

def run_semgrep(
    checkout_dir: Path,
    rule_file: Path,
    target_files: List[str],
    timeout: int = 300
) -> Tuple[List[Dict], Optional[str]]:
    """
    Run semgrep with specific rule on specific files.
    
    Args:
        checkout_dir: Base directory for files
        rule_file: Path to semgrep rule file
        target_files: List of relative file paths to scan
        timeout: Timeout in seconds
    
    Returns:
        Tuple of (findings list, error message or None)
    """
    logger.info(f"[SEMGREP] Running rule: {rule_file.name}")
    logger.debug(f"[SEMGREP] Rule path: {rule_file}")
    logger.debug(f"[SEMGREP] Target files count: {len(target_files)}")
    
    if not rule_file.exists():
        logger.error(f"[SEMGREP] Rule file not found: {rule_file.name}")
        return [], f"Rule file not found: {rule_file.name}"
    
    if not target_files:
        logger.warning("[SEMGREP] No target files to scan")
        return [], "No target files to scan"
    
    # Build file path lookup cache
    all_checkout_files = {}
    for found_file in checkout_dir.rglob("*"):
        if found_file.is_file():
            normalized = str(found_file).replace("\\", "/")
            all_checkout_files[found_file.name.lower()] = str(found_file)
            try:
                rel = found_file.relative_to(checkout_dir)
                all_checkout_files[str(rel).replace("\\", "/").lower()] = str(found_file)
            except ValueError:
                pass
    
    # Resolve target files to absolute paths
    existing_files = []
    for f in target_files:
        f_normalized = f.replace("\\", "/")
        if f_normalized.startswith("./"):
            f_normalized = f_normalized[2:]
        
        # Strategy 1: Direct path join
        file_path = checkout_dir / f_normalized
        if file_path.exists():
            existing_files.append(str(file_path))
            continue
        
        # Strategy 2: Exact match in cache
        if f_normalized.lower() in all_checkout_files:
            existing_files.append(all_checkout_files[f_normalized.lower()])
            continue
        
        # Strategy 3: Filename-only match
        file_name = Path(f_normalized).name.lower()
        if file_name in all_checkout_files:
            existing_files.append(all_checkout_files[file_name])
            continue
        
        # Strategy 4: Suffix match
        for cached_path, full_path in all_checkout_files.items():
            if cached_path.endswith(f_normalized.lower()):
                existing_files.append(full_path)
                break
    
    if not existing_files:
        logger.warning("[SEMGREP] None of the target files exist in checkout")
        return [], f"None of the target files exist"
    
    # Deduplicate file list
    existing_files = list(set(existing_files))
    logger.debug(f"[SEMGREP] Resolved {len(existing_files)} existing files")
    
    # Run semgrep
    cmd = [
        "semgrep",
        "--config", str(rule_file),
        "--json",
        "--quiet",
    ] + existing_files
    
    try:
        logger.debug(f"[SEMGREP] Command: semgrep --config {rule_file.name} --json --quiet [files...]")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(checkout_dir)
        )
        
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                logger.info(f"[SEMGREP] Found {len(findings)} findings with rule {rule_file.name}")
                
                # Log detailed finding info for debugging
                for i, f in enumerate(findings[:5]):  # Log first 5 findings
                    extra = f.get("extra", {})
                    metavars = extra.get("metavars", {})
                    logger.debug(f"[SEMGREP] Finding {i+1}: rule={f.get('check_id', 'unknown')}")
                    logger.debug(f"[SEMGREP]   - file: {f.get('path', 'unknown')}")
                    logger.debug(f"[SEMGREP]   - line: {f.get('start', {}).get('line', 0)}")
                    logger.debug(f"[SEMGREP]   - message: {extra.get('message', '')[:80]}")
                    if metavars:
                        logger.debug(f"[SEMGREP]   - metavars: {list(metavars.keys())}")
                        for key, val in metavars.items():
                            content = val.get("abstract_content", "")
                            logger.debug(f"[SEMGREP]     {key} = '{content}'")
                
                return findings, None
            except json.JSONDecodeError as e:
                logger.error(f"[SEMGREP] JSON parse error: {e}")
                return [], f"JSON parse error: {str(e)}"
        
        logger.debug(f"[SEMGREP] No output from semgrep (no matches)")
        if result.stderr:
            logger.debug(f"[SEMGREP] Stderr: {result.stderr[:200]}")
        return [], None
        
    except subprocess.TimeoutExpired:
        logger.error("[SEMGREP] Scan timed out")
        return [], "Semgrep scan timed out"
    except FileNotFoundError:
        logger.error("[SEMGREP] Semgrep command not found")
        return [], "Semgrep command not found"
    except Exception as e:
        logger.error(f"[SEMGREP] Exception: {e}")
        return [], str(e)


# =============================================================================
# FINDING EXTRACTION (Now using model_extractor module)
# =============================================================================

# Import from centralized model extractor
from model_extractor import (
    extract_model_value,
    clean_model_value,
    extract_replicate_model,
    get_model_provider,
)


def extract_api_call_info(finding: Dict) -> Optional[Dict]:
    """Extract API call information from a finding."""
    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    
    api_info = {
        "method": None,
        "url": None
    }
    
    # Extract URL
    for key in ["$URL", "$ENDPOINT", "$API_URL"]:
        if key in metavars:
            api_info["url"] = metavars[key].get("abstract_content", "")
            break
    
    # Extract method from rule or code
    rule_id = finding.get("check_id", "")
    code = extra.get("lines", "")
    
    if "fetch" in rule_id or "fetch(" in code:
        api_info["method"] = "fetch"
    elif "axios" in rule_id or "axios" in code:
        api_info["method"] = "axios"
    elif "requests" in rule_id or "requests." in code:
        api_info["method"] = "requests"
    elif "httpx" in rule_id or "httpx." in code:
        api_info["method"] = "httpx"
    elif "aiohttp" in rule_id or "aiohttp" in code:
        api_info["method"] = "aiohttp"
    elif "got(" in code:
        api_info["method"] = "got"
    elif "XMLHttpRequest" in code:
        api_info["method"] = "XMLHttpRequest"
    else:
        api_info["method"] = "http"
    
    return api_info if api_info["method"] or api_info["url"] else None


def process_finding(
    finding: Dict, 
    checkout_dir: Path,
    rule_category: str
) -> Dict:
    """Process a single finding into standardized format."""
    file_path = finding.get("path", "")
    
    # Make path relative
    try:
        abs_path = Path(file_path)
        if abs_path.is_absolute():
            file_path = str(abs_path.relative_to(checkout_dir))
    except (ValueError, TypeError):
        pass
    
    file_path = file_path.replace("\\", "/")
    extra = finding.get("extra", {})
    
    processed = {
        "file": file_path,
        "line": finding.get("start", {}).get("line", 0),
        "end_line": finding.get("end", {}).get("line", 0),
        "rule_id": finding.get("check_id", ""),
        "rule_category": rule_category,
        "message": extra.get("message", ""),
        "severity": extra.get("severity", "INFO"),
        "code_snippet": extra.get("lines", "").strip()[:300],
        "model_value": extract_model_value(finding)
    }
    
    # Add API call info if applicable
    if rule_category == "api_calls":
        api_info = extract_api_call_info(finding)
        if api_info:
            processed["api_method"] = api_info["method"]
            processed["api_url"] = api_info["url"]
    
    return processed


# =============================================================================
# MAIN SCANNING LOGIC
# =============================================================================

def scan_ai_branches(
    checkout_dir: str,
    branch_trace: Dict,
    enabled_categories: Optional[List[str]] = None
) -> Dict:
    """
    Run targeted semgrep scans on AI branch traced files.
    
    Flow:
    1. For each library: Find matching provider rule → run on traced files
    2. If no provider rule: Skip (model detection covers it)
    3. Model detection: Run ONCE on ALL traced files
    4. API calls: Run ONCE on ALL traced files
    
    Args:
        checkout_dir: Path to checked out code
        branch_trace: Output from /ai-branch-trace endpoint
        enabled_categories: Optional filter (not used in new flow)
    
    Returns:
        Scan results with models_detected and api_calls_found
    """
    logger.info("=" * 60)
    logger.info("[SCAN] Starting AI targeted scan")
    logger.info("=" * 60)
    
    checkout_path = Path(checkout_dir)
    semgrep_dir = get_semgrep_dir()
    
    logger.info(f"[SCAN] Checkout directory: {checkout_path}")
    logger.info(f"[SCAN] Semgrep rules directory: {semgrep_dir}")
    
    branches = branch_trace.get("branches", {})
    logger.info(f"[SCAN] Total branches/libraries to process: {len(branches)}")
    
    if not branches:
        logger.warning("[SCAN] No branches found in branch_trace - nothing to scan")
        return {
            "scan_results": {},
            "models_detected": [],
            "distinct_models": [],
            "api_calls_found": [],
            "model_detection_findings": [],
            "summary": {
                "total_libraries": 0,
                "libraries_scanned": 0,
                "total_findings": 0,
                "unique_models_detected": 0,
                "all_models": [],
                "api_calls_count": 0,
                "model_detection_findings_count": 0,
                "errors": [],
                "timestamp": datetime.now().isoformat(),
                "language": "unknown",
                "rules_used": {"model_detection": None, "api_calls": None}
            }
        }
    
    # Determine primary language from branches
    language_counts = {"python": 0, "javascript": 0}
    for branch in branches.values():
        lang = branch.get("language", "python").lower()
        if "javascript" in lang or "typescript" in lang or lang == "js" or lang == "ts":
            language_counts["javascript"] += 1
        else:
            language_counts["python"] += 1
    
    primary_language = "javascript" if language_counts["javascript"] > language_counts["python"] else "python"
    
    # Collect all traced files across all libraries
    all_traced_files: Set[str] = set()
    scanned_file_rule_pairs: Set[str] = set()  # Track (file, rule) pairs to avoid duplicate scans
    
    scan_results = {}
    all_errors = []
    all_models: List[Dict] = []  # {model, file, line}
    all_api_calls: List[Dict] = []  # {method, url, file, line}
    libraries_scanned = 0
    
    # ==========================================================================
    # PASS 1: Per-library provider rules
    # ==========================================================================
    
    for lib_name, branch in branches.items():
        traced_files = branch.get("traced_files", [])
        language = branch.get("language", "python").lower()
        ai_category = branch.get("category", "UNKNOWN")
        
        logger.debug(f"[PASS1] Processing library: {lib_name}")
        logger.debug(f"[PASS1]   - Category: {ai_category}")
        logger.debug(f"[PASS1]   - Language: {language}")
        logger.debug(f"[PASS1]   - Traced files: {len(traced_files)}")
        
        # Normalize language
        if "javascript" in language or "typescript" in language or language in ["js", "ts"]:
            language = "javascript"
        else:
            language = "python"
        
        # Add to all traced files
        all_traced_files.update(traced_files)
        
        if not traced_files:
            logger.debug(f"[PASS1] Skipping {lib_name} - no traced files")
            scan_results[lib_name] = {
                "library": lib_name,
                "category": ai_category,
                "language": language,
                "scanned": False,
                "reason": "No traced files",
                "findings": [],
                "models_detected": [],
                "rules_used": []
            }
            continue
        
        # Find matching provider rule
        provider_rule = find_provider_rule(semgrep_dir, lib_name, language)
        logger.debug(f"[PASS1] Provider rule for {lib_name}: {provider_rule.name if provider_rule else 'None found'}")
        
        library_findings = []
        rules_used = []
        
        if provider_rule:
            # Filter files not already scanned with this rule
            files_to_scan = []
            for f in traced_files:
                key = f"{f}|{provider_rule.name}"
                if key not in scanned_file_rule_pairs:
                    scanned_file_rule_pairs.add(key)
                    files_to_scan.append(f)
            
            if files_to_scan:
                logger.info(f"[PASS1] Scanning {len(files_to_scan)} files for {lib_name} with {provider_rule.name}")
                findings, error = run_semgrep(checkout_path, provider_rule, files_to_scan)
                
                if error:
                    logger.error(f"[PASS1] Error scanning {lib_name}: {error}")
                    all_errors.append(f"{lib_name}/provider: {error}")
                elif findings:
                    logger.info(f"[PASS1] Found {len(findings)} provider findings for {lib_name}")
                    for f in findings:
                        processed = process_finding(f, checkout_path, "provider")
                        library_findings.append(processed)
                    rules_used.append(provider_rule.name)
        
        libraries_scanned += 1
        
        # Extract models from this library's findings
        lib_models = []
        for f in library_findings:
            if f.get("model_value"):
                lib_models.append(f["model_value"])
                all_models.append({
                    "model": f["model_value"],
                    "file": f["file"],
                    "line": f["line"],
                    "library": lib_name
                })
        
        if lib_models:
            logger.info(f"[PASS1] Models found for {lib_name}: {lib_models}")
        
        # Build model_values array with full details (Prism-AIBOM format)
        model_values = []
        for f in library_findings:
            if f.get("model_value"):
                model_values.append({
                    "model_name": f["model_value"],
                    "file": f["file"],
                    "line": f["line"],
                    "rule_id": f["rule_id"],
                    "code_snippet": f.get("code_snippet", "")[:100]
                })
        
        scan_results[lib_name] = {
            "library": lib_name,
            "category": ai_category,
            "language": language,
            "scanned": True,
            "reason": None,
            "traced_files_count": len(traced_files),
            "findings_count": len(library_findings),
            "findings": library_findings,
            "models_detected": list(set(lib_models)),
            "model_values": model_values,  # Prism-AIBOM format
            "rules_used": rules_used,
            "provider_rule_found": provider_rule is not None
        }
    
    # ==========================================================================
    # PASS 2: Model Detection (run ONCE on all traced files)
    # ==========================================================================
    
    logger.info("-" * 60)
    logger.info("[PASS2] Starting Model Detection pass")
    logger.info(f"[PASS2] Total traced files to scan: {len(all_traced_files)}")
    
    model_detection_findings = []
    model_detection_rule = get_model_detection_rule(semgrep_dir, primary_language)
    
    logger.info(f"[PASS2] Model detection rule: {model_detection_rule.name if model_detection_rule else 'NOT FOUND'}")
    if model_detection_rule:
        logger.debug(f"[PASS2] Rule path: {model_detection_rule}")
    
    if model_detection_rule and all_traced_files:
        # Filter files not already scanned with this rule
        files_to_scan = []
        for f in all_traced_files:
            key = f"{f}|{model_detection_rule.name}"
            if key not in scanned_file_rule_pairs:
                scanned_file_rule_pairs.add(key)
                files_to_scan.append(f)
        
        logger.info(f"[PASS2] Files to scan (after dedup): {len(files_to_scan)}")
        
        if files_to_scan:
            logger.debug(f"[PASS2] Sample files: {files_to_scan[:5]}")
            findings, error = run_semgrep(checkout_path, model_detection_rule, files_to_scan)
            
            if error:
                logger.error(f"[PASS2] Error in model detection: {error}")
                all_errors.append(f"model_detection: {error}")
            elif findings:
                logger.info(f"[PASS2] Model detection found {len(findings)} raw findings")
                for f in findings:
                    processed = process_finding(f, checkout_path, "model_detection")
                    model_detection_findings.append(processed)
                    
                    if processed.get("model_value"):
                        logger.info(f"[PASS2] Model extracted: '{processed['model_value']}' in {processed['file']}:{processed['line']}")
                        all_models.append({
                            "model": processed["model_value"],
                            "file": processed["file"],
                            "line": processed["line"],
                            "library": "detected"
                        })
            else:
                logger.warning("[PASS2] No findings from model detection rule")
    else:
        if not model_detection_rule:
            logger.error(f"[PASS2] No model detection rule found for language: {primary_language}")
        if not all_traced_files:
            logger.warning("[PASS2] No traced files to scan")
    
    # ==========================================================================
    # PASS 3: API Calls (run ONCE on all traced files)
    # ==========================================================================
    
    logger.info("-" * 60)
    logger.info("[PASS3] Starting API Calls pass")
    
    api_calls_rule = get_api_calls_rule(semgrep_dir, primary_language)
    logger.info(f"[PASS3] API calls rule: {api_calls_rule.name if api_calls_rule else 'NOT FOUND'}")
    
    if api_calls_rule and all_traced_files:
        # Filter files not already scanned with this rule
        files_to_scan = []
        for f in all_traced_files:
            key = f"{f}|{api_calls_rule.name}"
            if key not in scanned_file_rule_pairs:
                scanned_file_rule_pairs.add(key)
                files_to_scan.append(f)
        
        logger.info(f"[PASS3] Files to scan: {len(files_to_scan)}")
        
        if files_to_scan:
            findings, error = run_semgrep(checkout_path, api_calls_rule, files_to_scan)
            
            if error:
                logger.error(f"[PASS3] Error: {error}")
                all_errors.append(f"api_calls: {error}")
            elif findings:
                logger.info(f"[PASS3] API calls found: {len(findings)}")
                for f in findings:
                    processed = process_finding(f, checkout_path, "api_calls")
                    all_api_calls.append({
                        "method": processed.get("api_method", "http"),
                        "url": processed.get("api_url"),
                        "file": processed["file"],
                        "line": processed["line"],
                        "code_snippet": processed.get("code_snippet", "")[:100]
                    })
    
    # ==========================================================================
    # Build Final Response
    # ==========================================================================
    
    logger.info("-" * 60)
    logger.info("[SUMMARY] Building final response")
    
    # Deduplicate models by (model, file, line)
    seen_models = set()
    unique_models = []
    for m in all_models:
        key = f"{m['model']}|{m['file']}|{m['line']}"
        if key not in seen_models:
            seen_models.add(key)
            unique_models.append(m)
    
    # Get distinct model names
    distinct_model_names = sorted(set(m["model"] for m in unique_models))
    
    logger.info(f"[SUMMARY] Total unique models: {len(unique_models)}")
    logger.info(f"[SUMMARY] Distinct model names: {distinct_model_names}")
    
    # Deduplicate model_detection_findings by (file, line, model_value)
    seen_findings = set()
    unique_model_findings = []
    for f in model_detection_findings:
        key = f"{f['file']}|{f['line']}|{f.get('model_value', '')}"
        if key not in seen_findings:
            seen_findings.add(key)
            unique_model_findings.append(f)
    model_detection_findings = unique_model_findings
    
    # Deduplicate API calls
    seen_api = set()
    unique_api_calls = []
    for a in all_api_calls:
        key = f"{a['method']}|{a['file']}|{a['line']}"
        if key not in seen_api:
            seen_api.add(key)
            unique_api_calls.append(a)
    
    total_findings = sum(
        r.get("findings_count", 0) for r in scan_results.values()
    ) + len(model_detection_findings) + len(unique_api_calls)
    
    return {
        "scan_results": scan_results,
        "models_detected": unique_models,
        "distinct_models": distinct_model_names,
        "api_calls_found": unique_api_calls,
        "model_detection_findings": model_detection_findings,
        "summary": {
            "total_libraries": len(branches),
            "libraries_scanned": libraries_scanned,
            "total_findings": total_findings,
            "unique_models_detected": len(distinct_model_names),
            "all_models": distinct_model_names,
            "api_calls_count": len(unique_api_calls),
            "model_detection_findings_count": len(model_detection_findings),
            "errors": all_errors,
            "timestamp": datetime.now().isoformat(),
            "language": primary_language,
            "rules_used": {
                "model_detection": model_detection_rule.name if model_detection_rule else None,
                "api_calls": api_calls_rule.name if api_calls_rule else None
            }
        }
    }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_available_categories(semgrep_dir: Optional[Path] = None) -> Dict:
    """Get information about available rules."""
    if semgrep_dir is None:
        semgrep_dir = get_semgrep_dir()
    
    return {
        "semgrep_dir": str(semgrep_dir),
        "rules": discover_all_rules(semgrep_dir)
    }
