"""
AI Targeted Scanner Module
Runs targeted semgrep scans on AI branch traced files.

Flow:
1. For each library: Find matching provider rule → run on library's traced files
2. If no provider rule: Skip (model detection covers it)
3. Model detection: Run ONCE on ALL traced files for that language
Rule: Each file scanned by each rule only ONCE (deduplicate)
"""

import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from functools import lru_cache

from config import SEMGREP_DIR, NORMALIZED_PROVIDER_KEYWORDS, SUPPORTED_LANGUAGES, SKIP_DIRECTORIES, JS_LANGUAGE_VARIANTS
from model_extractor import extract_model_value

logger = logging.getLogger(__name__)

# =============================================================================
# RULE DISCOVERY (cached for performance)
# =============================================================================

@lru_cache(maxsize=32)
def _get_provider_rules_for_lang(lang_folder: Path) -> Tuple[Tuple[str, Path], ...]:
    """Cache provider rules for a language folder. Returns tuple for hashability."""
    if not lang_folder.exists():
        return ()
    return tuple(
        (rule_file.stem.lower(), rule_file)
        for rule_file in lang_folder.glob("*_provider_rules*.yml")
    )


def find_provider_rule(library_name: str, language: str) -> Optional[Path]:
    """Find provider rule matching the library name using cached rule list."""
    lib_lower = library_name.lower().replace("@", "").replace("-", "_").replace("/", "_")
    cached_rules = _get_provider_rules_for_lang(SEMGREP_DIR / language)
    
    if not cached_rules:
        return None
    
    # Strategy 1: Direct name match in cached rules
    for rule_name, rule_file in cached_rules:
        if lib_lower in rule_name:
            return rule_file
    
    # Strategy 2: Provider keyword match using pre-normalized lookup
    for keyword_norm, provider in NORMALIZED_PROVIDER_KEYWORDS.items():
        if keyword_norm in lib_lower:
            for rule_name, rule_file in cached_rules:
                if provider in rule_name:
                    return rule_file
            break  # Only check first matching provider
    
    return None


@lru_cache(maxsize=8)
def get_model_detection_rule(language: str) -> Optional[Path]:
    """Get the model detection rule for a language (cached)."""
    lang_folder = SEMGREP_DIR / language
    
    if not lang_folder.exists():
        return None
    
    # Look for *_model_detection.yml first (most specific)
    for rule_file in lang_folder.glob("*_model_detection.yml"):
        return rule_file
    
    # Fallback to exact names
    for name in (f"{language}_model_detection.yml", "model_detection.yml"):
        candidate = lang_folder / name
        if candidate.exists():
            return candidate
    
    return None


def discover_all_rules() -> Dict[str, Dict[str, List[str]]]:
    """Discover all available rules organized by category and language."""
    languages = tuple(SUPPORTED_LANGUAGES.keys())
    result = {
        "provider": {lang: [] for lang in languages},
        "model_detection": {lang: [] for lang in languages}
    }
    
    for lang in languages:
        lang_folder = SEMGREP_DIR / lang
        if lang_folder.exists():
            result["provider"][lang] = [f.name for f in lang_folder.glob("*_provider_rules*.yml")]
            result["model_detection"][lang] = [f.name for f in lang_folder.glob("*_model_detection*.yml")]
    
    return result


# =============================================================================
# FILE RESOLUTION
# =============================================================================

def _build_file_cache(checkout_dir: Path) -> Dict[str, str]:
    """
    Build a lookup cache for files in checkout directory. Call once per scan.
    
    Optimized: Pre-check parts intersection with SKIP_DIRECTORIES using set ops.
    """
    cache: Dict[str, str] = {}
    checkout_str = str(checkout_dir)
    
    for found_file in checkout_dir.rglob("*"):
        if not found_file.is_file():
            continue
        
        # Fast skip check: convert parts to set for O(1) intersection
        parts = found_file.parts
        if SKIP_DIRECTORIES.intersection(parts) or any(p.startswith(".") for p in parts):
            continue
        
        file_str = str(found_file)
        cache[found_file.name.lower()] = file_str
        
        # Compute relative path for secondary lookup
        rel_path = file_str[len(checkout_str) + 1:].replace("\\", "/").lower()
        cache[rel_path] = file_str
    
    return cache


def _resolve_files(
    target_files: List[str], 
    checkout_dir: Path, 
    file_cache: Dict[str, str]
) -> List[str]:
    """Resolve target file paths to absolute paths using pre-built cache."""
    existing: List[str] = []
    seen: Set[str] = set()
    
    for f in target_files:
        f_normalized = f.replace("\\", "/").lstrip("./")
        
        # Strategy 1: Direct path check (common case)
        file_path = checkout_dir / f_normalized
        if file_path.exists():
            path_str = str(file_path)
            if path_str not in seen:
                seen.add(path_str)
                existing.append(path_str)
            continue
        
        # Strategy 2: Exact cache match (O(1))
        key_lower = f_normalized.lower()
        if path_str := file_cache.get(key_lower):
            if path_str not in seen:
                seen.add(path_str)
                existing.append(path_str)
            continue
        
        # Strategy 3: Filename-only match (O(1))
        file_name_lower = Path(f_normalized).name.lower()
        if path_str := file_cache.get(file_name_lower):
            if path_str not in seen:
                seen.add(path_str)
                existing.append(path_str)
            continue
        
        # Strategy 4: Suffix match (O(C) - last resort)
        for cached_path, full_path in file_cache.items():
            if cached_path.endswith(key_lower) and full_path not in seen:
                seen.add(full_path)
                existing.append(full_path)
                break
    
    return existing


# =============================================================================
# SEMGREP EXECUTION
# =============================================================================

def run_semgrep(
    checkout_dir: Path,
    rule_file: Path,
    target_files: List[str],
    timeout: int = 300,
    file_cache: Optional[Dict[str, str]] = None
) -> Tuple[List[Dict], Optional[str]]:
    """
    Run semgrep with specific rule on specific files.
    
    Returns:
        Tuple of (findings list, error message or None)
    """
    if not rule_file.exists():
        logger.error(f"[SEMGREP] Rule file not found: {rule_file.name}")
        return [], f"Rule file not found: {rule_file.name}"
    
    if not target_files:
        return [], "No target files to scan"
    
    cache = file_cache or _build_file_cache(checkout_dir)
    existing_files = _resolve_files(target_files, checkout_dir, cache)
    
    if not existing_files:
        logger.warning("[SEMGREP] None of the target files exist in checkout")
        return [], "None of the target files exist"
    
    logger.debug(f"[SEMGREP] Running {rule_file.name} on {len(existing_files)} files")
    
    cmd = ["semgrep", "--config", str(rule_file), "--json", "--quiet"] + existing_files
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(checkout_dir)
        )
        
        if result.stdout.strip():
            try:
                findings = json.loads(result.stdout).get("results", [])
                logger.info(f"[SEMGREP] Found {len(findings)} findings with {rule_file.name}")
                return findings, None
            except json.JSONDecodeError as e:
                logger.error(f"[SEMGREP] JSON parse error: {e}")
                return [], f"JSON parse error: {e}"
        
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
# FINDING EXTRACTION
# =============================================================================

def _process_finding(finding: Dict, checkout_dir: Path, rule_category: str) -> Dict:
    """Process a single finding into standardized format."""
    file_path = finding.get("path", "")
    
    # Make path relative
    try:
        abs_path = Path(file_path)
        if abs_path.is_absolute():
            file_path = str(abs_path.relative_to(checkout_dir))
    except (ValueError, TypeError):
        pass
    
    extra = finding.get("extra", {})
    
    return {
        "file": file_path.replace("\\", "/"),
        "line": finding.get("start", {}).get("line", 0),
        "end_line": finding.get("end", {}).get("line", 0),
        "rule_id": finding.get("check_id", ""),
        "rule_category": rule_category,
        "message": extra.get("message", ""),
        "severity": extra.get("severity", "INFO"),
        "code_snippet": extra.get("lines", "").strip()[:300],
        "model_value": extract_model_value(finding)
    }


def _normalize_language(lang_raw: str) -> str:
    """Normalize language to 'javascript' or 'python'."""
    return "javascript" if lang_raw in JS_LANGUAGE_VARIANTS else "python"


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
    """
    logger.info("[SCAN] Starting AI targeted scan")
    
    checkout_path = Path(checkout_dir)
    branches = branch_trace.get("branches", {})
    
    if not branches:
        logger.warning("[SCAN] No branches found - nothing to scan")
        return _empty_scan_result()
    
    # Build file cache ONCE for all semgrep runs
    file_cache = _build_file_cache(checkout_path)
    
    # Determine primary language (majority vote)
    js_count = sum(1 for b in branches.values() if b.get("language", "python").lower() in JS_LANGUAGE_VARIANTS)
    primary_language = "javascript" if js_count > len(branches) // 2 else "python"
    
    # State tracking
    all_traced_files: Set[str] = set()
    scanned_pairs: Set[Tuple[str, str]] = set()  # (file, rule_name) tuples
    
    scan_results: Dict[str, Dict] = {}
    all_errors: List[str] = []
    all_models: List[Dict] = []
    
    # ==========================================================================
    # PASS 1: Per-library provider rules
    # ==========================================================================
    
    for lib_name, branch in branches.items():
        traced_files = branch.get("traced_files", [])
        language = _normalize_language(branch.get("language", "python").lower())
        ai_category = branch.get("category", "UNKNOWN")
        
        all_traced_files.update(traced_files)
        
        if not traced_files:
            scan_results[lib_name] = _lib_result(lib_name, ai_category, language, scanned=False, reason="No traced files")
            continue
        
        provider_rule = find_provider_rule(lib_name, language)
        library_findings: List[Dict] = []
        rules_used: List[str] = []
        
        if provider_rule:
            rule_name = provider_rule.name
            # Filter files not already scanned with this rule (use tuple keys for efficiency)
            files_to_scan = [f for f in traced_files if (f, rule_name) not in scanned_pairs]
            scanned_pairs.update((f, rule_name) for f in files_to_scan)
            
            if files_to_scan:
                logger.info(f"[PASS1] Scanning {len(files_to_scan)} files for {lib_name}")
                findings, error = run_semgrep(checkout_path, provider_rule, files_to_scan, file_cache=file_cache)
                
                if error:
                    all_errors.append(f"{lib_name}/provider: {error}")
                elif findings:
                    logger.info(f"[PASS1] Found {len(findings)} provider findings for {lib_name}")
                    library_findings = [_process_finding(f, checkout_path, "provider") for f in findings]
                    rules_used.append(rule_name)
        
        # Extract models from findings
        lib_models: List[str] = []
        model_values: List[Dict] = []
        
        for f in library_findings:
            if model_val := f.get("model_value"):
                lib_models.append(model_val)
                all_models.append({"model": model_val, "file": f["file"], "line": f["line"], "library": lib_name})
                model_values.append({
                    "model_name": model_val,
                    "file": f["file"],
                    "line": f["line"],
                    "rule_id": f["rule_id"],
                    "code_snippet": f.get("code_snippet", "")[:100]
                })
        
        if lib_models:
            logger.info(f"[PASS1] Models found for {lib_name}: {lib_models}")
        
        scan_results[lib_name] = _lib_result(
            lib_name, ai_category, language,
            scanned=True,
            traced_files_count=len(traced_files),
            findings=library_findings,
            models_detected=list(set(lib_models)),
            model_values=model_values,
            rules_used=rules_used,
            provider_rule_found=provider_rule is not None
        )
    
    # ==========================================================================
    # PASS 2: Model Detection (run ONCE on all traced files)
    # ==========================================================================
    
    logger.info("[PASS2] Starting Model Detection pass")
    
    model_detection_findings: List[Dict] = []
    model_detection_rule = get_model_detection_rule(primary_language)
    
    if model_detection_rule and all_traced_files:
        rule_name = model_detection_rule.name
        files_to_scan = [f for f in all_traced_files if (f, rule_name) not in scanned_pairs]
        scanned_pairs.update((f, rule_name) for f in files_to_scan)
        
        if files_to_scan:
            findings, error = run_semgrep(checkout_path, model_detection_rule, files_to_scan, file_cache=file_cache)
            
            if error:
                all_errors.append(f"model_detection: {error}")
            elif findings:
                for f in findings:
                    processed = _process_finding(f, checkout_path, "model_detection")
                    model_detection_findings.append(processed)
                    
                    if model_val := processed.get("model_value"):
                        all_models.append({
                            "model": model_val,
                            "file": processed["file"],
                            "line": processed["line"],
                            "library": "detected"
                        })
    
    # ==========================================================================
    # Build Final Response
    # ==========================================================================
    
    return _build_scan_response(
        scan_results, all_models, model_detection_findings,
        all_errors, branches, primary_language, model_detection_rule
    )


def _lib_result(
    lib_name: str,
    category: str,
    language: str,
    scanned: bool,
    reason: Optional[str] = None,
    traced_files_count: int = 0,
    findings: Optional[List[Dict]] = None,
    models_detected: Optional[List[str]] = None,
    model_values: Optional[List[Dict]] = None,
    rules_used: Optional[List[str]] = None,
    provider_rule_found: bool = False
) -> Dict:
    """Create standardized library result dict."""
    return {
        "library": lib_name,
        "category": category,
        "language": language,
        "scanned": scanned,
        "reason": reason,
        "traced_files_count": traced_files_count,
        "findings_count": len(findings) if findings else 0,
        "findings": findings or [],
        "models_detected": models_detected or [],
        "model_values": model_values or [],
        "rules_used": rules_used or [],
        "provider_rule_found": provider_rule_found
    }


def _empty_scan_result() -> Dict:
    """Return empty scan result structure."""
    return {
        "scan_results": {},
        "models_detected": [],
        "distinct_models": [],
        "model_detection_findings": [],
        "summary": {
            "total_libraries": 0,
            "libraries_scanned": 0,
            "total_findings": 0,
            "unique_models_detected": 0,
            "all_models": [],
            "model_detection_findings_count": 0,
            "errors": [],
            "timestamp": datetime.now().isoformat(),
            "language": "unknown",
            "rules_used": {"model_detection": None}
        }
    }


def _build_scan_response(
    scan_results: Dict,
    all_models: List[Dict],
    model_detection_findings: List[Dict],
    all_errors: List[str],
    branches: Dict,
    primary_language: str,
    model_detection_rule: Optional[Path]
) -> Dict:
    """Build final response with deduplication."""
    # Deduplicate models by (model, file, line)
    seen_models: Set[Tuple[str, str, int]] = set()
    unique_models: List[Dict] = []
    
    for m in all_models:
        key = (m["model"], m["file"], m["line"])
        if key not in seen_models:
            seen_models.add(key)
            unique_models.append(m)
    
    distinct_model_names = sorted({m["model"] for m in unique_models})
    
    # Deduplicate model_detection_findings
    seen_findings: Set[Tuple[str, int, str]] = set()
    unique_findings: List[Dict] = []
    
    for f in model_detection_findings:
        key = (f["file"], f["line"], f.get("model_value", ""))
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    
    libraries_scanned = sum(1 for r in scan_results.values() if r.get("scanned"))
    total_findings = sum(r.get("findings_count", 0) for r in scan_results.values()) + len(unique_findings)
    
    return {
        "scan_results": scan_results,
        "models_detected": unique_models,
        "distinct_models": distinct_model_names,
        "model_detection_findings": unique_findings,
        "summary": {
            "total_libraries": len(branches),
            "libraries_scanned": libraries_scanned,
            "total_findings": total_findings,
            "unique_models_detected": len(distinct_model_names),
            "all_models": distinct_model_names,
            "model_detection_findings_count": len(unique_findings),
            "errors": all_errors,
            "timestamp": datetime.now().isoformat(),
            "language": primary_language,
            "rules_used": {
                "model_detection": model_detection_rule.name if model_detection_rule else None
            }
        }
    }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_available_categories() -> Dict:
    """Get information about available rules."""
    return {
        "semgrep_dir": str(SEMGREP_DIR),
        "rules": discover_all_rules()
    }
