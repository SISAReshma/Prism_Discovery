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

from aibom.config import (
    SEMGREP_DIR, NORMALIZED_PROVIDER_KEYWORDS, SUPPORTED_LANGUAGES,
    SKIP_DIRECTORIES, JS_LANGUAGE_VARIANTS, LANGUAGE_EXTENSIONS,
    NORMALIZED_API_KEYWORDS, API_METAVAR_PRIORITY, API_FALSE_POSITIVES,
    CATEGORY_TO_MODEL_TAG, MODEL_TAG_PATTERNS, MODEL_PROVIDER_PREFIXES_PATTERNS,
    PROVIDER_KEYWORDS, HTTP_METHOD_PATTERNS, REQUEST_BODY_PATTERNS,
    REQUEST_HEADER_PATTERNS, SDK_METHOD_HTTP_MAP, SDK_PARAM_PATTERNS,
)
import re
from aibom.src.model_extractor import extract_model_value, scan_file_for_models
from core.log_sanitizer import sanitize_sensitive

logger = logging.getLogger(__name__)


# =============================================================================
# MODEL TAGGING HELPERS
# =============================================================================

def _category_to_tag(category: str) -> str:
    """Map a library's AI category to a model tag (LLM / DL / ML / AI)."""
    return CATEGORY_TO_MODEL_TAG.get(category.upper(), "AI")


def _infer_tag_from_model_name(model_name: str) -> str:
    """Guess tag from model name string when no parent library is known."""
    name_lower = model_name.lower()
    for prefixes, tag in MODEL_TAG_PATTERNS:
        if any(p in name_lower for p in prefixes):
            return tag
    return "AI"  # safe fallback


# Tag specificity: more specific wins when model name gives a stronger hint
_TAG_PRIORITY = {"LLM": 4, "DL": 3, "ML": 2, "AI": 1}


def _best_tag(inherited_tag: str, model_name: str) -> str:
    """Pick the more specific of inherited tag vs model-name-inferred tag.

    Example: tiktoken is DATA_PROCESSING -> ML, but 'gpt2' clearly is LLM.
    LLM priority (4) > ML priority (2) -> returns 'LLM'.
    """
    name_tag = _infer_tag_from_model_name(model_name)
    if _TAG_PRIORITY.get(name_tag, 0) > _TAG_PRIORITY.get(inherited_tag, 0):
        return name_tag
    return inherited_tag


def _build_file_to_branch_lookup(branches: Dict) -> Dict[str, List[Tuple[str, str]]]:
    """Build a lookup: normalized file path → list of (library_name, category).

    Stores ALL libraries that trace to a file, not just the first.
    Monolithic files (e.g. app.py importing openai + anthropic + groq)
    will have multiple entries so PASS 2 can disambiguate by model name.
    """
    lookup: Dict[str, List[Tuple[str, str]]] = {}
    for lib_name, branch in branches.items():
        category = branch.get("category", "UNKNOWN")
        for f in branch.get("traced_files", []):
            key = f.replace("\\", "/").lower()
            if key not in lookup:
                lookup[key] = []
            lookup[key].append((lib_name, category))
    return lookup


def _model_to_provider(model_name: str) -> Optional[str]:
    """Map a model name to its provider for monolithic file disambiguation.

    Uses MODEL_PROVIDER_PREFIXES_PATTERNS first (most specific), then
    PROVIDER_KEYWORDS for stem matching, then org/model → huggingface.
    """
    model_lower = model_name.lower().rstrip("-")

    # Strategy 1: Prefix patterns (gpt- → openai, claude- → anthropic, etc.)
    for provider, prefixes in MODEL_PROVIDER_PREFIXES_PATTERNS.items():
        for p in prefixes:
            p_clean = p.rstrip("-")
            if model_lower.startswith(p_clean):
                return provider

    # Strategy 2: PROVIDER_KEYWORDS stem match (handles "o1", "o3", etc.)
    model_stem = model_lower.split("-")[0]  # "gpt-5" → "gpt", "o1" → "o1"
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if model_lower in keywords or model_stem in keywords:
            return provider

    # Strategy 3: HuggingFace org/model format (microsoft/Phi-3.5-mini-instruct)
    if "/" in model_name and not model_name.startswith("http"):
        return "huggingface"

    return None


def _resolve_tag_for_pass2(
    file_path: str,
    model_name: str,
    file_branch_lookup: Dict[str, List[Tuple[str, str]]]
) -> Tuple[str, str]:
    """Determine library and tag for a PASS 2 model finding.

    Handles monolithic files where multiple AI libraries share one file.
    Uses model name → provider mapping to pick the correct library.

    Strategy:
    1. Get all libraries that claim this file
    2. If one library → use it
    3. If multiple → use model name to determine provider, match to right library
    4. Fallback: infer tag from model name patterns

    Returns:
        (library_name, tag)
    """
    file_key = file_path.replace("\\", "/").lower()
    claimants = file_branch_lookup.get(file_key)

    if not claimants:
        return "detected", _infer_tag_from_model_name(model_name)

    if len(claimants) == 1:
        lib_name, category = claimants[0]
        return lib_name, _best_tag(_category_to_tag(category), model_name)

    # ── Monolithic file: multiple libraries share this file ───────────
    model_provider = _model_to_provider(model_name)

    if model_provider:
        # Try to find a library among claimants that matches the model's provider
        for lib_name, category in claimants:
            lib_norm = lib_name.lower().replace("-", "_").replace("@", "")
            lib_provider = NORMALIZED_PROVIDER_KEYWORDS.get(lib_norm)
            if lib_provider == model_provider:
                return lib_name, _best_tag(_category_to_tag(category), model_name)

        # Provider identified but no matching library in claimants
        # (e.g. "groq" lib serving OpenAI models) — pick best claimant
        # by checking which claimant's provider group is closest
        # Fallback: report the provider name as the library
        best_lib = model_provider
        best_cat = "AI_PROVIDER"
        for lib_name, category in claimants:
            if category == "AI_PROVIDER":
                best_lib = lib_name
                best_cat = category
                break
        return best_lib, _best_tag(_category_to_tag(best_cat), model_name)

    # Cannot determine provider from model name — use first AI_PROVIDER claimant
    for lib_name, category in claimants:
        if category == "AI_PROVIDER":
            return lib_name, _best_tag(_category_to_tag(category), model_name)

    # Last resort: first claimant
    lib_name, category = claimants[0]
    return lib_name, _best_tag(_category_to_tag(category), model_name)


def _get_all_language_files(checkout_path: Path, language: str) -> List[str]:
    """
    Return absolute paths for every source file of `language` found under
    `checkout_path`, skipping hidden dirs and well-known skip directories.
    Used by model-detection PASS 2 so we catch model strings in files that
    don't directly import an AI library (e.g. GptRequest.cs, ParameterManager.cs).
    """
    extensions = LANGUAGE_EXTENSIONS.get(language, frozenset())
    if not extensions:
        return []
    results: List[str] = []
    for p in checkout_path.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in extensions:
            continue
        parts = p.parts
        if SKIP_DIRECTORIES.intersection(parts):
            continue
        if any(part.startswith(".") for part in parts):
            continue
        results.append(str(p))
    return results


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
    
    # Strategy 1: Exact provider prefix match in cached rules
    for rule_name, rule_file in cached_rules:
        provider_prefix = rule_name.split("_provider_rules")[0]
        if lib_lower == provider_prefix:
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
        "model_detection": {lang: [] for lang in languages},
        "api_calls": {lang: [] for lang in languages},
        "ai_api_calls": {lang: [] for lang in languages}
    }
    
    for lang in languages:
        lang_folder = SEMGREP_DIR / lang
        if lang_folder.exists():
            result["provider"][lang] = [f.name for f in lang_folder.glob("*_provider_rules*.yml")]
            result["model_detection"][lang] = [f.name for f in lang_folder.glob("*_model_detection*.yml")]
            result["api_calls"][lang] = [f.name for f in lang_folder.glob("*_api_calls.yml")]
            result["ai_api_calls"][lang] = [f.name for f in lang_folder.glob("*_ai_api_calls.yml")]
    
    return result


# =============================================================================
# API RULE DISCOVERY (cached for performance)
# =============================================================================

@lru_cache(maxsize=8)
def get_api_calls_rule(language: str) -> Optional[Path]:
    """Get the api_calls rule file for a language (cached).
    
    Searches in SEMGREP_DIR/api_calls/ first (where python_api_calls.yml etc. live),
    then falls back to SEMGREP_DIR/<language>/ for backward compatibility.
    """
    # Strategy 1: Look in the dedicated api_calls/ directory
    api_calls_dir = SEMGREP_DIR / "api_calls"
    if api_calls_dir.exists():
        # Direct name match: python_api_calls.yml, javascript_api_calls.yml, etc.
        candidate = api_calls_dir / f"{language}_api_calls.yml"
        if candidate.exists():
            return candidate
        # Glob fallback within api_calls/
        for rule_file in api_calls_dir.glob(f"{language}*_api_calls.yml"):
            return rule_file
    
    # Strategy 2: Look in the language-specific folder (backward compat)
    lang_folder = SEMGREP_DIR / language
    if lang_folder and lang_folder.exists():
        for rule_file in lang_folder.glob("*_api_calls.yml"):
            return rule_file
        candidate = lang_folder / f"{language}_api_calls.yml"
        if candidate.exists():
            return candidate
    
    return None


@lru_cache(maxsize=8)
def get_ai_api_calls_rule(language: str) -> Optional[Path]:
    """Get the ai_api_calls rule file for a language (cached).
    
    These rules capture AI-specific API calls: chat completions,
    embeddings, AI provider endpoint URLs, streaming, multi-provider SDKs.
    """
    lang_folder = SEMGREP_DIR / language
    
    if not lang_folder.exists():
        return None
    
    # Look for *_ai_api_calls.yml
    for rule_file in lang_folder.glob("*_ai_api_calls.yml"):
        return rule_file
    
    # Fallback to exact name
    candidate = lang_folder / f"{language}_ai_api_calls.yml"
    if candidate.exists():
        return candidate
    
    return None


def find_api_category_for_library(library_name: str) -> Optional[str]:
    """Find the API category that matches a library using normalized keywords.
    
    Returns the category string (http_client, api_framework, etc.) or None.
    """
    lib_lower = library_name.lower().replace("@", "").replace("-", "_").replace("/", "_").replace(".", "_")
    
    # Strategy 1: Direct lookup in normalized keywords
    if category := NORMALIZED_API_KEYWORDS.get(lib_lower):
        return category.upper()
    
    # Strategy 2: Partial keyword match
    for keyword_norm, category in NORMALIZED_API_KEYWORDS.items():
        if keyword_norm in lib_lower or lib_lower in keyword_norm:
            return category.upper()
    
    return None


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
        
        stdout_text = result.stdout or ""
        stderr_text = result.stderr or ""
        
        # Log stderr (semgrep warnings/errors) even on success
        if stderr_text.strip():
            logger.warning(f"[SEMGREP] stderr from {rule_file.name}: {stderr_text[:500]}")
        
        if stdout_text.strip():
            try:
                parsed = json.loads(stdout_text)
                findings = parsed.get("results", [])
                # Log any rule-level errors reported inside the JSON
                json_errors = parsed.get("errors", [])
                if json_errors:
                    logger.warning(f"[SEMGREP] Rule errors in {rule_file.name}: {json_errors[:3]}")
                logger.info(f"[SEMGREP] Found {len(findings)} findings with {rule_file.name}")
                return findings, None
            except json.JSONDecodeError as e:
                logger.error(f"[SEMGREP] JSON parse error: {e}")
                return [], f"JSON parse error: {e}"
        
        # Semgrep exited with non-zero and no stdout — surface the stderr as error
        if result.returncode != 0 and stderr_text.strip():
            short_err = stderr_text.strip()[:300]
            logger.error(f"[SEMGREP] Non-zero exit {result.returncode}: {short_err}")
            return [], f"semgrep exit {result.returncode}: {short_err}"
        
        return [], None
        
    except subprocess.TimeoutExpired:
        logger.error("[SEMGREP] Scan timed out")
        return [], "Semgrep scan timed out"
    except FileNotFoundError:
        logger.error("[SEMGREP] Semgrep command not found")
        return [], "Semgrep command not found"
    except Exception as e:
        sanitized_error = sanitize_sensitive(str(e))
        logger.error("[SEMGREP] Exception during scan", extra={"error": sanitized_error})
        return [], sanitized_error


# =============================================================================
# FINDING EXTRACTION
# =============================================================================

def _extract_sdk_details(code_snippet: str, rule_id: str = "") -> Dict:
    """Extract SDK-level enrichment from a code snippet.
    
    Returns dict with:
      api_method:  The SDK method call (e.g. 'AutoModel.from_pretrained')
      http_method: Implied HTTP verb (e.g. 'GET' for downloads, 'POST' for creates)
      request_body: Key parameters as dict (model, repo_id, filename, etc.)
    """
    result: Dict = {"api_method": None, "http_method": None, "request_body": None}
    if not code_snippet:
        return result
    
    # --- 1. Extract the method name from the code snippet ---
    # Match patterns like: AutoModelForCausalLM.from_pretrained(...
    #                      hf_hub_download(...
    #                      client.chat.completions.create(...
    #                      pipeline(...
    #                      Trainer(...
    method_match = re.search(
        r'(?:([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.)?'
        r'([A-Za-z_]\w*)\s*\(',
        code_snippet
    )
    if method_match:
        obj_part = method_match.group(1) or ""
        method_name = method_match.group(2)
        # Build the full method reference
        if obj_part:
            result["api_method"] = f"{obj_part}.{method_name}"
        else:
            result["api_method"] = method_name
    
    # --- 2. Map to implied HTTP method ---
    if result["api_method"]:
        # Try progressively shorter suffixes: chat.completions.create -> completions.create -> create
        parts = result["api_method"].split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix in SDK_METHOD_HTTP_MAP:
                result["http_method"] = SDK_METHOD_HTTP_MAP[suffix]
                break
    
    # Also try from rule_id as fallback  (e.g. "huggingface-automodel" -> from_pretrained)
    if not result["http_method"] and rule_id:
        rule_lower = rule_id.lower()
        for method_key, http_verb in SDK_METHOD_HTTP_MAP.items():
            if method_key.replace("_", "-") in rule_lower or method_key.replace(".", "-") in rule_lower:
                result["http_method"] = http_verb
                break
    
    # --- 3. Extract key parameters ---
    params: Dict[str, str] = {}
    for pattern, label in SDK_PARAM_PATTERNS:
        m = re.search(pattern, code_snippet)
        if m:
            val = m.group(1).strip()
            if val and val not in ("None", "null", "undefined", "True", "False"):
                params[label] = val
    
    if params:
        result["request_body"] = params
    
    return result

def _read_source_line(file_path: str, line_number: int) -> str:
    """Read a specific line from a source file for model extraction fallback.
    
    When semgrep returns 'requires login' instead of the matched code,
    we read the source file directly to get the actual line content.
    """
    try:
        p = Path(file_path)
        if not p.is_file():
            return ""
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
    except Exception:
        pass
    return ""


def _process_finding(finding: Dict, checkout_dir: Path, rule_category: str) -> Dict:
    """Process a single finding into standardized format."""
    file_path = finding.get("path", "")
    abs_file_path = file_path  # Keep absolute path for file reading
    
    # Make path relative
    try:
        abs_path = Path(file_path)
        if abs_path.is_absolute():
            file_path = str(abs_path.relative_to(checkout_dir))
    except (ValueError, TypeError):
        pass
    
    extra = finding.get("extra", {})
    code_lines = (extra.get("lines") or "").strip()
    
    # If semgrep masked the code ("requires login" or empty), read the source
    # file directly so the model extractor has real code to work with.
    if not code_lines or code_lines == "requires login":
        start_line = finding.get("start", {}).get("line", 0)
        if start_line and abs_file_path:
            code_lines = _read_source_line(abs_file_path, start_line)
            if code_lines:
                # Inject real code so extract_model_value can use it
                extra = dict(extra)  # shallow copy
                extra["lines"] = code_lines
                finding = dict(finding, extra=extra)
    
    check_id = finding.get("check_id", "")
    snippet = code_lines.strip()[:300] if code_lines else ""
    
    # SDK enrichment: extract method, implied HTTP verb, key params
    sdk = _extract_sdk_details(snippet, check_id)
    
    result = {
        "file": file_path.replace("\\", "/"),
        "line": finding.get("start", {}).get("line", 0),
        "end_line": finding.get("end", {}).get("line", 0),
        "rule_id": check_id,
        "rule_category": rule_category,
        "message": extra.get("message", ""),
        "severity": extra.get("severity", "INFO"),
        "code_snippet": snippet,
        "model_value": extract_model_value(finding),
    }
    # Only include SDK-enriched fields when they have real values
    if sdk.get("api_method"):
        result["api_method"] = sdk["api_method"]
    if sdk.get("http_method"):
        result["http_method"] = sdk["http_method"]
    if sdk.get("request_body"):
        result["request_body"] = sdk["request_body"]
    return result


def _normalize_language(lang_raw: str) -> str:
    """Normalize language to a supported language name."""
    if lang_raw in JS_LANGUAGE_VARIANTS:
        return "javascript"
    if lang_raw in ("go", "golang"):
        return "go"
    if lang_raw in ("dotnet", "csharp", "cs", "fsharp", "fs", "vb", "vbnet"):
        return "dotnet"
    if lang_raw in ("java", "kotlin", "kt"):
        return "java"
    return "python"


# =============================================================================
# MAIN SCANNING LOGIC
# =============================================================================

def scan_ai_branches(
    checkout_dir: str,
    branch_trace: Dict,
    enabled_categories: Optional[List[str]] = None,
    languages_detected: Optional[List[str]] = None
) -> Dict:
    """
    Run targeted semgrep scans on AI branch traced files.
    
    Flow:
    1. For each library: Find matching provider rule → run on traced files
    2. If no provider rule: Skip (model detection covers it)
    3. Model detection: Run ONCE on ALL language files (even with 0 branches)
    
    Args:
        languages_detected: List of languages found in the repo (from /packages).
                           Used for PASS 2 model detection when branches is empty.
    """
    logger.info("[SCAN] Starting AI targeted scan")
    
    checkout_path = Path(checkout_dir)
    branches = branch_trace.get("branches", {})
    
    # Build file cache ONCE for all semgrep runs
    file_cache = _build_file_cache(checkout_path)
    
    # Determine primary language:
    # 1. From branch trace (majority vote) — best signal
    # 2. From languages_detected (session data) — fallback for 0-branch repos
    # 3. Default to "python"
    lang_counts: Dict[str, int] = {}
    for b in branches.values():
        lang = _normalize_language(b.get("language", "python").lower())
        lang_counts[lang] = lang_counts.get(lang, 0) + 1
    
    if lang_counts:
        primary_language = max(lang_counts, key=lang_counts.get)
    elif languages_detected:
        # Use first detected language (already normalized by /packages endpoint)
        primary_language = _normalize_language(languages_detected[0].lower())
    else:
        primary_language = "python"
    
    if not branches:
        logger.warning("[SCAN] No branches found - running PASS 2 model detection only")
        # Skip PASS 1 entirely but still run PASS 2 model detection
        # so we catch model names in repos that use raw REST calls (no AI SDK)
        return _run_model_detection_only(checkout_path, primary_language, file_cache)
    
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
        base_tag = _category_to_tag(ai_category)
        
        for f in library_findings:
            if model_val := f.get("model_value"):
                lib_models.append(model_val)
                all_models.append({"model": model_val, "file": f["file"], "line": f["line"], "library": lib_name, "tag": _best_tag(base_tag, model_val)})
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
    
    # Build file → (library, category) lookup for tagging PASS 2 models
    file_branch_lookup = _build_file_to_branch_lookup(branches)
    
    model_detection_findings: List[Dict] = []
    model_detection_rule = get_model_detection_rule(primary_language)
    
    if model_detection_rule and all_traced_files:
        rule_name = model_detection_rule.name
        # Expand scope: scan ALL language files in checkout so we detect model
        # strings in helper/settings files that don't directly import AI libs
        # (e.g. GptRequest.cs with `Model = "gpt-4o"`, ParameterManager.cs, etc.)
        all_lang_files = _get_all_language_files(checkout_path, primary_language)
        logger.info(f"[PASS2] Found {len(all_lang_files)} total {primary_language} files in checkout, "
                    f"{len(all_traced_files)} traced, rule={rule_name}")
        model_scan_candidates = all_lang_files if all_lang_files else list(all_traced_files)
        files_to_scan = [f for f in model_scan_candidates if (f, rule_name) not in scanned_pairs]
        scanned_pairs.update((f, rule_name) for f in files_to_scan)

        logger.info(f"[PASS2] Model detection scanning {len(files_to_scan)} {primary_language} files "
                    f"(traced={len(all_traced_files)}, total_lang={len(model_scan_candidates)})")

        if files_to_scan:
            findings, error = run_semgrep(checkout_path, model_detection_rule, files_to_scan, file_cache=file_cache)
            
            if error:
                all_errors.append(f"model_detection: {error}")
            elif findings:
                for f in findings:
                    processed = _process_finding(f, checkout_path, "model_detection")
                    model_detection_findings.append(processed)
                    
                    if model_val := processed.get("model_value"):
                        lib_name_p2, tag_p2 = _resolve_tag_for_pass2(
                            processed["file"], model_val, file_branch_lookup
                        )
                        all_models.append({
                            "model": model_val,
                            "file": processed["file"],
                            "line": processed["line"],
                            "library": lib_name_p2,
                            "tag": tag_p2
                        })

            # ------------------------------------------------------------------
            # Python regex fallback: scan files directly for model string literals.
            # Catches patterns semgrep misses: Go const blocks with custom types,
            # typed constants like `const GPT4 ChatModel = "gpt-4"`, etc.
            # ------------------------------------------------------------------
            seen_model_locs: Set[Tuple[str, int, str]] = {
                (f.get("file", ""), f.get("line", 0), f.get("model_value", ""))
                for f in model_detection_findings
                if f.get("model_value")
            }
            for filepath in files_to_scan:
                for hit in scan_file_for_models(filepath, str(checkout_path)):
                    key = (hit["file"], hit["line"], hit["model"])
                    if key not in seen_model_locs:
                        seen_model_locs.add(key)
                        model_detection_findings.append({
                            "file": hit["file"],
                            "line": hit["line"],
                            "end_line": hit["line"],
                            "rule_id": hit["rule_id"],
                            "rule_category": hit["rule_category"],
                            "message": f"AI model string detected: {hit['model']}",
                            "severity": "INFO",
                            "code_snippet": hit["code_snippet"],
                            "model_value": hit["model"]
                        })
                        lib_name_rx, tag_rx = _resolve_tag_for_pass2(
                            hit["file"], hit["model"], file_branch_lookup
                        )
                        all_models.append({
                            "model": hit["model"],
                            "file": hit["file"],
                            "line": hit["line"],
                            "library": lib_name_rx,
                            "tag": tag_rx
                        })
            logger.info(f"[PASS2] Total model findings after regex fallback: {len(model_detection_findings)}")
    
    # ==========================================================================
    # PASS 3: AI API Call Detection (chat completions, embeddings, AI URLs)
    # ==========================================================================
    
    logger.info("[PASS3] Starting AI API call detection pass")
    
    ai_api_findings: List[Dict] = []
    ai_api_rule = get_ai_api_calls_rule(primary_language)
    
    if ai_api_rule:
        rule_name = ai_api_rule.name
        # Scan ALL language files for AI API calls (they may be in any file)
        all_lang_files_for_ai = _get_all_language_files(checkout_path, primary_language)
        if not all_lang_files_for_ai:
            all_lang_files_for_ai = list(all_traced_files)
        
        files_to_scan = [f for f in all_lang_files_for_ai if (f, rule_name) not in scanned_pairs]
        scanned_pairs.update((f, rule_name) for f in files_to_scan)
        
        logger.info(f"[PASS3] AI API call scanning {len(files_to_scan)} {primary_language} files")
        
        if files_to_scan:
            findings, error = run_semgrep(checkout_path, ai_api_rule, files_to_scan, file_cache=file_cache)
            
            if error:
                all_errors.append(f"ai_api_calls: {error}")
            elif findings:
                for f in findings:
                    processed = _process_api_finding(f, checkout_path, "ai_api_call")
                    ai_api_findings.append(processed)
                    
                    # If the finding has AI provider info, enrich with it
                    metadata = f.get("extra", {}).get("metadata", {})
                    provider = metadata.get("provider", "")
                    api_type = metadata.get("api_type", "")
                    
                    if provider:
                        processed["ai_provider"] = provider
                    if api_type:
                        processed["ai_api_type"] = api_type
                
                logger.info(f"[PASS3] Found {len(ai_api_findings)} AI API call findings")
    else:
        logger.info(f"[PASS3] No ai_api_calls rule for {primary_language}")
    
    # ==========================================================================
    # Build Final Response
    # ==========================================================================
    
    return _build_scan_response(
        scan_results, all_models, model_detection_findings,
        all_errors, branches, primary_language, model_detection_rule,
        ai_api_findings=ai_api_findings, ai_api_rule=ai_api_rule
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


def _run_model_detection_only(
    checkout_path: Path,
    primary_language: str,
    file_cache: Dict[str, str]
) -> Dict:
    """
    Run PASS 2 model detection when there are no AI branches.
    
    This handles repos that use raw REST / HTTP calls to AI APIs instead of
    AI SDKs.  The import scanner finds no AI libs → 0 branches, but model
    names like 'text-davinci-003' are embedded in URLs or string literals.
    We still want to scan ALL source files with the model detection rules.
    """
    model_detection_rule = get_model_detection_rule(primary_language)
    if not model_detection_rule:
        logger.info(f"[PASS2-ONLY] No model detection rule for {primary_language}")
        return _empty_scan_result()

    all_lang_files = _get_all_language_files(checkout_path, primary_language)
    if not all_lang_files:
        logger.info(f"[PASS2-ONLY] No {primary_language} source files found")
        return _empty_scan_result()

    logger.info(f"[PASS2-ONLY] Scanning {len(all_lang_files)} {primary_language} files with {model_detection_rule.name}")

    findings, error = run_semgrep(checkout_path, model_detection_rule, all_lang_files, file_cache=file_cache)
    all_errors: List[str] = []
    if error:
        all_errors.append(f"model_detection: {error}")

    all_models: List[Dict] = []
    model_detection_findings: List[Dict] = []
    if findings:
        for f in findings:
            processed = _process_finding(f, checkout_path, "model_detection")
            model_detection_findings.append(processed)
            if model_val := processed.get("model_value"):
                all_models.append({
                    "model": model_val,
                    "file": processed["file"],
                    "line": processed["line"],
                    "library": "detected",
                    "tag": _infer_tag_from_model_name(model_val)
                })

    # ------------------------------------------------------------------
    # Python regex fallback: catches model strings that semgrep misses
    # (Go const blocks, typed constants, direct HTTP calls with model in URL/body).
    # Runs on ALL language files, same as the main scan path PASS 2.
    # ------------------------------------------------------------------
    seen_model_locs: Set[Tuple[str, int, str]] = {
        (f.get("file", ""), f.get("line", 0), f.get("model_value", ""))
        for f in model_detection_findings
        if f.get("model_value")
    }
    for filepath in all_lang_files:
        for hit in scan_file_for_models(filepath, str(checkout_path)):
            key = (hit["file"], hit["line"], hit["model"])
            if key not in seen_model_locs:
                seen_model_locs.add(key)
                model_detection_findings.append({
                    "file": hit["file"],
                    "line": hit["line"],
                    "end_line": hit["line"],
                    "rule_id": hit["rule_id"],
                    "rule_category": hit["rule_category"],
                    "message": f"AI model string detected: {hit['model']}",
                    "severity": "INFO",
                    "code_snippet": hit["code_snippet"],
                    "model_value": hit["model"]
                })
                all_models.append({
                    "model": hit["model"],
                    "file": hit["file"],
                    "line": hit["line"],
                    "library": "detected",
                    "tag": _infer_tag_from_model_name(hit["model"])
                })

    logger.info(f"[PASS2-ONLY] Found {len(all_models)} models, {len(model_detection_findings)} findings after regex fallback")

    # Also run AI API call detection on all files
    ai_api_findings: List[Dict] = []
    ai_api_rule = get_ai_api_calls_rule(primary_language)
    if ai_api_rule and all_lang_files:
        logger.info(f"[PASS3-ONLY] AI API call scanning {len(all_lang_files)} {primary_language} files")
        ai_findings_raw, ai_error = run_semgrep(checkout_path, ai_api_rule, all_lang_files, file_cache=file_cache)
        if ai_error:
            all_errors.append(f"ai_api_calls: {ai_error}")
        elif ai_findings_raw:
            for f in ai_findings_raw:
                processed = _process_api_finding(f, checkout_path, "ai_api_call")
                metadata = f.get("extra", {}).get("metadata", {})
                provider = metadata.get("provider", "")
                api_type = metadata.get("api_type", "")
                if provider:
                    processed["ai_provider"] = provider
                if api_type:
                    processed["ai_api_type"] = api_type
                ai_api_findings.append(processed)
            logger.info(f"[PASS3-ONLY] Found {len(ai_api_findings)} AI API call findings")

    return _build_scan_response(
        scan_results={},
        all_models=all_models,
        model_detection_findings=model_detection_findings,
        all_errors=all_errors,
        branches={},
        primary_language=primary_language,
        model_detection_rule=model_detection_rule,
        ai_api_findings=ai_api_findings,
        ai_api_rule=ai_api_rule
    )


def _empty_scan_result() -> Dict:
    """Return empty scan result structure."""
    return {
        "scan_results": [],
        "models_detected": [],
        "distinct_models": [],
        "model_detection_findings": [],
        "ai_api_call_findings": [],
        "summary": {
            "total_libraries": 0,
            "libraries_scanned": 0,
            "total_findings": 0,
            "unique_models_detected": 0,
            "all_models": [],
            "model_detection_findings_count": 0,
            "ai_api_call_findings_count": 0,
            "errors": [],
            "timestamp": datetime.now().isoformat(),
            "language": "unknown",
            "rules_used": {"model_detection": None, "ai_api_calls": None}
        }
    }


def _build_scan_response(
    scan_results: Dict,
    all_models: List[Dict],
    model_detection_findings: List[Dict],
    all_errors: List[str],
    branches: Dict,
    primary_language: str,
    model_detection_rule: Optional[Path],
    ai_api_findings: Optional[List[Dict]] = None,
    ai_api_rule: Optional[Path] = None
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
    
    # Build all_models as list of {model_name, tag} with deduplication
    _seen_model_for_tag: Dict[str, str] = {}
    for m in unique_models:
        mname = m["model"]
        if mname not in _seen_model_for_tag:
            _seen_model_for_tag[mname] = m.get("tag", "AI")
    all_models_with_tags = sorted(
        [{"model_name": k, "tag": v} for k, v in _seen_model_for_tag.items()],
        key=lambda x: x["model_name"]
    )
    
    # Deduplicate model_detection_findings
    seen_findings: Set[Tuple[str, int, str]] = set()
    unique_findings: List[Dict] = []
    
    for f in model_detection_findings:
        key = (f["file"], f["line"], f.get("model_value", ""))
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    
    # Deduplicate AI API call findings
    ai_api_findings = ai_api_findings or []
    seen_ai_api: Set[Tuple[str, int, str]] = set()
    unique_ai_api: List[Dict] = []
    
    for f in ai_api_findings:
        key = (f["file"], f["line"], f.get("rule_id", ""))
        if key not in seen_ai_api:
            seen_ai_api.add(key)
            unique_ai_api.append(f)
    
    scan_results_list = list(scan_results.values())
    libraries_scanned = sum(1 for r in scan_results_list if r.get("scanned"))
    total_findings = (
        sum(r.get("findings_count", 0) for r in scan_results_list)
        + len(unique_findings)
        + len(unique_ai_api)
    )
    
    return {
        "scan_results": scan_results_list,
        "models_detected": unique_models,
        "distinct_models": distinct_model_names,
        "model_detection_findings": unique_findings,
        "ai_api_call_findings": unique_ai_api,
        "summary": {
            "total_libraries": len(branches),
            "libraries_scanned": libraries_scanned,
            "total_findings": total_findings,
            "unique_models_detected": len(distinct_model_names),
            "all_models": all_models_with_tags,
            "model_detection_findings_count": len(unique_findings),
            "ai_api_call_findings_count": len(unique_ai_api),
            "errors": all_errors,
            "timestamp": datetime.now().isoformat(),
            "language": primary_language,
            "rules_used": {
                "model_detection": model_detection_rule.name if model_detection_rule else None,
                "ai_api_calls": ai_api_rule.name if ai_api_rule else None
            }
        }
    }


def _extract_http_method(finding: Dict, code_lines: str) -> str:
    """Extract the HTTP verb (GET/POST/PUT/PATCH/DELETE) from a semgrep finding.

    Priority:
    1. Rule metadata ``http_method`` field when not 'ANY'
    2. Rule ID encodes the verb (e.g. 'api-requests-post-json' → POST)
    3. Code-line substring scan using HTTP_METHOD_PATTERNS
    4. Returns 'UNKNOWN' if undetermined.
    """
    import re as _re

    # 1. Metadata field
    metadata = finding.get("extra", {}).get("metadata", {})
    meta_method = metadata.get("http_method", "")
    if meta_method and meta_method not in ("ANY", ""):
        return meta_method.upper()

    # 2. Rule ID heuristic
    rule_id = (finding.get("check_id") or "").lower()
    for verb in ("post", "put", "patch", "delete", "get", "head", "options"):
        if f"-{verb}" in rule_id or f"_{verb}" in rule_id:
            return verb.upper()

    # 3. Code-line substring scan
    code_lower = code_lines.lower()
    for method, patterns in HTTP_METHOD_PATTERNS.items():
        if any(p.lower() in code_lower for p in patterns):
            return method

    return "UNKNOWN"


def _extract_api_url_info(finding: Dict) -> Tuple[Optional[str], bool, Optional[str]]:
    """Extract API URL, dynamic flag, and raw variable name from a semgrep finding.

    Returns
    -------
    (url, is_dynamic, url_raw)
    - url:        resolved literal URL string, or None if dynamic
    - is_dynamic: True when the URL is a variable / env var / f-string
    - url_raw:    the raw variable expression when dynamic, or None
    """
    import re as _re

    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    code_lines = (extra.get("lines") or "").strip()

    # ── Strategy 1: Metavar lookup ──────────────────────────────────────────
    for key in ("$URL", "$ROUTE", "$TARGET", "$URI", "$SERVICE",
                "$HOST", "$RESOURCE", "$PATH", "$ENDPOINT", "$CONN"):
        if key in metavars:
            raw_val = metavars[key].get("abstract_content", "").strip()
            if not raw_val or raw_val.lower() in API_FALSE_POSITIVES or len(raw_val) <= 1:
                continue
            # Looks like a quoted literal URL?
            clean = raw_val.strip('"\'')
            if clean.startswith(("http://", "https://", "/")):
                return clean, False, None
            # Looks like an env rule fired — special case
            rule_id = (finding.get("check_id") or "").lower()
            if "env" in rule_id or "environ" in raw_val.lower():
                return None, True, raw_val
            # Otherwise it's a variable / expression
            return None, True, raw_val

    # ── Strategy 2: Code-line regex for literal URL ──────────────────────────
    if code_lines:
        url_match = _re.search(r'["\']((https?://|/)[^"\']+)["\']', code_lines)
        if url_match:
            return url_match.group(1), False, None

        # f-string with URL fragment
        fstr = _re.search(r'f["\'].*(https?://[^"\'{]+)', code_lines)
        if fstr:
            return None, True, "f-string"

    # ── Strategy 3: env_url rule always means dynamic ────────────────────────
    rule_id = (finding.get("check_id") or "").lower()
    if "env" in rule_id:
        # Try to extract the env var name from the code
        env_match = _re.search(r'(?:environ|getenv|process\.env)\.(?:get\()?["\']([A-Z_]+)["\']', code_lines)
        env_name = env_match.group(1) if env_match else "ENV_VAR"
        return None, True, env_name

    return None, False, None


def _extract_request_body(finding: Dict, code_lines: str) -> Optional[Dict]:
    """Extract request body type and raw value from a semgrep finding.

    Prefers the ``$BODY`` metavar from structured rules, then falls back
    to regex matching against the code line.

    Returns a dict like ``{"type": "json", "raw": "payload"}`` or None.
    """
    import re as _re

    # 1. Structured metavar from semgrep
    body_val = (finding.get("extra", {}).get("metavars", {})
                        .get("$BODY", {}).get("abstract_content", "")).strip()
    if body_val:
        # Guess type from rule ID (already encodes POST/json hint)
        rule_id = (finding.get("check_id") or "").lower()
        body_type = "json" if "json" in rule_id else ("form" if "data" in rule_id else "body")
        return {"type": body_type, "raw": body_val.strip('"\' ')[:100]}

    # 2. Regex on code line
    for pattern, body_type in REQUEST_BODY_PATTERNS:
        m = _re.search(pattern, code_lines)
        if m:
            raw = m.group(1).strip().strip('"\'')
            return {"type": body_type, "raw": raw[:100]}

    return None


def _extract_request_headers(finding: Dict, code_lines: str) -> Optional[List[str]]:
    """Extract header key names (or variable name) from a semgrep finding.

    Returns a list of string header names, e.g. ``["Authorization", "Content-Type"]``,
    or ``["<variable-name>"]`` when assigned dynamically, or None if nothing found.
    """
    import re as _re

    # 1. Structured metavar
    hdr_val = (finding.get("extra", {}).get("metavars", {})
                       .get("$HEADERS", {}).get("abstract_content", "")).strip()
    if hdr_val:
        # Already a literal dict from code?
        keys = _re.findall(r'["\']([A-Za-z][A-Za-z0-9_-]{2,})["\']', hdr_val)
        if keys:
            return [k for k in keys if k.lower() not in ("true", "false", "none")]
        return [hdr_val.strip('"\' ')[:80]]

    # 2. Regex patterns on code line
    for pattern in REQUEST_HEADER_PATTERNS:
        m = _re.search(pattern, code_lines)
        if m:
            matched = m.group(1)
            # Literal dict — extract just the key names
            keys = _re.findall(r'["\']([A-Za-z][A-Za-z0-9_-]{2,})["\']', matched)
            if keys:
                return [k for k in keys if k.lower() not in ("true", "false", "none")]
            # Variable name
            var = matched.strip()
            if var:
                return [f"<{var}>"]   # tag as variable, not a literal key

    return None


# =============================================================================
# API ENDPOINT EXTRACTION
# =============================================================================

def _extract_api_value(finding: Dict) -> Optional[str]:
    """Extract API URL/endpoint/route from a semgrep finding.

    Thin wrapper kept for backward compatibility; uses _extract_api_url_info.
    """
    url, _dyn, _raw = _extract_api_url_info(finding)
    if url:
        return url
    # Fall back to code-line regex (same as original behaviour)
    import re as _re
    code_lines = (finding.get("extra", {}).get("lines") or "").strip()
    if code_lines:
        url_match = _re.search(r'["\']((https?://|/)[^"\']+)["\']', code_lines)
        if url_match:
            return url_match.group(1)
    return None




def _process_api_finding(finding: Dict, checkout_dir: Path, rule_category: str) -> Dict:
    """Process a single API finding into standardized format."""
    file_path = finding.get("path", "")
    abs_file_path = file_path
    
    # Make path relative
    try:
        abs_path = Path(file_path)
        if abs_path.is_absolute():
            file_path = str(abs_path.relative_to(checkout_dir))
    except (ValueError, TypeError):
        pass
    
    extra = finding.get("extra", {})
    code_lines = (extra.get("lines") or "").strip()
    
    # If semgrep masked the code, read the source file directly
    if not code_lines or code_lines == "requires login":
        start_line = finding.get("start", {}).get("line", 0)
        if start_line and abs_file_path:
            code_lines = _read_source_line(abs_file_path, start_line)
            if code_lines:
                extra = dict(extra)
                extra["lines"] = code_lines
                finding = dict(finding, extra=extra)
    
    # Get API category from rule metadata
    metadata = extra.get("metadata", {})
    api_type = metadata.get("api_type") or metadata.get("type") or ""
    api_category = (metadata.get("category") or rule_category or "").upper()
    
    result = {
        "file": file_path.replace("\\", "/"),
        "line": finding.get("start", {}).get("line", 0),
        "end_line": finding.get("end", {}).get("line", 0),
        "rule_id": finding.get("check_id", ""),
        "rule_category": api_category,
        "message": extra.get("message", ""),
        "severity": extra.get("severity", "INFO"),
        "code_snippet": code_lines.strip()[:300] if code_lines else "",
    }
    # Only include enriched fields when they have real values
    if api_type:
        result["api_method"] = api_type
    api_url = _extract_api_value(finding)
    if api_url:
        result["api_url"] = api_url
    http_method = _extract_http_method(finding, code_lines)
    if http_method:
        result["http_method"] = http_method
    _, url_is_dynamic, url_raw = _extract_api_url_info(finding)
    if url_is_dynamic is not None:
        result["url_is_dynamic"] = url_is_dynamic
    if url_raw:
        result["url_raw"] = url_raw
    request_body = _extract_request_body(finding, code_lines)
    if request_body:
        result["request_body"] = request_body
    request_headers = _extract_request_headers(finding, code_lines)
    if request_headers:
        result["request_headers"] = request_headers
    return result


# =============================================================================
# API SCANNING LOGIC
# =============================================================================

def scan_api_branches(
    checkout_dir: str,
    branch_trace: Dict,
    languages_detected: Optional[List[str]] = None
) -> Dict:
    """
    Run targeted semgrep scans on API branch traced files.
    
    Flow:
    1. For each API library: Find API rule for the language → run on traced files
    2. Collect all API findings (endpoints, URLs, routes, HTTP calls)
    
    Args:
        checkout_dir: Path to the repo checkout
        branch_trace: Branch trace data containing api_branches
        languages_detected: Languages found in the repo
    """
    logger.info("[API-SCAN] Starting API targeted scan")
    
    checkout_path = Path(checkout_dir)
    api_branches = branch_trace.get("api_branches", {})
    
    if not api_branches:
        logger.info("[API-SCAN] No API branches found, returning empty result")
        return _empty_api_scan_result()
    
    # Build file cache ONCE
    file_cache = _build_file_cache(checkout_path)
    
    # Build a fallback list of all Python .py files in the checkout.
    # Used when a library's traced_files contain no Python source files
    # (e.g., only requirements.txt) — we scan the whole Python codebase instead.
    _python_fallback: List[str] = []
    def _get_python_fallback() -> List[str]:
        nonlocal _python_fallback
        if not _python_fallback:
            _python_fallback = [
                v for k, v in file_cache.items()
                if k.endswith(".py") and "/" not in k  # filename-only keys
            ]
            logger.info(f"[API-SCAN] Built Python fallback: {len(_python_fallback)} .py files")
        return _python_fallback
    
    # Determine primary language
    lang_counts: Dict[str, int] = {}
    for b in api_branches.values():
        lang = _normalize_language(b.get("language", "python").lower())
        lang_counts[lang] = lang_counts.get(lang, 0) + 1
    
    if lang_counts:
        primary_language = max(lang_counts, key=lang_counts.get)
    elif languages_detected:
        primary_language = _normalize_language(languages_detected[0].lower())
    else:
        primary_language = "python"
    
    # State tracking
    scanned_pairs: Set[Tuple[str, str]] = set()  # (file, rule_name) — for .py-traced files only
    _fallback_findings_cache: Optional[List[Dict]] = None  # shared findings from fallback scan
    _fallback_scan_done: bool = False
    api_scan_results: Dict[str, Dict] = {}
    all_errors: List[str] = []
    all_api_findings: List[Dict] = []
    all_api_endpoints: List[Dict] = []
    
    def _get_fallback_findings(api_rule_path: Path) -> List[Dict]:
        """Run semgrep on all Python fallback files ONCE and cache results."""
        nonlocal _fallback_findings_cache, _fallback_scan_done
        if not _fallback_scan_done:
            _fallback_scan_done = True
            py_files = _get_python_fallback()
            if py_files:
                logger.info(f"[API-SCAN] Running one-time fallback scan on {len(py_files)} Python files")
                findings, err = run_semgrep(checkout_path, api_rule_path, py_files, file_cache=file_cache)
                if err:
                    logger.warning(f"[API-SCAN] Fallback scan error: {err}")
                    _fallback_findings_cache = []
                else:
                    _fallback_findings_cache = findings
                    logger.info(f"[API-SCAN] Fallback scan yielded {len(findings)} total findings")
            else:
                _fallback_findings_cache = []
        return _fallback_findings_cache or []

    # For each API library: run the api_calls rule on its traced files
    for lib_name, branch in api_branches.items():
        traced_files = branch.get("traced_files", [])
        language = _normalize_language(branch.get("language", "python").lower())
        api_category = branch.get("category", "UNKNOWN")
        
        if not traced_files:
            api_scan_results[lib_name] = _api_lib_result(
                lib_name, api_category, language, scanned=False, reason="No traced files"
            )
            continue
        
        # Find the API calls rule for this language
        api_rule = get_api_calls_rule(language)
        library_findings: List[Dict] = []
        rules_used: List[str] = []
        
        if api_rule:
            rule_name = api_rule.name
            rules_used.append(rule_name)
            
            # Determine whether this library has real .py traced files
            py_traced = [f for f in traced_files if f.endswith(".py")]
            
            if py_traced:
                # Normal case: scan the .py files directly (with dedup)
                files_to_scan = [f for f in py_traced if (f, rule_name) not in scanned_pairs]
                scanned_pairs.update((f, rule_name) for f in files_to_scan)
                if files_to_scan:
                    logger.info(f"[API-SCAN] Scanning {len(files_to_scan)} .py files for {lib_name}")
                    findings, error = run_semgrep(checkout_path, api_rule, files_to_scan, file_cache=file_cache)
                    if error:
                        all_errors.append(f"{lib_name}/api_calls: {error}")
                    elif findings:
                        logger.info(f"[API-SCAN] Found {len(findings)} findings for {lib_name}")
                        lib_api_category = find_api_category_for_library(lib_name)
                        for f in findings:
                            processed = _process_api_finding(f, checkout_path, "api_calls")
                            if api_category and api_category != "UNKNOWN":
                                processed["rule_category"] = api_category
                            finding_category = processed.get("rule_category", "")
                            if not lib_api_category or finding_category == lib_api_category or api_category == "UNKNOWN":
                                library_findings.append(processed)
            else:
                # Fallback case: all traced files are non-.py (e.g. requirements.txt)
                # Use the one-time cached fallback scan and filter relevant findings
                logger.info(f"[API-SCAN] {lib_name}: using cached fallback scan (no .py traced files)")
                all_fallback = _get_fallback_findings(api_rule)
                lib_api_category = find_api_category_for_library(lib_name)
                for f in all_fallback:
                    processed = _process_api_finding(f, checkout_path, "api_calls")
                    if api_category and api_category != "UNKNOWN":
                        processed["rule_category"] = api_category
                    finding_category = processed.get("rule_category", "")
                    if not lib_api_category or finding_category == lib_api_category or api_category == "UNKNOWN":
                        library_findings.append(processed)

        else:
            logger.warning(f"[API-SCAN] No api_calls rule for language: {language}")
        
        # Extract API endpoints from findings
        lib_endpoints: List[str] = []
        endpoint_values: List[Dict] = []
        
        for f in library_findings:
            all_api_findings.append(f)
            if api_url := f.get("api_url"):
                lib_endpoints.append(api_url)
                all_api_endpoints.append({
                    "endpoint": api_url,
                    "file": f["file"],
                    "line": f["line"],
                    "library": lib_name,
                    "api_type": f.get("api_method", ""),
                    "category": f.get("rule_category", "")
                })
                endpoint_values.append({
                    "endpoint": api_url,
                    "file": f["file"],
                    "line": f["line"],
                    "rule_id": f["rule_id"],
                    "code_snippet": f.get("code_snippet", "")[:100]
                })
        
        if lib_endpoints:
            logger.info(f"[API-SCAN] Endpoints found for {lib_name}: {lib_endpoints[:5]}")
        
        api_scan_results[lib_name] = _api_lib_result(
            lib_name, api_category, language,
            scanned=True,
            traced_files_count=len(traced_files),
            findings=library_findings,
            endpoints_detected=list(set(lib_endpoints)),
            endpoint_values=endpoint_values,
            rules_used=rules_used,
            api_rule_found=api_rule is not None
        )
    
    # Build response
    return _build_api_scan_response(
        api_scan_results, all_api_endpoints, all_api_findings,
        all_errors, api_branches, primary_language
    )


def _api_lib_result(
    lib_name: str,
    category: str,
    language: str,
    scanned: bool,
    reason: Optional[str] = None,
    traced_files_count: int = 0,
    findings: Optional[List[Dict]] = None,
    endpoints_detected: Optional[List[str]] = None,
    endpoint_values: Optional[List[Dict]] = None,
    rules_used: Optional[List[str]] = None,
    api_rule_found: bool = False
) -> Dict:
    """Create standardized API library result dict."""
    return {
        "library": lib_name,
        "category": category,
        "language": language,
        "scanned": scanned,
        "reason": reason,
        "traced_files_count": traced_files_count,
        "findings_count": len(findings) if findings else 0,
        "findings": findings or [],
        "endpoints_detected": endpoints_detected or [],
        "endpoint_values": endpoint_values or [],
        "rules_used": rules_used or [],
        "api_rule_found": api_rule_found
    }


def _empty_api_scan_result() -> Dict:
    """Return empty API scan result structure."""
    return {
        "api_scan_results": [],
        "api_endpoints_detected": [],
        "distinct_endpoints": [],
        "api_findings": [],
        "api_summary": {
            "total_libraries": 0,
            "libraries_scanned": 0,
            "total_findings": 0,
            "unique_endpoints_detected": 0,
            "all_endpoints": [],
            "errors": [],
            "timestamp": datetime.now().isoformat(),
            "language": "unknown",
            "rules_used": {}
        }
    }


def _build_api_scan_response(
    api_scan_results: Dict,
    all_api_endpoints: List[Dict],
    all_api_findings: List[Dict],
    all_errors: List[str],
    api_branches: Dict,
    primary_language: str
) -> Dict:
    """Build final API scan response with deduplication."""
    # Deduplicate endpoints by (endpoint, file, line)
    seen_endpoints: Set[Tuple[str, str, int]] = set()
    unique_endpoints: List[Dict] = []
    
    for ep in all_api_endpoints:
        key = (ep["endpoint"], ep["file"], ep["line"])
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            unique_endpoints.append(ep)
    
    distinct_endpoint_values = sorted({ep["endpoint"] for ep in unique_endpoints})
    
    # Deduplicate findings
    seen_findings: Set[Tuple[str, int, str]] = set()
    unique_findings: List[Dict] = []
    
    for f in all_api_findings:
        key = (f["file"], f["line"], f.get("rule_id", ""))
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    
    api_results_list = list(api_scan_results.values())
    libraries_scanned = sum(1 for r in api_results_list if r.get("scanned"))
    total_findings = sum(r.get("findings_count", 0) for r in api_results_list)
    
    api_rule = get_api_calls_rule(primary_language)
    
    return {
        "api_scan_results": api_results_list,
        "api_endpoints_detected": unique_endpoints,
        "distinct_endpoints": distinct_endpoint_values,
        "api_findings": unique_findings,
        "api_summary": {
            "total_libraries": len(api_branches),
            "libraries_scanned": libraries_scanned,
            "total_findings": total_findings,
            "unique_endpoints_detected": len(distinct_endpoint_values),
            "all_endpoints": distinct_endpoint_values,
            "errors": all_errors,
            "timestamp": datetime.now().isoformat(),
            "language": primary_language,
            "rules_used": {
                "api_calls": api_rule.name if api_rule else None
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
        "rules": discover_all_rules(),
        "api_rules": {
            lang: get_api_calls_rule(lang) is not None
            for lang in SUPPORTED_LANGUAGES
        },
        "ai_api_rules": {
            lang: get_ai_api_calls_rule(lang) is not None
            for lang in SUPPORTED_LANGUAGES
        }
    }
