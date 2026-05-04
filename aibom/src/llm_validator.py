"""
LLM Validator for AI Library Classification
Validates and classifies libraries as AI-positive or non-AI using Groq LLM.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

from aibom.config import (
    LLM_BATCH_SIZE,
    LLM_MAX_TOKENS_PER_LIB,
    LLM_MAX_TOKENS_CAP,
    LLM_MIN_TOKENS,
    LLM_TEMPERATURE,
    LLM_SYSTEM_PROMPT,
    SUPPORTED_LANGUAGES,
)

# Load environment variables once at module load
# Walk up to app/ directory to find .env
_app_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_app_root / ".env")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
LLM_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

# Lazy-loaded client
_groq_client = None

# =============================================================================
# Client & Helpers
# =============================================================================

def get_groq_client():
    """Get or create Groq client (lazy loading)."""
    global _groq_client
    if _groq_client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in environment")
        from groq import Groq
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


def _empty_result() -> Dict:
    """Return empty validation result structure."""
    return {
        "ai_libraries": [],
        "non_ai_libraries": [],
        "total_classified": 0,
        "total_ai_positive": 0,
        "total_non_ai": 0,
        "model_used": LLM_MODEL
    }

# =============================================================================
# Single Entry Point
# =============================================================================

def validate_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict,
    resolved_packages: Optional[Dict] = None,
    manifests_found: Optional[Dict[str, List[str]]] = None
) -> Optional[Dict]:
    """
    Main validation function - collects libraries, classifies, returns result.
    Args:
        manifest_deps: Dependencies from manifests {"python": [...], "javascript": [...]}
        import_packages: Import packages from /filtered-imports endpoint
        resolved_packages: Optional resolved/merged packages from /resolve-packages
        manifests_found: Optional manifest file paths per language {"python": ["requirements.txt"], ...}
    Returns:
        Validation result or None if classification failed
    """
    # Step 1: Extract libraries and build source lookup from appropriate input
    libraries, source_lookup = _extract_libraries(
        manifest_deps, import_packages, resolved_packages, manifests_found
    )
    if not libraries:
        return _empty_result()
    
    # Step 2: Classify with LLM
    logger.info(f"Classifying {len(libraries)} libraries...")
    classifications = classify_libraries(libraries)
    
    if not classifications:
        return None
    
    # Step 3: Build result (single pass through classifications)
    return _build_result(classifications, source_lookup)

# =============================================================================
# Step 1: Extract Libraries
# =============================================================================

def _build_source_files_lookup(import_packages: Dict) -> Dict[str, Dict]:
    """
    Build a lookup of package -> {source_files, import_details} from import_packages.
    This data comes from semgrep scan and has file locations + sub-import detail.
    """
    source_lookup = {}
    
    # Use configured language keys for future extensibility
    for import_key in SUPPORTED_LANGUAGES.values():
        for imp in import_packages.get(import_key, []):
            pkg_name = imp.get("package", "")
            if pkg_name:
                if pkg_name not in source_lookup:
                    source_lookup[pkg_name] = {
                        "source_files": [],
                        "import_details": [],
                    }
                # Add source files, avoiding duplicates
                for f in imp.get("source_files", []):
                    if f and f not in source_lookup[pkg_name]["source_files"]:
                        source_lookup[pkg_name]["source_files"].append(f)
                # Collect import details (already deduplicated by semgrep_scanner)
                for detail in imp.get("import_details", []):
                    source_lookup[pkg_name]["import_details"].append(detail)
    
    return source_lookup


def _extract_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict,
    resolved_packages: Optional[Dict],
    manifests_found: Optional[Dict[str, List[str]]] = None
) -> Tuple[List[str], Dict[str, Dict]]:
    """
    Extract unique library names and source lookup from inputs.
    
    Returns:
        Tuple of (sorted library names, source file lookup dict)
    """
    # Build source files lookup from import_packages (has file locations)
    source_files_map = _build_source_files_lookup(import_packages)
    logger.debug(f"source_files_map has {len(source_files_map)} entries from semgrep")
    
    # Build manifest-file lookup: package_name -> [manifest files]
    # so libraries from manifests get their manifest as source_files
    manifest_source_map: Dict[str, List[str]] = {}
    if manifests_found and manifest_deps:
        for lang, deps in manifest_deps.items():
            manifest_files = manifests_found.get(lang, [])
            logger.debug(f"manifest_source_map: lang={lang}, manifest_files={manifest_files}, deps_count={len(deps)}")
            if manifest_files:
                for dep in deps:
                    if dep:
                        manifest_source_map[dep] = list(manifest_files)
    else:
        logger.warning(f"manifest_source_map EMPTY: manifests_found={manifests_found!r}, manifest_deps keys={list(manifest_deps.keys()) if manifest_deps else 'None'}")
    
    logger.debug(f"manifest_source_map has {len(manifest_source_map)} entries")
    
    # Use resolved packages if available (already deduplicated)
    # Check for both possible data structures
    if resolved_packages:
        # Structure from package_resolver.py: {"resolved_packages": [...]}
        resolved_list = resolved_packages.get("resolved_packages", [])
        
        # Legacy structure: {"unified_packages": [...]}
        if not resolved_list:
            resolved_list = resolved_packages.get("unified_packages", [])
        
        if resolved_list:
            # Build lookup and collect names in single pass
            lookup = {}
            libraries = []
            for pkg in resolved_list:
                # Handle both key formats: "package" (new) or "library" (legacy)
                lib_name = pkg.get("package") or pkg.get("library", "")
                if lib_name:
                    libraries.append(lib_name)
                    # Get source files + import_details from import_packages lookup
                    pkg_entry = source_files_map.get(lib_name, {})
                    pkg_source_files = list(pkg_entry.get("source_files", []))
                    pkg_import_details = list(pkg_entry.get("import_details", []))
                    # Also check import_names for alternate lookups
                    for import_name in pkg.get("import_names", []):
                        if import_name in source_files_map:
                            alt = source_files_map[import_name]
                            for f in alt.get("source_files", []):
                                if f not in pkg_source_files:
                                    pkg_source_files.append(f)
                            for d in alt.get("import_details", []):
                                pkg_import_details.append(d)
                    
                    # If no source files from semgrep, fall back to manifest file(s)
                    if not pkg_source_files and lib_name in manifest_source_map:
                        pkg_source_files = list(manifest_source_map[lib_name])
                        logger.debug(f"Fallback to manifest for '{lib_name}': {pkg_source_files}")
                    elif not pkg_source_files:
                        logger.debug(f"No source_files for '{lib_name}': not in manifest_source_map ({lib_name in manifest_source_map})")
                    
                    lookup[lib_name] = {
                        "language": pkg.get("language"),
                        "source_files": pkg_source_files,
                        "import_details": pkg_import_details,
                        "import_names": pkg.get("import_names", []),
                        "is_used": pkg.get("is_used", True)
                    }
            
            return sorted(set(libraries)), lookup
    
    # Fallback: extract libraries directly from import_packages (semgrep scan results)
    # This handles cases where no manifest files exist (no requirements.txt, package.json, etc.)
    # but semgrep still detected third-party imports in the code.
    if source_files_map:
        logger.info(
            f"No resolved packages available. Falling back to {len(source_files_map)} "
            f"libraries from import scan results."
        )
        lookup = {}
        for lib_name, pkg_data in source_files_map.items():
            lookup[lib_name] = {
                "language": None,
                "source_files": pkg_data.get("source_files", []),
                "import_details": pkg_data.get("import_details", []),
                "import_names": [lib_name],
                "is_used": True
            }
        return sorted(source_files_map.keys()), lookup
    
    # Truly nothing to classify
    logger.warning("No libraries found from resolved packages or import scan.")
    return [], {}
# =============================================================================
# Step 2: Classify with LLM
# =============================================================================

def call_llm_batch(
    items: List,
    system_prompt: str,
    user_message: str,
    item_formatter=None,
    max_tokens_per_item: Optional[int] = None
) -> List[Dict]:
    """
    Generic LLM batch call - shared by validator and categorizer.
    
    Args:
        items: List of items to process (strings or dicts)
        system_prompt: System prompt for LLM
        user_message: User message prefix (items will be appended)
        item_formatter: Optional function to format each item (default: str)
        max_tokens_per_item: Override tokens-per-item estimate (default: LLM_MAX_TOKENS_PER_LIB).
                             Categorization needs ~120 tokens/lib vs validation's ~60.
    
    Returns:
        Parsed JSON array from LLM response
    """
    if not items:
        return []
    
    client = get_groq_client()
    
    # Format items for prompt
    formatter = item_formatter or str
    lib_list = "\n".join(f"- {formatter(item)}" for item in items)
    
    messages = [
        {"role": "system", "content": system_prompt.strip()},
        {"role": "user", "content": f"{user_message}\n{lib_list}"}
    ]
    
    # Token estimation — use override if provided
    tokens_per = max_tokens_per_item or LLM_MAX_TOKENS_PER_LIB
    max_tokens = min(
        max(LLM_MIN_TOKENS, len(items) * tokens_per + 500),
        LLM_MAX_TOKENS_CAP
    )
    
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=LLM_TEMPERATURE,
            max_tokens=max_tokens
        )
        
        choice = response.choices[0]
        truncated = choice.finish_reason == "length"
        if truncated:
            logger.warning(f"Response truncated at {max_tokens} tokens")
        
        return _parse_llm_response(choice.message.content, allow_partial=truncated)
        
    except Exception as e:
        logger.error(f"LLM API error: {e}")
        return []


def process_in_batches(
    items: List,
    batch_processor,
    batch_size: int = LLM_BATCH_SIZE
) -> List[Dict]:
    """
    Generic batch processor - shared by validator and categorizer.
    Args:
        items: List of items to process
        batch_processor: Function to process each batch
        batch_size: Items per batch
    Returns:
        Combined results from all batches
    """
    if not items:
        return []
    
    # Single batch - no overhead
    if len(items) <= batch_size:
        return batch_processor(items)
    
    # Multiple batches
    results = []
    total_batches = -(-len(items) // batch_size)
    
    for batch_num, i in enumerate(range(0, len(items), batch_size), 1):
        batch = items[i:i + batch_size]
        logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} items)")
        results.extend(batch_processor(batch))
    
    return results


def classify_libraries(libraries: List[str]) -> List[Dict]:
    """
    Classify all libraries, batching if necessary.
    Args:
        libraries: Sorted list of unique library names
    Returns:
        List of classification results
    """
    return process_in_batches(libraries, _classify_batch)


def _classify_batch(libraries: List[str]) -> List[Dict]:
    """Classify a single batch of libraries using LLM."""
    return call_llm_batch(
        items=libraries,
        system_prompt=LLM_SYSTEM_PROMPT,
        user_message="Classify these libraries:"
    )

def _parse_llm_response(text: str, allow_partial: bool = False) -> List[Dict]:
    """Extract JSON array from LLM response.
    
    Args:
        text: Raw LLM response text
        allow_partial: If True, attempt to recover partial results from
                       truncated JSON (e.g. when finish_reason == "length")
    """
    # Try markdown code block
    if "```json" in text:
        start = text.find("```json") + 7
        end = text.find("```", start)
        if end != -1:
            try:
                return json.loads(text[start:end].strip())
            except json.JSONDecodeError:
                pass
    
    # Try raw JSON array
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            # Fall through to partial recovery if allowed
            if not allow_partial:
                return []
    
    # ── Truncation recovery ──────────────────────────────────────────────
    # When the LLM response is cut off mid-JSON, try to salvage whatever
    # complete objects were returned before the truncation point.
    if allow_partial and "[" in text:
        recovered = _recover_truncated_json(text)
        if recovered:
            logger.warning(f"Recovered {len(recovered)} items from truncated response")
            return recovered
    
    logger.error("No JSON array found in response")
    return []


def _recover_truncated_json(text: str) -> List[Dict]:
    """Attempt to recover complete JSON objects from a truncated array.
    
    Strategy: find the last complete '}, {' or '}\n]' boundary and close
    the array there.
    """
    start = text.find("[")
    if start == -1:
        return []
    
    fragment = text[start:]
    
    # Find the last complete object boundary  "},"  or  "}\n,"  or  "}  ,"
    last_obj_end = -1
    depth_brace = 0
    i = 1  # skip opening '['
    
    while i < len(fragment):
        ch = fragment[i]
        if ch == '"':
            # Skip string contents (handle escaped quotes)
            i += 1
            while i < len(fragment) and fragment[i] != '"':
                if fragment[i] == '\\':
                    i += 1  # skip escaped char
                i += 1
        elif ch == '{':
            depth_brace += 1
        elif ch == '}':
            depth_brace -= 1
            if depth_brace == 0:
                last_obj_end = i  # potential complete object
        i += 1
    
    if last_obj_end <= 0:
        return []
    
    # Close the array after the last complete object
    repaired = fragment[:last_obj_end + 1].rstrip().rstrip(',') + "]"
    
    try:
        result = json.loads(repaired)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass
    
    return []

# =============================================================================
# Step 3: Build Result
# =============================================================================

def _build_result(
    classifications: List[Dict],
    source_lookup: Dict[str, Dict]
) -> Dict:
    """
    Build final validation result in single pass through classifications.

    Args:
        classifications: LLM classification results
        source_lookup: lib_name → {language, source_files} mapping
    """
    ai_libraries = []
    non_ai = []

    for item in classifications:
        lib_name = item.get("library", "")
        classification = item.get("classification", "").upper()
        confidence = item.get("confidence", "LOW").upper()
        reason = item.get("reason", "")

        if classification == "AI_POSITIVE":
            entry = {
                "library": lib_name,
                "classification": classification,
                "confidence": confidence,
                "reason": reason,
                "source_files": [],
                "import_details": [],
            }
            if lib_name in source_lookup:
                entry["source_files"] = source_lookup[lib_name].get("source_files", [])
                entry["language"] = source_lookup[lib_name].get("language")
                entry["import_details"] = source_lookup[lib_name].get("import_details", [])
            ai_libraries.append(entry)
        else:
            non_ai.append(lib_name)

    return {
        "ai_libraries": ai_libraries,
        "non_ai_libraries": non_ai,
        "total_classified": len(classifications),
        "total_ai_positive": len(ai_libraries),
        "total_non_ai": len(non_ai),
        "model_used": LLM_MODEL
    }