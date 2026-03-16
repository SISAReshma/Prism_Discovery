"""
LLM Categorizer for AI + API Library Classification
Categorizes both AI-positive and API-positive libraries in a single LLM call.

Reuses shared LLM infrastructure from llm_validator.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

from aibom.config import (
    LLM_CATEGORIZATION_PROMPT,
    VALID_CATEGORIES,
    VALID_API_CATEGORIES,
)

# Reuse shared components from llm_validator
from aibom.src.llm_validator import (
    call_llm_batch,
    process_in_batches,
    LLM_MODEL,
)

# =============================================================================
# Entry Point
# =============================================================================

def run_categorization(
    ai_libraries: List[Dict],
    api_libraries: Optional[List[Dict]] = None
) -> Optional[Dict]:
    """
    Unified categorization function — categorizes both AI and API libraries
    in a single LLM call.
    
    Libraries classified as BOTH (present in both lists) are tagged [BOTH] and
    the LLM returns two entries per such library — one AI category + one API category.
    
    Args:
        ai_libraries: List of AI-positive libraries from /llm-validate
        api_libraries: List of API-positive libraries from /llm-validate
    Returns:
        Combined categorization result or None if failed
    """
    if api_libraries is None:
        api_libraries = []

    if not ai_libraries and not api_libraries:
        return _empty_result()

    # Deduplicate each list by library name
    unique_ai = _deduplicate(ai_libraries)
    unique_api = _deduplicate(api_libraries)

    # Detect BOTH: libraries that appear in both lists
    ai_names = {lib["library"].lower() for lib in unique_ai}
    api_names = {lib["library"].lower() for lib in unique_api}
    both_names = ai_names & api_names

    # Build tagged list — BOTH libs get [BOTH] tag (LLM returns 2 entries each)
    tagged_libs = []
    for lib in unique_ai:
        if lib["library"].lower() in both_names:
            tagged_libs.append({"library": lib["library"], "tag": "BOTH"})
        else:
            tagged_libs.append({"library": lib["library"], "tag": "AI"})
    for lib in unique_api:
        if lib["library"].lower() not in both_names:
            tagged_libs.append({"library": lib["library"], "tag": "API"})
        # BOTH libs already added above — skip duplicates

    if not tagged_libs:
        return _empty_result()

    both_count = len(both_names)
    ai_only = len(unique_ai) - both_count
    api_only = len(unique_api) - both_count
    logger.info(f"Categorizing {ai_only} AI + {api_only} API + {both_count} BOTH libraries in single LLM call...")

    # Single LLM call with tagged items
    categorizations = process_in_batches(tagged_libs, _categorize_batch, batch_size=25)

    if not categorizations:
        return None

    # Build split result
    return _build_result(ai_libraries, api_libraries, categorizations)


def _deduplicate(libraries: List[Dict]) -> List[Dict]:
    """Deduplicate library list by name."""
    seen = set()
    unique = []
    for lib in libraries:
        name = lib.get("library", "")
        if name and name not in seen:
            seen.add(name)
            unique.append(lib)
    return unique


# =============================================================================
# LLM Categorization
# =============================================================================

# Categorization responses are richer (category + confidence + reason per library)
# so they need ~120 tokens per item vs validation's default 60.
CATEGORIZATION_TOKENS_PER_LIB: int = 120


def _categorize_batch(libraries: List[Dict]) -> List[Dict]:
    """Categorize a single batch using shared LLM call with tagged items."""
    return call_llm_batch(
        items=libraries,
        system_prompt=LLM_CATEGORIZATION_PROMPT,
        user_message="Categorize these libraries:",
        item_formatter=lambda lib: f"[{lib['tag']}] {lib['library']}",
        max_tokens_per_item=CATEGORIZATION_TOKENS_PER_LIB
    )


# =============================================================================
# Result Building
# =============================================================================

def _build_result(
    ai_libraries: List[Dict],
    api_libraries: List[Dict],
    categorizations: List[Dict]
) -> Dict:
    """Build combined categorization result from single LLM response.
    
    For BOTH libraries, the LLM returns two entries (one AI category, one API category).
    We build separate lookups: AI-valid entries go to ai_cat_map, API-valid to api_cat_map.
    """
    # Split categorizations into AI and API lookups
    # A BOTH lib like openai will have 2 entries: one with AI_PROVIDER, one with HTTP_CLIENT
    ai_cat_map = {}   # lib_name_lower -> cat_data (for AI-valid categories)
    api_cat_map = {}  # lib_name_lower -> cat_data (for API-valid categories)
    
    for c in categorizations:
        lib_key = c.get("library", "").lower()
        raw_cat = c.get("category", "UNKNOWN").upper().replace(" ", "_")
        
        if raw_cat in VALID_CATEGORIES:
            ai_cat_map[lib_key] = c
        elif raw_cat in VALID_API_CATEGORIES:
            api_cat_map[lib_key] = c
        else:
            # UNKNOWN or unrecognized — put in whichever doesn't have it yet
            if lib_key not in ai_cat_map:
                ai_cat_map[lib_key] = c
            if lib_key not in api_cat_map:
                api_cat_map[lib_key] = c

    # Build AI categories
    ai_categories = {cat: [] for cat in VALID_CATEGORIES}
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        cat_data = ai_cat_map.get(lib_name.lower())
        entry = _build_entry(lib, cat_data, VALID_CATEGORIES)
        ai_categories[entry["_category"]].append(entry["data"])

    # Build API categories
    api_categories = {cat: [] for cat in VALID_API_CATEGORIES}
    for lib in api_libraries:
        lib_name = lib.get("library", "")
        cat_data = api_cat_map.get(lib_name.lower())
        entry = _build_entry(lib, cat_data, VALID_API_CATEGORIES)
        api_categories[entry["_category"]].append(entry["data"])

    return {
        "ai_categories": {
            cat.lower(): {"count": len(libs), "libraries": libs}
            for cat, libs in ai_categories.items()
        },
        "api_categories": {
            cat.lower(): {"count": len(libs), "libraries": libs}
            for cat, libs in api_categories.items()
        },
        "total_ai_libraries": len(ai_libraries),
        "total_api_libraries": len(api_libraries),
        "model_used": LLM_MODEL,
        # Keep backward-compatible keys for downstream (ai-branch-trace)
        "by_category": {
            cat.lower(): {"count": len(libs), "libraries": libs}
            for cat, libs in ai_categories.items()
        },
        "total_libraries": len(ai_libraries),
    }


def _build_entry(lib: Dict, cat_data: Optional[Dict], valid_set: frozenset) -> Dict:
    """Build a single categorized entry."""
    if cat_data:
        raw_cat = cat_data.get("category", "UNKNOWN")
        category = raw_cat.upper().replace(" ", "_")
        if category not in valid_set:
            category = "UNKNOWN"
        confidence = cat_data.get("confidence", "LOW")
        reason = cat_data.get("reason", "")
    else:
        category = "UNKNOWN"
        confidence = "LOW"
        reason = "Categorization failed"

    return {
        "_category": category,
        "data": {
            "library": lib.get("library", ""),
            "source_files": lib.get("source_files", []),
            "import_details": lib.get("import_details", []),
            "language": lib.get("language"),
            "confidence": confidence,
            "reason": reason,
        }
    }


def _empty_result() -> Dict:
    """Return empty combined structure."""
    return {
        "ai_categories": {
            cat.lower(): {"count": 0, "libraries": []}
            for cat in VALID_CATEGORIES
        },
        "api_categories": {
            cat.lower(): {"count": 0, "libraries": []}
            for cat in VALID_API_CATEGORIES
        },
        "total_ai_libraries": 0,
        "total_api_libraries": 0,
        "model_used": LLM_MODEL,
        # Backward-compatible
        "by_category": {
            cat.lower(): {"count": 0, "libraries": []}
            for cat in VALID_CATEGORIES
        },
        "total_libraries": 0,
    }
