"""
LLM Categorizer for AI Library Classification
Categorizes AI-positive libraries detected by llm_validator.

Reuses shared LLM infrastructure from llm_validator.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

from aibom.config import (
    LLM_CATEGORIZATION_PROMPT,
    VALID_CATEGORIES,
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

def run_categorization(ai_libraries: List[Dict]) -> Optional[Dict]:
    """
    Categorize AI libraries into subcategories (AI_PROVIDER, DL_ALGORITHM, etc.).

    Args:
        ai_libraries: List of AI-positive libraries from llm_validator
    Returns:
        Categorization result or None if failed
    """
    if not ai_libraries:
        return _empty_result()

    unique_ai = _deduplicate(ai_libraries)

    logger.info(f"Categorizing {len(unique_ai)} AI libraries in single LLM call...")

    categorizations = process_in_batches(unique_ai, _categorize_batch, batch_size=25)

    if not categorizations:
        return None

    return _build_result(ai_libraries, categorizations)


def _deduplicate(libraries: List[Dict]) -> List[Dict]:
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

CATEGORIZATION_TOKENS_PER_LIB: int = 120


def _categorize_batch(libraries: List[Dict]) -> List[Dict]:
    return call_llm_batch(
        items=libraries,
        system_prompt=LLM_CATEGORIZATION_PROMPT,
        user_message="Categorize these AI libraries:",
        item_formatter=lambda lib: lib["library"],
        max_tokens_per_item=CATEGORIZATION_TOKENS_PER_LIB
    )


# =============================================================================
# Result Building
# =============================================================================

def _build_result(ai_libraries: List[Dict], categorizations: List[Dict]) -> Dict:
    cat_map = {}
    for c in categorizations:
        lib_key = c.get("library", "").lower()
        raw_cat = c.get("category", "UNKNOWN").upper().replace(" ", "_")
        if raw_cat in VALID_CATEGORIES:
            cat_map[lib_key] = c
        elif lib_key not in cat_map:
            cat_map[lib_key] = c

    ai_categories = {cat: [] for cat in VALID_CATEGORIES}
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        cat_data = cat_map.get(lib_name.lower())
        entry = _build_entry(lib, cat_data)
        ai_categories[entry["_category"]].append(entry["data"])

    categorized = {
        cat.lower(): {"count": len(libs), "libraries": libs}
        for cat, libs in ai_categories.items()
    }

    return {
        "ai_categories": categorized,
        "total_ai_libraries": len(ai_libraries),
        "model_used": LLM_MODEL,
        # Backward-compatible key for ai-branch-trace
        "by_category": categorized,
        "total_libraries": len(ai_libraries),
    }


def _build_entry(lib: Dict, cat_data: Optional[Dict]) -> Dict:
    if cat_data:
        raw_cat = cat_data.get("category", "UNKNOWN")
        category = raw_cat.upper().replace(" ", "_")
        if category not in VALID_CATEGORIES:
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
    empty = {cat.lower(): {"count": 0, "libraries": []} for cat in VALID_CATEGORIES}
    return {
        "ai_categories": empty,
        "total_ai_libraries": 0,
        "model_used": LLM_MODEL,
        "by_category": empty,
        "total_libraries": 0,
    }
