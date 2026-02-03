"""
LLM Categorizer for AI Library Classification
Categorizes AI-positive libraries into specific types using Groq LLM.

Reuses shared LLM infrastructure from llm_validator.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

from config import (
    LLM_CATEGORIZATION_PROMPT,
    VALID_CATEGORIES,
)

# Reuse shared components from llm_validator
from llm_validator import (
    call_llm_batch,
    process_in_batches,
    LLM_MODEL,
)
# =============================================================================
# Entry Point
# =============================================================================

def run_categorization(ai_libraries: List[Dict]) -> Optional[Dict]:
    """
    Main categorization function.
    Args:
        ai_libraries: List of AI-positive libraries from /llm-validate
    Returns:
        Categorization result or None if failed
    """
    if not ai_libraries:
        return _empty_categories()
    
    # Deduplicate by library name (single pass)
    seen = set()
    unique_libs = []
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        if lib_name and lib_name not in seen:
            seen.add(lib_name)
            unique_libs.append(lib)
    
    logger.info(f"Categorizing {len(unique_libs)} AI libraries...")
    
    # Categorize with LLM using shared batch processor
    categorizations = process_in_batches(unique_libs, _categorize_batch)
    
    if not categorizations:
        return None
    
    # Build result
    return _build_categorization_result(ai_libraries, categorizations)


# =============================================================================
# LLM Categorization
# =============================================================================

def _categorize_batch(libraries: List[Dict]) -> List[Dict]:
    """Categorize a single batch using shared LLM call."""
    return call_llm_batch(
        items=libraries,
        system_prompt=LLM_CATEGORIZATION_PROMPT,
        user_message="Categorize these AI/ML libraries:",
        item_formatter=lambda lib: lib["library"]  # Extract name from dict
    )


# =============================================================================
# Result Building
# =============================================================================

def _build_categorization_result(
    ai_libraries: List[Dict],
    categorizations: List[Dict]
) -> Dict:
    """Build categorization result in single pass."""
    # Create lookup (case-insensitive)
    cat_map = {c.get("library", "").lower(): c for c in categorizations}
    
    # Initialize categories with empty lists
    categories = {cat: [] for cat in VALID_CATEGORIES}
    
    # Categorize each library (single pass)
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        cat_data = cat_map.get(lib_name.lower())
        
        # Determine category
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
        
        categories[category].append({
            "library": lib_name,
            "source_files": lib.get("source_files", []),
            "language": lib.get("language"),
            "confidence": confidence,
            "reason": reason
        })
    
    # Build response (dict comprehension)
    return {
        "by_category": {
            cat.lower(): {"count": len(libs), "libraries": libs}
            for cat, libs in categories.items()
        },
        "total_libraries": len(ai_libraries),
        "model_used": LLM_MODEL
    }


def _empty_categories() -> Dict:
    """Return empty category structure."""
    return {
        "by_category": {
            cat.lower(): {"count": 0, "libraries": []}
            for cat in VALID_CATEGORIES
        },
        "total_libraries": 0,
        "model_used": LLM_MODEL
    }
