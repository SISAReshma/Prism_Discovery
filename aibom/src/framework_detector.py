"""
Framework Detector
Aggregates categorized libraries into framework groups (AI, API, Agentic)
with full sub-import mappings back to the base package.

Consumes output from:
  - /aibom/llm-categorize  (categorization data with ai_categories / api_categories)
  - /aibom/filtered-imports (import_packages with per-package import_details)
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Categories that qualify as "agentic"
_AGENTIC_CATEGORIES = frozenset({"agentic_framework"})

# Categories under the AI umbrella (non-agentic AI)
_AI_CATEGORIES = frozenset({
    "ai_provider", "ml_algorithm", "dl_algorithm",
    "ai_orchestration", "vector_db", "data_processing",
})

# All API categories
_API_CATEGORIES = frozenset({
    "http_client", "api_framework", "graphql",
    "grpc", "websocket", "cloud_sdk", "api_wrapper",
})


def _build_import_lookup(import_packages: Dict) -> Dict[str, Dict]:
    """Build base_package -> {source_files, sub_imports} lookup from import_packages.

    import_packages has keys like python_imports, javascript_imports, etc.
    Each entry: {"package": "openai", "source_files": [...], "import_details": [...]}

    sub_imports are the imported_item values (e.g. OpenAIError, ChatCompletion)
    mapped back to their base package with file/line info.
    """
    lookup: Dict[str, Dict] = {}

    for _key, packages in import_packages.items():
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            name = pkg.get("package", "")
            if not name:
                continue

            if name not in lookup:
                lookup[name] = {"source_files": [], "sub_imports": []}

            # Merge source files (deduplicate)
            for f in pkg.get("source_files", []):
                if f and f not in lookup[name]["source_files"]:
                    lookup[name]["source_files"].append(f)

            # Build sub-import records from import_details
            for detail in pkg.get("import_details", []):
                item = detail.get("imported_item")
                if item:
                    lookup[name]["sub_imports"].append({
                        "item": item,
                        "module": detail.get("module", ""),
                        "file": detail.get("file", ""),
                        "line": detail.get("line", 0),
                    })

    return lookup


def _extract_frameworks_from_categories(
    categories: Dict[str, Dict],
    target_cats: frozenset,
    framework_type: str,
    import_lookup: Dict[str, Dict],
) -> List[Dict]:
    """Walk categorization groups and build framework entries for matching categories."""
    frameworks = []

    for cat_key, cat_data in categories.items():
        if cat_key not in target_cats:
            continue

        for lib in cat_data.get("libraries", []):
            lib_name = lib.get("library", "")
            if not lib_name:
                continue

            pkg_data = import_lookup.get(lib_name, {})

            frameworks.append({
                "base_package": lib_name,
                "category": cat_key.upper(),
                "framework_type": framework_type,
                "confidence": lib.get("confidence", "LOW"),
                "reason": lib.get("reason", ""),
                "source_files": pkg_data.get("source_files", []) or lib.get("source_files", []),
                "sub_imports": pkg_data.get("sub_imports", []),
                "language": lib.get("language"),
            })

    return frameworks


def detect_frameworks(
    categorization_data: Dict,
    import_packages: Dict,
) -> Dict:
    """
    Main entry point — detect and group frameworks by type.

    Args:
        categorization_data: Result from /aibom/llm-categorize
        import_packages: Result from /aibom/filtered-imports (import_packages dict)

    Returns:
        {
            "ai_frameworks": [...],
            "api_frameworks": [...],
            "agentic_frameworks": [...],
            "summary": {
                "total_ai": N,
                "total_api": N,
                "total_agentic": N,
                "total_frameworks": N,
            }
        }
    """
    import_lookup = _build_import_lookup(import_packages)
    ai_categories = categorization_data.get("ai_categories", {})
    api_categories = categorization_data.get("api_categories", {})

    # --- Agentic (subset of ai_categories) ---
    agentic = _extract_frameworks_from_categories(
        ai_categories, _AGENTIC_CATEGORIES, "agentic", import_lookup
    )

    # --- AI (non-agentic AI categories) ---
    ai = _extract_frameworks_from_categories(
        ai_categories, _AI_CATEGORIES, "ai", import_lookup
    )

    # --- API ---
    api = _extract_frameworks_from_categories(
        api_categories, _API_CATEGORIES, "api", import_lookup
    )

    summary = {
        "total_ai": len(ai),
        "total_api": len(api),
        "total_agentic": len(agentic),
        "total_frameworks": len(ai) + len(api) + len(agentic),
    }

    logger.info(
        f"[FRAMEWORKS] Detected {summary['total_ai']} AI, "
        f"{summary['total_api']} API, {summary['total_agentic']} agentic frameworks"
    )

    return {
        "ai_frameworks": ai,
        "api_frameworks": api,
        "agentic_frameworks": agentic,
        "summary": summary,
    }
