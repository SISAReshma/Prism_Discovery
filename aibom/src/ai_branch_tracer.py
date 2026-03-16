"""
AI Branch Tracer Module
Traces AI library dependencies through the codebase using dependency graph.
This module:
1. Uses dependency graph to find all files that import AI libraries (direct + transitive)
2. Returns branches showing AI usage flow through the codebase
"""

import logging
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime

from aibom.config import normalize_path, LANGUAGE_EXTENSIONS
from aibom.src.dependency_graph import (
    build_graph_index,
    build_reverse_adjacency,
    find_node_by_file,
    trace_importers
)

logger = logging.getLogger(__name__)
# Pre-build reverse mapping: extension -> language (O(1) lookup vs O(L) search)
_EXT_TO_LANG: Dict[str, str] = {
    ext: lang
    for lang, extensions in LANGUAGE_EXTENSIONS.items()
    for ext in extensions
}


def get_language_from_files(files: List[str], default: str = "python") -> str:
    """
    Determine primary language from a list of files using extension counts.
    """
    if not files:
        return default
    
    # Count files per language using O(1) lookup
    lang_counts: Dict[str, int] = {}
    
    for f in files:
        ext = Path(f).suffix.lower()
        lang = _EXT_TO_LANG.get(ext)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    
    # Return language with max count, or default if no matches
    return max(lang_counts, key=lang_counts.get) if lang_counts else default

# =============================================================================
# BRANCH BUILDING
# =============================================================================

def _normalize_source_files(lib: Dict) -> List[str]:
    """Extract and normalize source files from library data."""
    source_files = lib.get("source_files") or lib.get("import_details", {}).get("source_files", [])
    return [normalize_path(f) for f in source_files if f]


def _create_branch_entry(
    lib_name: str,
    category: str,
    language: str,
    source_files: List[str],
    traced_files: Set[str],
    import_details: List[Dict] = None,
    error: str = None
) -> Dict:
    """Create a standardized branch entry dict."""
    entry = {
        "library": lib_name,
        "category": category,
        "language": language,
        "source_files": source_files,
        "import_details": import_details or [],
        "traced_files": sorted(traced_files) if traced_files else [],
        "branch_size": len(traced_files),
    }
    # Only include error when it has a real value — avoids "error": null in JSON
    if error:
        entry["error"] = error
    return entry

def build_ai_branches(
    dependency_graph: Dict,
    categorization_data: Dict
) -> Dict[str, Dict]:
    """
    Build AI branches by tracing dependencies for each AI library.
    For each categorized AI library:
    1. Get source files where the library is imported
    2. Trace backward through dependency graph to find all files that use it
    """
    # Pre-build indexes ONCE (O(N) + O(E)) - shared across all libraries
    graph_index = build_graph_index(dependency_graph)
    reverse_adj = build_reverse_adjacency(dependency_graph)
    
    ai_branches = {}
    by_category = categorization_data.get("by_category", {})
    
    # Iterate through categories and libraries
    for cat_key, cat_data in by_category.items():
        category = cat_key.upper()
        libraries = cat_data.get("libraries", [])
        
        for lib in libraries:
            lib_name = lib.get("library")
            if not lib_name:
                continue
            
            # Extract and normalize source files
            source_files = _normalize_source_files(lib)
            import_details = lib.get("import_details", [])
            
            # Early exit for no source files
            if not source_files:
                language = "python"  # Default when no files to analyze
                ai_branches[lib_name] = _create_branch_entry(
                    lib_name, category, language, [],
                    set(), import_details=import_details,
                    error="No source files found for library"
                )
                continue
            
            # Determine primary language from source files
            language = get_language_from_files(source_files)
            
            # Trace backward dependencies using pre-built indexes
            all_traced_files: Set[str] = set()
            
            for source_file in source_files:
                node_id = find_node_by_file(dependency_graph, source_file, graph_index)
                
                if node_id:
                    # Trace using shared indexes (no rebuild per file)
                    traced = trace_importers(
                        dependency_graph, node_id,
                        index=graph_index, reverse_adj=reverse_adj
                    )
                    all_traced_files.update(traced)
                else:
                    # If not found in graph, include source file itself
                    all_traced_files.add(source_file)
            
            ai_branches[lib_name] = _create_branch_entry(
                lib_name, category, language,
                source_files, all_traced_files,
                import_details=import_details
            )
    
    return ai_branches


def build_api_branches(
    dependency_graph: Dict,
    categorization_data: Dict
) -> Dict[str, Dict]:
    """
    Build API branches by tracing dependencies for each API library.
    Same logic as build_ai_branches but uses api_categories from categorization data.
    """
    graph_index = build_graph_index(dependency_graph)
    reverse_adj = build_reverse_adjacency(dependency_graph)

    api_branches = {}
    api_categories = categorization_data.get("api_categories", {})

    for cat_key, cat_data in api_categories.items():
        category = cat_key.upper()
        libraries = cat_data.get("libraries", [])

        for lib in libraries:
            lib_name = lib.get("library")
            if not lib_name:
                continue

            source_files = _normalize_source_files(lib)
            import_details = lib.get("import_details", [])

            if not source_files:
                language = "python"
                api_branches[lib_name] = _create_branch_entry(
                    lib_name, category, language, [],
                    set(), import_details=import_details,
                    error="No source files found for library"
                )
                continue

            language = get_language_from_files(source_files)

            all_traced_files: Set[str] = set()
            for source_file in source_files:
                node_id = find_node_by_file(dependency_graph, source_file, graph_index)
                if node_id:
                    traced = trace_importers(
                        dependency_graph, node_id,
                        index=graph_index, reverse_adj=reverse_adj
                    )
                    all_traced_files.update(traced)
                else:
                    all_traced_files.add(source_file)

            api_branches[lib_name] = _create_branch_entry(
                lib_name, category, language,
                source_files, all_traced_files,
                import_details=import_details
            )

    return api_branches

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def _compute_summary(ai_branches: Dict[str, Dict]) -> Dict:
    """
    Compute summary statistics from branches in a single pass.
    """
    total_source = 0
    total_traced = 0
    by_category: Dict[str, Dict[str, int]] = {}
    by_language: Dict[str, Dict[str, int]] = {}
    
    for branch in ai_branches.values():
        cat = branch.get("category", "UNKNOWN")
        lang = branch.get("language", "unknown")
        branch_size = branch.get("branch_size", 0)
        source_count = len(branch.get("source_files", []))
        
        total_source += source_count
        total_traced += branch_size
        
        # Group by category (minimize dict operations)
        if cat not in by_category:
            by_category[cat] = {"count": 0, "total_files": 0}
        cat_stats = by_category[cat]
        cat_stats["count"] += 1
        cat_stats["total_files"] += branch_size
        
        # Group by language
        if lang not in by_language:
            by_language[lang] = {"count": 0, "total_files": 0}
        lang_stats = by_language[lang]
        lang_stats["count"] += 1
        lang_stats["total_files"] += branch_size
    
    return {
        "total_branches": len(ai_branches),
        "total_source_files": total_source,
        "total_traced_files": total_traced,
        "by_category": by_category,
        "by_language": by_language,
        "timestamp": datetime.now().isoformat()
    }


def trace_ai_branches(
    checkout_dir: str,
    dependency_graph: Dict,
    categorization_data: Dict
) -> Dict:
    """
    Main function to trace AI and API branches through the codebase.
    Called by the /ai-branch-trace endpoint.
    
    Traces both AI library branches (from ai_categories / by_category)
    and API library branches (from api_categories).
    
    Args:
        checkout_dir: Base directory (currently unused but kept for API compatibility)
        dependency_graph: Pre-built dependency graph
        categorization_data: Unified categorization results (ai_categories + api_categories)
    
    Returns:
        Dict with ai_branches, api_branches, and summary statistics
    """
    ai_branches = build_ai_branches(dependency_graph, categorization_data)
    api_branches = build_api_branches(dependency_graph, categorization_data)

    empty_summary = {
        "total_branches": 0,
        "total_source_files": 0,
        "total_traced_files": 0,
        "by_category": {},
        "by_language": {},
        "timestamp": datetime.now().isoformat()
    }

    return {
        # AI branches
        "branches": ai_branches,
        "summary": _compute_summary(ai_branches) if ai_branches else empty_summary,
        # API branches
        "api_branches": api_branches,
        "api_summary": _compute_summary(api_branches) if api_branches else empty_summary,
    }

def format_branch_summary(result: Dict) -> List[Dict]:
    """
    Format branches for API response summary (sorted by branch size).
    """
    branches = result.get("branches", {})
    
    # Build summary list with all required fields
    # Only include error/semgrep_rule when they have real values — avoids null in JSON
    summary = []
    for lib_name, branch in branches.items():
        item = {
            "library": lib_name,
            "category": branch.get("category", "UNKNOWN"),
            "language": branch.get("language", "unknown"),
            "branch_size": branch.get("branch_size", 0),
            "source_files": branch.get("source_files", []),
            "import_details": branch.get("import_details", []),
            "traced_files": branch.get("traced_files", []),
        }
        if branch.get("error"):
            item["error"] = branch["error"]
        if branch.get("semgrep_rule"):
            item["semgrep_rule"] = branch["semgrep_rule"]
        summary.append(item)
    
    # Sort by branch size descending (single pass)
    summary.sort(key=lambda x: x["branch_size"], reverse=True)
    return summary
