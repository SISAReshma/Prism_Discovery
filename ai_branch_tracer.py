"""
AI Branch Tracer Module
Traces AI library dependencies through the codebase using dependency graph.

This module:
1. Uses dependency graph to find all files that import AI libraries (direct + transitive)
2. Returns branches showing AI usage flow through the codebase
3. Determines appropriate semgrep rules based on language and category

Note: Actual semgrep scanning is done in the next endpoint (/ai-targeted-scan)
"""

import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from collections import deque
from datetime import datetime


# =============================================================================
# PATH UTILITIES
# =============================================================================

def normalize_path(path: str) -> str:
    """Normalize path separators and remove leading ./"""
    if not path:
        return ""
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def get_language_from_files(files: List[str]) -> str:
    """Determine primary language from a list of files."""
    python_exts = {'.py', '.pyx', '.pyi', '.ipynb'}
    js_exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
    
    py_count = 0
    js_count = 0
    
    for f in files:
        f_lower = f.lower()
        for ext in python_exts:
            if f_lower.endswith(ext):
                py_count += 1
                break
        for ext in js_exts:
            if f_lower.endswith(ext):
                js_count += 1
                break
    
    return "javascript" if js_count > py_count else "python"


def get_semgrep_dir() -> Path:
    """Get the semgrep rules directory path dynamically."""
    module_dir = Path(__file__).parent.resolve()
    
    # Try various locations - prioritize local semgrep folder
    candidates = [
        module_dir / "semgrep",  # Local to endpoints
        module_dir.parent / "Prism-AIBOM" / "semgrep",
        module_dir.parent / "semgrep",
        Path.cwd().parent / "Prism-AIBOM" / "semgrep"
    ]
    
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    
    return candidates[0]  # Default fallback


def discover_available_rules(semgrep_dir: Path) -> Dict[str, Dict[str, List[str]]]:
    """
    Discover available semgrep rules dynamically from the directory.
    
    Returns:
        Dict with structure: {
            "python": {"provider": [...], "model_detection": [...]},
            "javascript": {"provider": [...], "model_detection": [...]}
        }
    """
    rules = {
        "python": {"provider": [], "model_detection": []},
        "javascript": {"provider": [], "model_detection": []}
    }
    
    if not semgrep_dir.exists():
        return rules
    
    # Check root level
    for yml_file in semgrep_dir.glob("*.yml"):
        name = yml_file.name.lower()
        if "model_detection" in name:
            if "python" in name:
                rules["python"]["model_detection"].append(yml_file.name)
            elif "javascript" in name:
                rules["javascript"]["model_detection"].append(yml_file.name)
        elif "provider" in name or "rules" in name:
            if "_js" in name or "javascript" in name:
                rules["javascript"]["provider"].append(yml_file.name)
            else:
                rules["python"]["provider"].append(yml_file.name)
    
    # Check language subdirectories
    python_dir = semgrep_dir / "python"
    if python_dir.exists():
        for yml_file in python_dir.glob("*.yml"):
            name = yml_file.name.lower()
            if "model_detection" in name:
                rules["python"]["model_detection"].append(f"python/{yml_file.name}")
            elif "provider" in name:
                rules["python"]["provider"].append(f"python/{yml_file.name}")
    
    js_dir = semgrep_dir / "javascript"
    if js_dir.exists():
        for yml_file in js_dir.glob("*.yml"):
            name = yml_file.name.lower()
            if "model_detection" in name:
                rules["javascript"]["model_detection"].append(f"javascript/{yml_file.name}")
            elif "provider" in name:
                rules["javascript"]["provider"].append(f"javascript/{yml_file.name}")
    
    return rules


def get_rule_for_category(
    category: str,
    lib_name: str,
    language: str,
    available_rules: Dict
) -> Optional[str]:
    """
    Determine appropriate semgrep rule for a library based on category and language.
    
    Args:
        category: AI category (AI_PROVIDER, AI_ORCHESTRATION, etc.)
        lib_name: Library name for provider-specific matching
        language: Primary language (python/javascript)
        available_rules: Available rules from discover_available_rules()
    
    Returns:
        Rule file path relative to semgrep dir, or None
    """
    lang_rules = available_rules.get(language, {})
    provider_rules = lang_rules.get("provider", [])
    model_rules = lang_rules.get("model_detection", [])
    
    lib_lower = lib_name.lower()
    cat_upper = category.upper()
    
    # For AI_PROVIDER and AI_ORCHESTRATION, try to match provider-specific rules
    if cat_upper in ("AI_PROVIDER", "AI_ORCHESTRATION", "AI_EMBEDDING", "AI_FRAMEWORK"):
        # Check for provider-specific rule - extended keywords
        provider_keywords = [
            "openai", "anthropic", "google", "cohere", "replicate", 
            "huggingface", "langchain", "pinecone", "ai", "ai_sdk"
        ]
        
        for keyword in provider_keywords:
            if keyword in lib_lower or lib_lower in keyword:
                # Find matching rule
                for rule in provider_rules:
                    if keyword in rule.lower():
                        return rule
    
    # Fall back to model detection rules
    if model_rules:
        return model_rules[0]
    
    return None


# =============================================================================
# DEPENDENCY GRAPH TRAVERSAL
# =============================================================================

def find_file_node(graph: Dict, file_path: str) -> Optional[str]:
    """
    Find node ID for a given file path in the dependency graph.
    
    Handles path normalization and partial matching.
    Uses strict matching to avoid false positives with common filenames like route.ts.
    """
    normalized = normalize_path(file_path)
    
    # Extract just the relative path if it's absolute
    if "/" in normalized:
        parts = normalized.split("/")
        # Try to find common project markers
        for marker in ["src", "lib", "app", "components", "scripts"]:
            if marker in parts:
                idx = parts.index(marker)
                normalized = "/".join(parts[idx:])
                break
    
    nodes = graph.get("nodes", [])
    
    # PASS 1: Exact match (highest priority)
    for node in nodes:
        node_file = normalize_path(node.get("file", ""))
        if node_file == normalized:
            return node.get("id")
    
    # PASS 2: Suffix match - but require significant path overlap
    # To avoid matching "qa-pinecone/route.ts" to "qa-pg-vector/route.ts"
    best_match = None
    best_match_len = 0
    
    for node in nodes:
        node_file = normalize_path(node.get("file", ""))
        
        if node_file.endswith(normalized):
            # The search path is a suffix of the node path - good match
            if len(normalized) > best_match_len:
                best_match = node.get("id")
                best_match_len = len(normalized)
        elif normalized.endswith(node_file):
            # The node path is a suffix of the search path - good match
            if len(node_file) > best_match_len:
                best_match = node.get("id")
                best_match_len = len(node_file)
    
    if best_match:
        return best_match
    
    # PASS 3: Match by parent directory + filename (avoid matching just "route.ts")
    # This requires at least the immediate parent directory to match
    if "/" in normalized:
        search_parent_and_file = "/".join(normalized.split("/")[-2:])  # e.g., "qa-pinecone/route.ts"
        
        for node in nodes:
            node_file = normalize_path(node.get("file", ""))
            if node_file.endswith(search_parent_and_file):
                return node.get("id")
    
    # DO NOT match by filename alone - too many false positives (route.ts, index.ts, etc.)
    
    return None


def trace_backward_dependencies(
    graph: Dict,
    source_node_id: str,
    max_depth: int = 50
) -> Set[str]:
    """
    BFS traversal to find all files that import the source file (directly or indirectly).
    
    Args:
        graph: Dependency graph with nodes and edges
        source_node_id: Starting node ID to trace from
        max_depth: Maximum traversal depth
    
    Returns:
        Set of file paths that depend on the source file (including source itself)
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    # Build node_id -> file mapping (uses 'file' key)
    node_to_file = {n.get("id"): n.get("file", "") for n in nodes}
    
    # Build reverse adjacency (who imports whom)
    # Edge: source imports target, so we want files that import source_node
    importers = {}  # node_id -> [nodes that import it]
    for edge in edges:
        target = edge.get("target")
        source = edge.get("source")
        if target not in importers:
            importers[target] = []
        importers[target].append(source)
    
    # BFS from source node
    visited = {source_node_id}
    queue = deque([(source_node_id, 0)])
    
    while queue:
        node_id, depth = queue.popleft()
        
        if depth >= max_depth:
            continue
        
        # Get all files that import this node
        for importer_id in importers.get(node_id, []):
            if importer_id not in visited:
                visited.add(importer_id)
                queue.append((importer_id, depth + 1))
    
    # Convert node IDs to file paths
    traced_files = set()
    for node_id in visited:
        file_path = node_to_file.get(node_id, "")
        if file_path:
            traced_files.add(file_path)
    
    return traced_files


# =============================================================================
# BRANCH BUILDING
# =============================================================================

def build_ai_branches(
    dependency_graph: Dict,
    categorization_data: Dict
) -> Dict[str, Dict]:
    """
    Build AI branches by tracing dependencies for each AI library.
    
    For each categorized AI library:
    1. Get source files where the library is imported
    2. Trace backward through dependency graph to find all files that use it
    3. Determine appropriate semgrep rule based on language and category
    
    Args:
        dependency_graph: Output from /dependency-graph endpoint
        categorization_data: Output from /llm-categorize endpoint
    
    Returns:
        Dict mapping library names to branch data
    """
    # Discover available rules dynamically
    semgrep_dir = get_semgrep_dir()
    available_rules = discover_available_rules(semgrep_dir)
    
    ai_branches = {}
    
    # Iterate through categories
    for cat_key, cat_data in categorization_data.get("by_category", {}).items():
        libraries = cat_data.get("libraries", [])
        
        # Category is the key (e.g., "ai_provider"), convert to uppercase
        category = cat_key.upper()
        
        for lib in libraries:
            lib_name = lib.get("library", "")
            if not lib_name:
                continue
            
            # Get source files - try multiple locations
            source_files = lib.get("source_files", [])
            if not source_files:
                import_details = lib.get("import_details", {})
                source_files = import_details.get("source_files", [])
            
            # Normalize source file paths
            source_files = [normalize_path(f) for f in source_files if f]
            
            # Determine primary language from source files
            language = get_language_from_files(source_files) if source_files else "python"
            
            # Get appropriate semgrep rule
            semgrep_rule = get_rule_for_category(category, lib_name, language, available_rules)
            
            if not source_files:
                ai_branches[lib_name] = {
                    "library": lib_name,
                    "category": category,
                    "language": language,
                    "semgrep_rule": semgrep_rule,
                    "source_files": [],
                    "traced_files": [],
                    "branch_size": 0,
                    "error": "No source files found for library"
                }
                continue
            
            # Trace backward dependencies for each source file
            all_traced_files = set()
            
            for source_file in source_files:
                node_id = find_file_node(dependency_graph, source_file)
                
                if node_id:
                    # Trace all files that depend on this source
                    traced = trace_backward_dependencies(dependency_graph, node_id)
                    all_traced_files.update(traced)
                else:
                    # If not found in graph, include source file itself
                    all_traced_files.add(source_file)
            
            ai_branches[lib_name] = {
                "library": lib_name,
                "category": category,
                "language": language,
                "semgrep_rule": semgrep_rule,
                "source_files": source_files,
                "traced_files": sorted(list(all_traced_files)),
                "branch_size": len(all_traced_files),
                "error": None
            }
    
    return ai_branches


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def trace_ai_branches(
    checkout_dir: str,
    dependency_graph: Dict,
    categorization_data: Dict
) -> Dict:
    """
    Main function to trace AI branches through the codebase.
    
    Called by the /ai-branch-trace endpoint.
    
    Args:
        checkout_dir: Path to checked out code (for reference)
        dependency_graph: Output from /dependency-graph endpoint
        categorization_data: Output from /llm-categorize endpoint
    
    Returns:
        Branch trace results (without scan data - scanning is next endpoint)
    """
    # Build AI branches from categorization + dependency graph
    ai_branches = build_ai_branches(dependency_graph, categorization_data)
    
    if not ai_branches:
        return {
            "branches": {},
            "summary": {
                "total_branches": 0,
                "total_source_files": 0,
                "total_traced_files": 0,
                "by_category": {},
                "by_language": {},
                "timestamp": datetime.now().isoformat()
            }
        }
    
    # Compute summary statistics
    total_source = sum(len(b.get("source_files", [])) for b in ai_branches.values())
    total_traced = sum(b.get("branch_size", 0) for b in ai_branches.values())
    
    # Group by category
    by_category = {}
    for branch in ai_branches.values():
        cat = branch.get("category", "UNKNOWN")
        if cat not in by_category:
            by_category[cat] = {"count": 0, "total_files": 0}
        by_category[cat]["count"] += 1
        by_category[cat]["total_files"] += branch.get("branch_size", 0)
    
    # Group by language
    by_language = {}
    for branch in ai_branches.values():
        lang = branch.get("language", "unknown")
        if lang not in by_language:
            by_language[lang] = {"count": 0, "total_files": 0}
        by_language[lang]["count"] += 1
        by_language[lang]["total_files"] += branch.get("branch_size", 0)
    
    return {
        "branches": ai_branches,
        "summary": {
            "total_branches": len(ai_branches),
            "total_source_files": total_source,
            "total_traced_files": total_traced,
            "by_category": by_category,
            "by_language": by_language,
            "timestamp": datetime.now().isoformat()
        }
    }


def format_branch_summary(result: Dict) -> List[Dict]:
    """Format branches for API response summary (sorted by branch size)."""
    summary = []
    
    branches = result.get("branches", {})
    
    for lib_name, branch in branches.items():
        summary.append({
            "library": lib_name,
            "category": branch.get("category", "UNKNOWN"),
            "language": branch.get("language", "unknown"),
            "branch_size": branch.get("branch_size", 0),
            "source_files": branch.get("source_files", []),
            "traced_files": branch.get("traced_files", []),
            "semgrep_rule": branch.get("semgrep_rule"),
            "error": branch.get("error")
        })
    
    # Sort by branch size descending
    summary.sort(key=lambda x: x["branch_size"], reverse=True)
    
    return summary
