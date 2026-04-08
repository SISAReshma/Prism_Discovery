"""
Dependency Graph Generator
Builds file-to-file import dependency graph from semgrep scan results.

Graph Structure:
- nodes: Files with import metadata
- edges: Import relationships (source imports target)
"""
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from collections import deque

from aibom.config import normalize_path, FILE_STEM_EXTENSIONS, PATH_MARKERS


# Pre-compute stripped extensions once (avoid repeated string ops)
_STRIPPED_EXTS: Tuple[str, ...] = tuple(ext.replace(".", "") for ext in FILE_STEM_EXTENSIONS)
_EXT_LENGTHS: Tuple[int, ...] = tuple(len(ext) - 1 for ext in FILE_STEM_EXTENSIONS)  # -1 for the dot


# =============================================================================
# GRAPH BUILDING
# =============================================================================

def _is_local(base: str, item: str, tokens: Set[str]) -> bool:
    """Check if import is local (base_package or imported_item in code_tokens)."""
    return (base in tokens) if base else (item in tokens) if item else False


def _clean_stem(name: str) -> str:
    """Extract clean stem from import/file name. Optimized with pre-computed patterns."""
    stem = Path(name).stem
    # Fast path: check against pre-computed stripped extensions
    for stripped, ext_len in zip(_STRIPPED_EXTS, _EXT_LENGTHS):
        if stem.endswith(stripped):
            return stem[:-ext_len]
    return stem


def build_dependency_graph(
    semgrep_scan: Dict,
    code_tokens: Set[str]
) -> Dict:
    """
    Build dependency graph from semgrep scan results.
    
    Optimizations:
    - Single-pass import collection with aggregated stats
    - Pre-computed stems cached during node building
    - Edge deduplication with set lookups
    - No redundant dict.get() calls in hot paths
    
    Time: O(I + N + E) where I=imports, N=files, E=edges
    Space: O(N + E)
    """
    file_imports: Dict[str, Dict] = {}
    lang_stats: Dict[str, Dict[str, int]] = {}
    
    # Single pass: collect imports + aggregate stats
    for lang, lang_data in semgrep_scan.items():
        if not isinstance(lang_data, dict):
            continue
        
        # Initialize lang stats once
        stats = lang_stats.setdefault(lang, {"files": 0, "local": 0, "external": 0})
        
        for category in ("third_party", "builtin", "relative"):
            if category not in lang_data:  # Skip if category doesn't exist
                continue
                
            for imp in lang_data[category]:
                file_path = normalize_path(imp.get("file", ""))
                if not file_path:
                    continue
                
                # Initialize file entry + increment file count
                if file_path not in file_imports:
                    file_imports[file_path] = {
                        "local": set(), "external": set(), "language": lang
                    }
                    stats["files"] += 1
                
                info = file_imports[file_path]
                base = imp.get("base_package", "")
                item = imp.get("imported_item")
                module = imp.get("module", base)  # Use module name for edge building
                is_rel = category == "relative" or imp.get("is_relative", False)
                
                if is_rel or _is_local(base, item, code_tokens):
                    # Choose the best identifier for edge stem-matching:
                    #
                    # • Go internal imports (e.g. "github.com/8ff/gpt/pkg/foo"):
                    #   module = full path → stem "foo" → matches the file
                    #   base_package = module root "github.com/8ff/gpt" → stem "gpt" → NO match
                    #   → use module when it doesn't start with "."
                    #
                    # • Python relative (".utils", "..models.base"):
                    #   module starts with "." and has no "/" after the dots
                    #   base_package = "utils" / "models" → correct stem → use base
                    #
                    # • JS relative ("./utils", "../utils"):
                    #   module starts with "." but has "/" immediately after
                    #   Path("./utils").stem = "utils" → correct → use module
                    _py_relative = (
                        is_rel
                        and module
                        and module.startswith(".")
                        and "/" not in module.lstrip(".")
                    )
                    target_module = (base if _py_relative else module) or base or module
                    if target_module and target_module not in info["local"]:
                        info["local"].add(target_module)
                        stats["local"] += 1
                elif base and base not in info["external"]:  # Deduplicate at insertion
                    info["external"].add(base)
                    stats["external"] += 1
    
    # Build nodes + pre-compute stem cache for edge building
    nodes = []
    node_index = {}
    stem_cache = {}  # Cache stems to avoid recomputing in edge loop
    
    sorted_items = sorted(file_imports.items())  # Sort once
    for idx, (file_path, info) in enumerate(sorted_items):
        node_id = f"file_{idx}"
        node_index[file_path] = node_id
        
        # Pre-compute and cache stem for this file
        stem = _clean_stem(file_path)
        stem_cache[stem] = node_id
        
        # Don't sort external_imports unless needed (may not be displayed)
        nodes.append({
            "id": node_id,
            "file": file_path,
            "language": info["language"],
            "local_import_count": len(info["local"]),
            "external_import_count": len(info["external"]),
            "external_imports": list(info["external"])  # Keep as list (sort if needed by consumer)
        })
    
    # Build edges using pre-computed stem cache
    edges = []
    seen_edges = set()
    
    for file_path, info in file_imports.items():
        source_id = node_index[file_path]
        local_imports = info["local"]  # Cache the set reference
        
        for local_import in local_imports:
            stem = _clean_stem(local_import)
            target_id = stem_cache.get(stem)
            
            if target_id and target_id != source_id:
                edge_key = (source_id, target_id)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append({"source": source_id, "target": target_id, "type": "import"})
    
    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "total_files": len(nodes),
            "total_dependencies": len(edges),
            "local_imports": sum(s["local"] for s in lang_stats.values()),
            "external_imports": sum(s["external"] for s in lang_stats.values()),
            "by_language": lang_stats
        }
    }


# =============================================================================
# GRAPH RETRIEVAL UTILITIES
# =============================================================================

def build_graph_index(graph: Dict) -> Dict:
    """
    Build lookup indexes for graph nodes. Call once, then use for O(1) lookups.
    
    Returns:
        - by_file: normalized_path -> node_id
        - by_suffix: suffix_key -> [(path_len, node_id), ...]
        - id_to_file: node_id -> file_path
    """
    by_file = {}
    by_suffix = {}
    id_to_file = {}
    
    for node in graph.get("nodes", []):
        node_id = node.get("id")
        file_path = normalize_path(node.get("file", ""))
        
        if not node_id or not file_path:
            continue
        
        by_file[file_path] = node_id
        id_to_file[node_id] = file_path
        
        # Index by last 2 path segments for suffix matching
        parts = file_path.split("/")
        if len(parts) >= 2:
            suffix_key = "/".join(parts[-2:])
            by_suffix.setdefault(suffix_key, []).append((len(file_path), node_id))
    
    return {"by_file": by_file, "by_suffix": by_suffix, "id_to_file": id_to_file}


def build_reverse_adjacency(graph: Dict) -> Dict[str, List[str]]:
    """Build reverse adjacency map: target_node -> [source nodes that import it]."""
    importers: Dict[str, List[str]] = {}
    for edge in graph.get("edges", []):
        target = edge.get("target")
        source = edge.get("source")
        if target and source:
            importers.setdefault(target, []).append(source)
    return importers


def find_node_by_file(
    graph: Dict, 
    file_path: str, 
    index: Optional[Dict] = None
) -> Optional[str]:
    """
    Find node ID for a given file path in the dependency graph.
    
    """
    normalized = normalize_path(file_path)
    
    # Pre-compute parts and suffix once (used in both paths)
    parts = normalized.split("/") if "/" in normalized else None
    suffix_key = "/".join(parts[-2:]) if parts and len(parts) >= 2 else None
    
    # Extract relative path from absolute paths
    if parts:
        # Fast check using set membership
        for i, part in enumerate(parts):
            if part in PATH_MARKERS:
                normalized = "/".join(parts[i:])
                break
    
    # FAST PATH: Use pre-built index
    if index:
        # Direct lookup
        node_id = index["by_file"].get(normalized)
        if node_id:
            return node_id
        
        # Suffix match using pre-computed key
        if suffix_key:
            matches = index["by_suffix"].get(suffix_key)
            if matches:
                # Return longest path match (more specific)
                return max(matches, key=lambda x: x[0])[1]
        return None
    
    # SLOW PATH: Linear search (single pass, pre-computed suffix)
    nodes = graph.get("nodes", [])
    best_match = None
    best_len = 0
    
    for node in nodes:
        node_file = normalize_path(node.get("file", ""))
        node_id = node.get("id")
        
        # Exact match - return immediately
        if node_file == normalized:
            return node_id
        
        # Suffix matching with length priority
        match_len = 0
        if node_file.endswith(normalized):
            match_len = len(normalized)
        elif normalized.endswith(node_file):
            match_len = len(node_file)
        elif suffix_key and node_file.endswith(suffix_key):
            match_len = len(suffix_key)
        
        if match_len > best_len:
            best_match = node_id
            best_len = match_len
    
    return best_match


def trace_importers(
    graph: Dict,
    start_node_id: str,
    max_depth: int = 50,
    index: Optional[Dict] = None,
    reverse_adj: Optional[Dict] = None
) -> Set[str]:
    """
    BFS traversal to find all files that import the start file (directly or transitively).
    
    """
    # Use pre-built structures or build once (not per iteration)
    if index:
        id_to_file = index["id_to_file"]
    else:
        # Build once with dict comprehension (faster than repeated .get())
        id_to_file = {n["id"]: n.get("file", "") for n in graph.get("nodes", []) if "id" in n}
    
    importers = reverse_adj if reverse_adj else build_reverse_adjacency(graph)
    
    # BFS from start node
    visited = {start_node_id}
    queue = deque([(start_node_id, 0)])
    
    while queue:
        node_id, depth = queue.popleft()
        
        if depth >= max_depth:
            continue
        
        # Cache the importers list lookup
        node_importers = importers.get(node_id, [])
        for importer_id in node_importers:
            if importer_id not in visited:
                visited.add(importer_id)
                queue.append((importer_id, depth + 1))
    
    # Convert node IDs to file paths (filter empty in single comprehension)
    return {id_to_file[nid] for nid in visited if nid in id_to_file and id_to_file[nid]}