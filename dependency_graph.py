"""
Dependency Graph Generator
Builds file-to-file import dependency graph from semgrep scan results.
Uses session data directly - no file I/O needed.
"""

from pathlib import Path
from typing import Dict, List, Set, Optional


def normalize_path(path: str) -> str:
    """Normalize file path to use forward slashes and extract relative path."""
    p = Path(path)
    parts = p.parts
    
    # Try to extract path after 'checkout' or temp directory markers
    for i, part in enumerate(parts):
        # Look for aibom_ temp directory marker, take the repo folder contents
        if 'aibom_' in part and i + 1 < len(parts):
            # The next part should be the repo name, and after that is the actual code
            if i + 2 < len(parts):
                # Return everything after the repo name (the actual code structure)
                relative_parts = parts[i + 2:]
                if relative_parts:
                    return '/'.join(relative_parts)
            # Or just everything after aibom_xxx/
            relative_parts = parts[i + 1:]
            if relative_parts:
                return '/'.join(relative_parts)
        # Look for checkout marker
        if part == 'checkout' and i + 1 < len(parts):
            relative_parts = parts[i + 1:]
            if relative_parts:
                return '/'.join(relative_parts)
    
    # If no temp markers found, try to return a reasonable relative path
    # Look for common source markers
    for marker in ['src', 'lib', 'app', 'components', 'scripts', 'pages', 'api']:
        if marker in parts:
            idx = parts.index(marker)
            return '/'.join(parts[idx:])
    
    # Fallback: return last 3-4 path components or the full filename
    if len(parts) > 3:
        return '/'.join(parts[-3:])
    elif len(parts) > 1:
        return '/'.join(parts[-2:])
    
    return p.name


def is_local_import(
    base_package: str,
    imported_item: Optional[str],
    code_tokens: Set[str]
) -> bool:
    """Check if import is local based on code tokens."""
    if not base_package:
        return False
    if base_package in code_tokens:
        return True
    if imported_item and imported_item in code_tokens:
        return True
    return False


def build_dependency_graph(
    semgrep_scan: Dict,
    code_tokens: Set[str]
) -> Dict:
    """
    Build dependency graph from semgrep scan results.
    
    Args:
        semgrep_scan: Semgrep scan results by language
        code_tokens: Set of folder/file names from code files
        
    Returns:
        Dependency graph with nodes, edges, and metadata
    """
    graph = {
        "nodes": [],
        "edges": [],
        "metadata": {
            "total_files": 0,
            "total_dependencies": 0,
            "local_imports": 0,
            "external_imports": 0,
            "by_language": {}
        }
    }
    
    file_imports: Dict[str, Dict] = {}
    all_files: Set[str] = set()
    
    # Process imports from all languages dynamically
    for lang, lang_data in semgrep_scan.items():
        if not isinstance(lang_data, dict):
            continue
        
        lang_stats = {"files": 0, "local": 0, "external": 0}
        
        for category in ["third_party", "builtin", "relative"]:
            for imp in lang_data.get(category, []):
                file_path = normalize_path(imp.get("file", ""))
                if not file_path:
                    continue
                
                all_files.add(file_path)
                
                if file_path not in file_imports:
                    file_imports[file_path] = {
                        "local": set(),
                        "external": set(),
                        "language": lang
                    }
                
                base_package = imp.get("base_package", "")
                imported_item = imp.get("imported_item")
                is_relative = imp.get("is_relative", False)
                
                # Classify import
                if category == "relative" or is_relative:
                    target = imported_item or base_package
                    if target:
                        file_imports[file_path]["local"].add(target)
                        lang_stats["local"] += 1
                elif is_local_import(base_package, imported_item, code_tokens):
                    file_imports[file_path]["local"].add(base_package)
                    lang_stats["local"] += 1
                elif base_package:
                    file_imports[file_path]["external"].add(base_package)
                    lang_stats["external"] += 1
        
        lang_stats["files"] = len([f for f, info in file_imports.items() if info.get("language") == lang])
        graph["metadata"]["by_language"][lang] = lang_stats
    
    # Create nodes
    node_index = {}
    for idx, file_path in enumerate(sorted(all_files)):
        node_id = f"file_{idx}"
        node_index[file_path] = node_id
        
        file_info = file_imports.get(file_path, {"local": set(), "external": set(), "language": "unknown"})
        
        graph["nodes"].append({
            "id": node_id,
            "file": file_path,
            "language": file_info.get("language", "unknown"),
            "local_import_count": len(file_info["local"]),
            "external_import_count": len(file_info["external"]),
            "external_imports": sorted(file_info["external"])
        })
    
    # Create edges for local imports (file-to-file dependencies)
    for file_path, imports_info in file_imports.items():
        source_id = node_index.get(file_path)
        if not source_id:
            continue
        
        for local_import in imports_info["local"]:
            # Match import to target file
            local_stem = Path(local_import).stem.replace(".py", "").replace(".js", "")
            
            for target_file, target_id in node_index.items():
                target_stem = Path(target_file).stem
                if target_stem == local_stem:
                    graph["edges"].append({
                        "source": source_id,
                        "target": target_id,
                        "type": "import"
                    })
                    break
    
    # Update metadata
    graph["metadata"]["total_files"] = len(all_files)
    graph["metadata"]["total_dependencies"] = len(graph["edges"])
    graph["metadata"]["local_imports"] = sum(len(info["local"]) for info in file_imports.values())
    graph["metadata"]["external_imports"] = sum(len(info["external"]) for info in file_imports.values())
    
    return graph
