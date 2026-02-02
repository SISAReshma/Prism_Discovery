"""
AIBOM Semgrep Scanner
Simplified semgrep-based import detection for the AIBOM API.
Runs semgrep rules to detect Python and JavaScript imports.
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional

from config import (
    SEMGREP_MAX_MEMORY_MB,
    SEMGREP_TIMEOUT_SECONDS,
    SEMGREP_RULE_FILES,
    SEMGREP_IMPORT_EXTRACTORS,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
SEMGREP_RULES_DIR = BASE_DIR / "semgrep"

# =============================================================================
# BUILTIN MODULES
# =============================================================================

PYTHON_BUILTINS = {
    "os", "sys", "re", "json", "pathlib", "typing", "collections", "itertools",
    "functools", "datetime", "time", "math", "random", "string", "subprocess",
    "threading", "multiprocessing", "asyncio", "logging", "argparse", "unittest",
    "io", "csv", "pickle", "copy", "warnings", "traceback", "inspect", "ast",
    "importlib", "enum", "dataclasses", "contextlib", "tempfile", "shutil",
    "glob", "gzip", "zipfile", "tarfile", "urllib", "http", "email", "socket",
    "ssl", "sqlite3", "xml", "html", "hashlib", "hmac", "secrets", "uuid",
    "abc", "builtins", "codecs", "configparser", "ctypes", "decimal", "difflib",
    "dis", "doctest", "fileinput", "fnmatch", "fractions", "ftplib", "gc",
    "getopt", "getpass", "gettext", "graphlib", "heapq", "imaplib", "ipaddress",
    "keyword", "linecache", "locale", "mailbox", "mimetypes", "numbers", "operator",
    "struct", "statistics", "textwrap", "weakref", "zoneinfo"
}

JS_BUILTINS = {
    "fs", "path", "http", "https", "url", "os", "util", "events", "stream",
    "crypto", "buffer", "querystring", "readline", "zlib", "child_process",
    "cluster", "dns", "net", "tls", "dgram", "console", "process", "assert",
    "module", "vm", "worker_threads", "perf_hooks", "inspector", "async_hooks",
    "node:fs", "node:path", "node:http", "node:https", "node:url", "node:os",
    "node:util", "node:events", "node:stream", "node:crypto", "node:buffer",
    "node:child_process", "node:process", "node:assert", "node:module",
}


# =============================================================================
# SEMGREP RUNNER
# =============================================================================

def run_semgrep(checkout: Path, rule_file: Path, language: str) -> List[Dict]:
    """Run Semgrep with specific rule file and return findings."""
    if not rule_file.exists():
        return []
    
    cmd = [
        "semgrep",
        "--config", str(rule_file),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--optimizations", "all",
        "--max-memory", str(SEMGREP_MAX_MEMORY_MB),
        str(checkout)
    ]
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=SEMGREP_TIMEOUT_SECONDS,
            cwd=str(checkout)
        )
        
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                return data.get("results", [])
            except json.JSONDecodeError:
                pass
        
        return []
    
    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        # semgrep not installed
        return []
    except Exception:
        return []


# =============================================================================
# IMPORT EXTRACTION
# =============================================================================

def extract_python_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module and imported item from Python import finding."""
    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    
    module_raw = metavars.get("$MODULE", {}).get("abstract_content", "")
    item_raw = metavars.get("$ITEM", {}).get("abstract_content", "")
    
    # If metavars empty, parse from message
    if not module_raw:
        message = extra.get("message", "")
        if " import: from " in message:
            parts = message.split(" import: from ", 1)
            if len(parts) == 2:
                rest = parts[1]
                if " import " in rest:
                    mod_part, item_part = rest.split(" import ", 1)
                    module_raw = mod_part.strip()
                    item_raw = item_part.strip()
        elif " import: " in message:
            parts = message.split(" import: ", 1)
            if len(parts) == 2:
                module_raw = parts[1].strip()
    
    module = module_raw.strip() if module_raw else ""
    item = item_raw.strip() if item_raw else ""
    
    if not module or module == "$MODULE":
        return None
    
    base_package = module.replace(" ", ".").split(".")[0]
    is_builtin = base_package.lower() in PYTHON_BUILTINS
    
    import_type = extra.get("metadata", {}).get("import_type", "unknown")
    is_relative = import_type == "relative-import" or module.startswith(".")
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": item if item else None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "python",
    }


def extract_js_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module from JavaScript/TypeScript import finding."""
    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    
    module = metavars.get("$MODULE", {}).get("abstract_content", "")
    
    # If metavars empty, parse from message
    if not module:
        message = extra.get("message", "")
        if " from " in message:
            parts = message.split(" from ", 1)
            if len(parts) == 2:
                module = parts[1].strip()
        elif " import: " in message or " require: " in message:
            for sep in [" import: ", " require: "]:
                if sep in message:
                    parts = message.split(sep, 1)
                    if len(parts) == 2:
                        module = parts[1].strip()
                        break
    
    module = module.strip().strip('"').strip("'")
    
    if not module or module == "$MODULE":
        return None
    
    # Filter out TypeScript path aliases (@/ is for local imports)
    if module.startswith("@/"):
        return None
    
    # Get base package
    # For scoped packages (@scope/package), use full scope/package as base
    # For sub-paths (langchain/embeddings), extract only the root package
    if module.startswith("@"):
        # Scoped package: @anthropic-ai/sdk or @clerk/nextjs/server
        parts = module.split("/")
        base_package = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else module
    else:
        # Regular package: extract root before any slash
        # langchain/embeddings/openai -> langchain
        # dotenv -> dotenv
        base_package = module.split("/")[0]
    
    is_builtin = base_package in JS_BUILTINS or module in JS_BUILTINS
    is_relative = module.startswith(".") or module.startswith("/")
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": extra.get("metadata", {}).get("import_type", "unknown"),
        "language": "javascript",
    }


# Map language to extractor function
IMPORT_EXTRACTORS = {
    "python": extract_python_import_info,
    "javascript": extract_js_import_info,
}


# =============================================================================
# MAIN SCANNING FUNCTIONS
# =============================================================================

def make_path_relative(file_path: str, checkout: Path) -> str:
    """Convert absolute file path to relative path from checkout root."""
    try:
        from pathlib import Path as PathLib
        abs_path = PathLib(file_path)
        checkout_abs = PathLib(checkout).resolve()
        
        # Try to make it relative to checkout
        try:
            rel_path = abs_path.relative_to(checkout_abs)
            return str(rel_path).replace("\\", "/")
        except ValueError:
            # If path is not relative to checkout, try to find common path
            # This handles WSL paths like /mnt/c/Users/...
            file_str = str(abs_path)
            checkout_str = str(checkout_abs)
            
            # Find common suffix
            if checkout_abs.name in file_str:
                idx = file_str.find(checkout_abs.name)
                if idx != -1:
                    # Extract everything after the checkout directory
                    rel_part = file_str[idx + len(checkout_abs.name):].lstrip("/\\")
                    return rel_part.replace("\\", "/")
            
            # Fallback: return as-is but try to clean up
            return file_str.replace("\\", "/")
    except Exception:
        # Fallback
        return file_path.replace("\\", "/")


def scan_imports(checkout: Path, languages: Set[str]) -> Dict:
    """
    Scan for imports in all detected languages.
    
    Returns dict with results per language:
    {
        "python": {"third_party": [...], "builtin": [...], "relative": [...]},
        "javascript": {"third_party": [...], "builtin": [...], "relative": [...]}
    }
    """
    results = {}
    
    for lang in languages:
        # Check if we have a rule file configured for this language
        if lang in SEMGREP_RULE_FILES:
            rule_file = SEMGREP_RULES_DIR / SEMGREP_RULE_FILES[lang]
            findings = run_semgrep(checkout, rule_file, lang)
            results[lang] = categorize_imports(findings, lang, checkout)
        else:
            # Language not configured - return empty results
            results[lang] = {"third_party": [], "builtin": [], "relative": []}
    
    return results


def categorize_imports(findings: List[Dict], language: str, checkout: Path) -> Dict:
    """Categorize imports into third_party, builtin, and relative."""
    result = {
        "third_party": [],
        "builtin": [],
        "relative": []
    }
    
    # Get extractor function for this language dynamically
    extractor = IMPORT_EXTRACTORS.get(language)
    if not extractor:
        return result
    
    for finding in findings:
        import_info = extractor(finding)
        
        if import_info is None:
            continue
        
        # Make file path relative
        import_info["file"] = make_path_relative(import_info["file"], checkout)
        
        # Categorize
        if import_info.get("is_relative"):
            result["relative"].append(import_info)
        elif import_info.get("is_builtin"):
            result["builtin"].append(import_info)
        else:
            result["third_party"].append(import_info)
    
    return result


def deduplicate_imports(imports: List[Dict]) -> List[Dict]:
    """Remove duplicate imports based on file, line, and module."""
    seen = set()
    unique = []
    
    for imp in imports:
        key = (
            imp.get("file", ""),
            imp.get("line", 0),
            imp.get("module", ""),
            imp.get("imported_item", "")
        )
        if key not in seen:
            seen.add(key)
            unique.append(imp)
    
    return unique


def filter_local_imports(scan_results: Dict, code_tokens: Set[str]) -> Dict:
    """Filter out local/internal imports by matching against code tokens."""
    filtered = {}
    
    for lang in scan_results.keys():
        filtered[lang] = {
            "third_party": [],
            "builtin": scan_results[lang].get("builtin", []),
            "relative": scan_results[lang].get("relative", [])
        }
        
        for imp in scan_results[lang].get("third_party", []):
            module = imp.get("module", "")
            imported_item = imp.get("imported_item", "")
            base_package = imp.get("base_package", "")
            
            # Check if any part matches code tokens (local module)
            is_local = False
            
            if base_package and base_package in code_tokens:
                is_local = True
            if imported_item and imported_item in code_tokens:
                is_local = True
            if module:
                module_parts = module.split(".")
                if any(part in code_tokens for part in module_parts):
                    is_local = True
            
            if not is_local:
                filtered[lang]["third_party"].append(imp)
    
    return filtered


def extract_packages_with_sources(filtered_results: Dict, languages: Set[str]) -> Dict:
    """Extract unique packages with their source file mappings."""
    packages = {lang: {} for lang in languages}
    
    for lang in languages:
        if lang not in filtered_results:
            continue
        
        for imp in filtered_results[lang].get("third_party", []):
            base = imp.get("base_package", "")
            source_file = imp.get("file", "")
            
            if not base:
                continue
            
            if base not in packages[lang]:
                packages[lang][base] = {
                    "package": base,
                    "source_files": []
                }
            
            if source_file and source_file not in packages[lang][base]["source_files"]:
                packages[lang][base]["source_files"].append(source_file)
    
    # Convert to list format dynamically based on detected languages
    result = {}
    for lang in languages:
        result[f"{lang}_imports"] = [
            packages[lang][pkg] for pkg in sorted(packages.get(lang, {}).keys())
        ]
    
    # Ensure expected keys exist for response model compatibility
    if "python_imports" not in result:
        result["python_imports"] = []
    if "javascript_imports" not in result:
        result["javascript_imports"] = []
    
    return result


# =============================================================================
# SCAN FUNCTIONS (Used by endpoints)
# =============================================================================

def scan_and_dedupe(checkout: Path, languages: Set[str]) -> Dict:
    """
    Scan for imports and deduplicate results.
    
    Matches orchestrator's write_semgrep_findings workflow:
    1. Run semgrep import detection
    2. Deduplicate imports per category
    
    Returns scan results with summary (no filtering).
    """
    # Step 1: Run semgrep scan
    scan_results = scan_imports(checkout, languages)
    
    # Step 2: Deduplicate each category
    for lang in scan_results.keys():
        for category in ["third_party", "builtin", "relative"]:
            if category in scan_results[lang]:
                scan_results[lang][category] = deduplicate_imports(
                    scan_results[lang][category]
                )
    
    # Build summary
    summary = {
        "total_third_party": sum(
            len(scan_results.get(lang, {}).get("third_party", []))
            for lang in languages
        ),
        "total_builtin": sum(
            len(scan_results.get(lang, {}).get("builtin", []))
            for lang in languages
        ),
        "total_relative": sum(
            len(scan_results.get(lang, {}).get("relative", []))
            for lang in languages
        )
    }
    
    return {
        "scan_results": scan_results,
        "summary": summary
    }


# =============================================================================
# COMBINED ANALYSIS FUNCTION (Legacy - for backward compatibility)
# =============================================================================

def analyze_imports(checkout: Path, languages: Set[str], code_tokens: Set[str]) -> Dict:
    """
    Complete import analysis: scan, deduplicate, filter, extract packages.
    
    Matches orchestrator's write_semgrep_findings workflow:
    1. Run semgrep import detection
    2. Deduplicate imports
    3. Filter out local imports using code tokens
    4. Extract unique packages with source file mappings
    
    Returns combined result with all import information.
    """
    # Step 1: Run semgrep scan
    scan_results = scan_imports(checkout, languages)
    
    # Step 2: Deduplicate each category (matches orchestrator's write_semgrep_findings)
    for lang in scan_results.keys():
        for category in ["third_party", "builtin", "relative"]:
            if category in scan_results[lang]:
                scan_results[lang][category] = deduplicate_imports(
                    scan_results[lang][category]
                )
    
    # Step 3: Filter local imports
    filtered_results = filter_local_imports(scan_results, code_tokens)
    
    # Step 4: Extract packages with source mappings (pass languages for dynamic keys)
    import_packages = extract_packages_with_sources(filtered_results, languages)
    
    # Build summary
    summary = {
        "total_third_party": sum(
            len(scan_results.get(lang, {}).get("third_party", []))
            for lang in languages
        ),
        "total_builtin": sum(
            len(scan_results.get(lang, {}).get("builtin", []))
            for lang in languages
        ),
        "total_relative": sum(
            len(scan_results.get(lang, {}).get("relative", []))
            for lang in languages
        ),
        "filtered_external_packages": (
            len(import_packages["python_imports"]) + 
            len(import_packages["javascript_imports"])
        )
    }
    
    return {
        "scan_results": scan_results,
        "filtered_results": filtered_results,
        "import_packages": import_packages,
        "summary": summary
    }
