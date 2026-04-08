"""
AIBOM Semgrep Scanner
Simplified semgrep-based import detection for the AIBOM API.
Runs semgrep rules to detect Python and JavaScript imports.
"""

import json
import os
import re
import shutil
import subprocess
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Set, Optional

from aibom.config import (
    SEMGREP_MAX_MEMORY_MB,
    SEMGREP_TIMEOUT_SECONDS,
    SEMGREP_RULE_FILES,
    PYTHON_BUILTINS,
    JS_BUILTINS,
    GO_BUILTINS,
    DOTNET_BUILTINS,
    JAVA_BUILTINS,
    LANGUAGE_EXTENSIONS,
    SUPPORTED_LANGUAGES,
)

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
SEMGREP_RULES_DIR = BASE_DIR.parent / "semgrep"  # Go up to aibom/ then into semgrep/


@lru_cache(maxsize=32)
def _get_rule_file_path(language: str) -> Optional[Path]:
    """
    Get the validated rule file path for a language.
    Results are cached to avoid repeated path computation and validation.
    
    Args:
        language: Language identifier (e.g., 'python', 'javascript')
        
    Returns:
        Path to rule file if exists and valid, None otherwise
    """
    if language not in SEMGREP_RULE_FILES:
        return None
    
    rule_file = SEMGREP_RULES_DIR / SEMGREP_RULE_FILES[language]
    
    # Validate the rule file exists
    if not rule_file.exists():
        logger.warning(f"[SEMGREP] Rule file not found for {language}: {rule_file}")
        return None
    
    return rule_file


# Pre-warm the cache at module load for known languages
def _init_rule_file_cache():
    """Pre-cache rule file paths for all configured languages."""
    for lang in SEMGREP_RULE_FILES.keys():
        _get_rule_file_path(lang)
    logger.info(f"[SEMGREP] Pre-cached rule file paths for {len(SEMGREP_RULE_FILES)} languages")


# Initialize cache at module load
_init_rule_file_cache()


# =============================================================================
# SEMGREP PATH VALIDATION
# =============================================================================

def _get_semgrep_path() -> str:
    """Get validated semgrep executable path."""
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path:
        raise FileNotFoundError(
            "semgrep executable not found in PATH. "
            "Please install semgrep: pip install semgrep"
        )
    
    # Verify it's actually semgrep by checking version
    # semgrep --version outputs version number like "1.45.0"
    try:
        result = subprocess.run(
            [semgrep_path, "--version"],
            capture_output=True,
            text=True,
            timeout=60  # Windows/conda can be very slow on first invocation
        )
        # Check for successful execution and version-like output (e.g., "1.45.0")
        output = (result.stdout + result.stderr).strip()
        # Valid if returncode is 0 and output contains a version pattern (digits and dots)
        import re
        if result.returncode != 0:
            raise ValueError(f"semgrep version check failed at {semgrep_path}: exit code {result.returncode}")
        # Look for version pattern like "1.45.0" or "semgrep" in output
        if not re.search(r'\d+\.\d+\.\d+|semgrep', output, re.IGNORECASE):
            raise ValueError(f"Invalid semgrep binary at {semgrep_path}: unexpected output")
        logger.info(f"[SEMGREP] Version check passed: {output}")
    except subprocess.TimeoutExpired:
        # On Windows, semgrep can be extremely slow to start (conda env overhead).
        # If shutil.which found it, trust the path and proceed anyway.
        logger.warning(
            f"[SEMGREP] Version check timed out at {semgrep_path}, "
            "but executable exists — proceeding with it anyway."
        )
    
    return semgrep_path


# Lazy semgrep path resolution — retries if not found at startup
_SEMGREP_PATH_CACHE: Optional[str] = None
_SEMGREP_PATH_CHECKED: bool = False


def _get_cached_semgrep_path() -> Optional[str]:
    """Lazy-resolve semgrep path. Retries if previously unavailable."""
    global _SEMGREP_PATH_CACHE, _SEMGREP_PATH_CHECKED
    if _SEMGREP_PATH_CACHE is not None:
        return _SEMGREP_PATH_CACHE
    try:
        _SEMGREP_PATH_CACHE = _get_semgrep_path()
        logger.info(f"[SEMGREP] Using validated semgrep at: {_SEMGREP_PATH_CACHE}")
    except (FileNotFoundError, ValueError) as e:
        if not _SEMGREP_PATH_CHECKED:
            logger.warning(f"[SEMGREP] Semgrep not available: {e}")
            _SEMGREP_PATH_CHECKED = True
    return _SEMGREP_PATH_CACHE


# Try once at startup (logs a warning if not found, but will retry later)
_get_cached_semgrep_path()


# =============================================================================
# SEMGREP RUNNER
# =============================================================================

def _get_short_path(checkout: Path) -> tuple:
    """
    On Windows, if the checkout path is very long (>180 chars), create a
    temporary drive letter mapping via `subst` so semgrep can traverse
    the directory without hitting the 260-char MAX_PATH limit.
    
    Returns:
        (effective_path, subst_drive_or_None)
    """
    import string as _string
    if os.name != "nt" or len(str(checkout)) < 180:
        return checkout, None
    
    # Find an unused drive letter
    for letter in reversed(_string.ascii_uppercase):
        drive = f"{letter}:"
        if not Path(f"{drive}\\").exists():
            try:
                subprocess.run(
                    ["subst", drive, str(checkout)],
                    check=True, capture_output=True, timeout=10
                )
                logger.info(f"[SEMGREP] Created subst mapping {drive} -> ...{checkout.name}")
                return Path(f"{drive}\\"), drive
            except Exception as e:
                logger.debug(f"[SEMGREP] subst {drive} failed: {e}")
                continue
    
    logger.warning("[SEMGREP] Could not create subst mapping, using original path")
    return checkout, None


def _release_short_path(subst_drive: str) -> None:
    """Release a subst drive mapping."""
    if subst_drive:
        try:
            subprocess.run(["subst", "/D", subst_drive], capture_output=True, timeout=10)
            logger.info(f"[SEMGREP] Released subst mapping {subst_drive}")
        except Exception as e:
            logger.warning(f"[SEMGREP] Failed to release subst {subst_drive}: {e}")


def run_semgrep(checkout: Path, rule_file: Path, language: str) -> List[Dict]:
    """Run Semgrep with specific rule file and return findings."""
    semgrep_path = _get_cached_semgrep_path()
    if semgrep_path is None:
        logger.error("[SEMGREP] Semgrep executable not available")
        raise FileNotFoundError(
            "semgrep executable not found. Please install semgrep: pip install semgrep"
        )
    
    if not rule_file.exists():
        logger.error("Rule file not found", extra={"rule_file": str(rule_file)})
        return []
    
    # Count files that will be scanned using config-defined extensions
    # Use \\?\ prefix on Windows to support paths longer than MAX_PATH (260 chars)
    exts = LANGUAGE_EXTENSIONS.get(language, frozenset())
    scan_root = checkout
    if os.name == "nt":
        long_path = str(checkout.resolve())
        if not long_path.startswith("\\\\?\\"): 
            long_path = "\\\\?\\" + long_path
        scan_root = Path(long_path)
    try:
        file_count = sum(1 for ext in exts for _ in scan_root.rglob(f"*{ext}"))
    except OSError as e:
        # Gracefully handle Windows long-path or permission errors during rglob
        logger.warning("rglob failed (likely Windows long path), falling back to os.walk",
                        extra={"error": str(e), "checkout": str(checkout)})
        file_count = 0
        for root, _dirs, files in os.walk(str(scan_root)):
            try:
                for f in files:
                    if any(f.endswith(ext) for ext in exts):
                        file_count += 1
            except OSError:
                continue
    logger.info("Scanning files", extra={"file_count": file_count, "language": language, "checkout": str(checkout), "rule_file": rule_file.name})
    
    if file_count == 0:
        logger.warning("No files found for language", extra={"language": language, "checkout": str(checkout)})
        return []
    
    # On Windows with long paths, use subst to give semgrep a short path
    # (semgrep itself does NOT support \\?\ or paths >260 chars)
    effective_checkout, subst_drive = _get_short_path(checkout)
    
    cmd = [
        semgrep_path,
        "--config", str(rule_file),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--optimizations", "all",
        "--max-memory", str(SEMGREP_MAX_MEMORY_MB),
        str(effective_checkout)
    ]
    
    try:
        logger.debug("Running semgrep", extra={"rule_file": rule_file.name})
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=SEMGREP_TIMEOUT_SECONDS,
            cwd=str(effective_checkout),
            encoding="utf-8",
            errors="replace",
        )
        
        if result.returncode != 0:
            logger.warning("Semgrep non-zero exit code", extra={"returncode": result.returncode})
            if result.stderr:
                logger.debug("Semgrep stderr", extra={"stderr": result.stderr[:500]})
        
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                logger.info("Import findings detected", extra={"count": len(findings), "language": language})
                return findings
            except json.JSONDecodeError as e:
                logger.error("JSON parse error", extra={"error": str(e)})
                return []
        
        logger.info("No findings (empty output)", extra={"language": language})
        return []
    
    except subprocess.TimeoutExpired:
        logger.error("Semgrep timeout", extra={"timeout_seconds": SEMGREP_TIMEOUT_SECONDS})
        return []
    except FileNotFoundError:
        logger.error("Semgrep command not found - is it installed?")
        return []
    except Exception as e:
        logger.error("Unexpected semgrep error", extra={"error": str(e)})
        return []
    finally:
        _release_short_path(subst_drive)


# =============================================================================
# IMPORT EXTRACTION
# =============================================================================

def extract_python_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module and imported item from Python import finding.
    
    Semgrep OSS doesn't export metavars in JSON, so we parse from message.
    Message formats from python_imports.yml:
      - "Python import: <module>"                      (direct-import)
      - "Python import: from <module> import <item>"   (from-import)
      - "Python relative import: from .<module> import <item>" (relative-import)
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    module = ""
    item = ""
    
    # Try metavars first (works in some semgrep versions)
    metavars = extra.get("metavars", {})
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
        item = metavars.get("$ITEM", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        # Handle relative import message format
        if "Python relative import:" in message:
            # "Python relative import: from .module import item"
            content = message.split("Python relative import:", 1)[-1].strip()
            if content.startswith("from "):
                parts = content.split(" import ", 1)
                if len(parts) >= 2:
                    module = parts[0].replace("from ", "").strip()
                    item = parts[1].strip()
                    # Handle "from . import item" case where module might be empty/just dots
                    if module in (".", "..", "..."):
                        item = parts[1].strip()
                        module = module  # Keep the dots
        
        # Handle regular import message format
        elif "Python import:" in message:
            # "Python import: from module import item" or "Python import: module"
            content = message.split("Python import:", 1)[-1].strip()
            
            if content.startswith("from "):
                # "from module import item" pattern
                parts = content.split(" import ", 1)
                if len(parts) >= 2:
                    module = parts[0].replace("from ", "").strip()
                    item = parts[1].strip()
            else:
                # Direct import: just the module name
                module = content.strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Reject invalid module names that contain " import " - these are parsing errors
    # from semgrep matching the wrong pattern (e.g., direct-import matching from-import)
    if " import " in module:
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    is_relative = metadata.get("is_relative", False) or module.startswith(".")
    
    # Clean relative import prefix for base_package extraction
    module_clean = module.lstrip(".")
    base_package = module_clean.split(".")[0] if module_clean else module
    is_builtin = base_package.lower() in PYTHON_BUILTINS
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": item or None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "python",
    }


def extract_js_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module from JavaScript/TypeScript import finding.
    
    Semgrep OSS doesn't export metavars, so we parse from message.
    Message formats from javascript_imports.yml:
      - "JavaScript named import from <module>"
      - "JavaScript default import from <module>"
      - "JavaScript namespace import from <module>"
      - "JavaScript require: <module>"
      - "JavaScript dynamic import: <module>"
    """
    extra = finding.get("extra", {})
    metavars = extra.get("metavars", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    # Skip if marked by semgrep rule (e.g., path aliases)
    if metadata.get("skip"):
        return None
    
    module = ""
    
    # Try metavars first (works in some semgrep versions)
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        # Pattern: "JavaScript X import from <module>" or "JavaScript require: <module>"
        if " from " in message:
            # Named/default/namespace import: extract after "from "
            module = message.split(" from ", 1)[-1].strip()
        elif "require:" in message:
            # Require pattern: "JavaScript require: <module>"
            module = message.split("require:", 1)[-1].strip()
        elif "dynamic import:" in message:
            # Dynamic import: "JavaScript dynamic import: <module>"
            module = message.split("dynamic import:", 1)[-1].strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    is_relative = metadata.get("is_relative", False) or module.startswith(".") or module.startswith("/")
    
    # Python-only: derive base_package (scoped packages need special handling)
    if module.startswith("@"):
        # Scoped package: @anthropic-ai/sdk → @anthropic-ai/sdk
        parts = module.split("/")
        base_package = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else module
    else:
        # Regular package: langchain/embeddings → langchain
        base_package = module.split("/")[0]
    
    # Python-only: check against builtin set
    is_builtin = base_package in JS_BUILTINS or module in JS_BUILTINS
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "javascript",
    }


def extract_go_import_info(finding: Dict) -> Optional[Dict]:
    """Extract module from Go import finding.
    
    Semgrep OSS doesn't export metavars, so we parse from message.
    Message formats from go_imports.yml:
      - "Go import: <module>"
    
    Go import paths are full module paths like:
      - "fmt" (stdlib)
      - "github.com/gin-gonic/gin" (third-party)
      - "github.com/sashabaranov/go-openai" (AI library)
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    module = ""
    
    # Try metavars first (works in some semgrep versions)
    metavars = extra.get("metavars", {})
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        if "Go import:" in message:
            module = message.split("Go import:", 1)[-1].strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    
    # Go imports: relative if starts with ./ or ../
    is_relative = module.startswith("./") or module.startswith("../")
    
    # Determine base package:
    # stdlib: "fmt", "net/http" → base_package = "fmt", "net"
    # third-party: "github.com/gin-gonic/gin" → base_package = full path
    # For third-party Go modules, we keep the full import path as base_package
    # since that's how Go modules are identified
    if "/" in module:
        # Could be stdlib (net/http) or third-party (github.com/...)
        parts = module.split("/")
        # Third-party packages typically have a domain with a dot
        if "." in parts[0]:
            # Third-party: github.com/user/repo/pkg → use first 3 segments as base
            base_package = "/".join(parts[:3]) if len(parts) >= 3 else module
        else:
            # Stdlib: net/http → base is "net/http" (full path)
            base_package = module
    else:
        base_package = module
    
    # Check if builtin - match full path or first segment
    is_builtin = module in GO_BUILTINS or base_package in GO_BUILTINS
    # Also check first segment for nested stdlib packages
    if not is_builtin and "/" in module:
        first_segment = module.split("/")[0]
        # Stdlib packages don't have dots in first segment
        if "." not in first_segment:
            is_builtin = True
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "go",
    }


def extract_dotnet_import_info(finding: Dict) -> Optional[Dict]:
    """Extract namespace from .NET (C#) using directive finding.
    
    Semgrep OSS doesn't export metavars, so we parse from message.
    Message formats from dotnet_imports.yml:
      - "Dotnet import: <namespace>"
    
    C# using statement namespaces:
      - "System" (builtin)
      - "System.Linq" (builtin)
      - "Microsoft.ML" (NuGet package)
      - "Azure.AI.OpenAI" (NuGet package)
      - "Newtonsoft.Json" (NuGet package)
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    
    module = ""
    
    # Try metavars first (works in some semgrep versions)
    metavars = extra.get("metavars", {})
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()
    
    # Parse from message (semgrep OSS interpolates $MODULE into message)
    if not module and message:
        if "Dotnet import:" in message:
            module = message.split("Dotnet import:", 1)[-1].strip()
    
    # Validate we got a module
    if not module or module == "$MODULE":
        return None
    
    # Read metadata from semgrep rules
    import_type = metadata.get("import_type", "unknown")
    
    # .NET using directives are never relative
    is_relative = False
    
    # Determine base package (NuGet package name):
    # NuGet packages map to top-level namespaces, e.g.:
    #   "Microsoft.ML" → base = "Microsoft.ML"
    #   "Azure.AI.OpenAI" → base = "Azure.AI.OpenAI"
    #   "System.Linq" → base = "System" (builtin)
    #   "Newtonsoft.Json" → base = "Newtonsoft.Json"
    # For matching with .csproj PackageReferences, keep the full namespace
    base_package = module
    
    # Check if builtin - match full namespace or any parent namespace
    is_builtin = module in DOTNET_BUILTINS
    if not is_builtin:
        # Check parent namespaces (System.Linq.Expressions → System.Linq → System)
        parts = module.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            if parent in DOTNET_BUILTINS:
                is_builtin = True
                break
    
    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "dotnet",
    }


def extract_java_import_info(finding: Dict) -> Optional[Dict]:
    """Extract package from Java import statement finding.

    Semgrep message formats from java_imports.yml:
      - "Java import: <fully.qualified.Name>"

    Java import packages:
      - "java.util.List" (builtin)
      - "com.openai.client.OpenAiClient" (third-party)
      - "dev.langchain4j.model.openai.OpenAiChatModel" (third-party)
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")

    module = ""

    # Try metavars first
    metavars = extra.get("metavars", {})
    if metavars:
        module = metavars.get("$MODULE", {}).get("abstract_content", "").strip()

    # Parse from message
    if not module and message:
        if "Java import:" in message:
            module = message.split("Java import:", 1)[-1].strip()

    if not module or module == "$MODULE":
        return None

    import_type = metadata.get("import_type", "unknown")
    is_relative = False

    # Determine base package:
    # Java packages are hierarchical. For Maven/Gradle dependency matching,
    # we care about the top-level group (e.g., "com.openai" from "com.openai.client.OpenAiClient")
    # But for builtin detection, we match the root namespace.
    base_package = module

    # Strip wildcard: import com.openai.* → com.openai
    if module.endswith(".*"):
        module = module[:-2]
        base_package = module

    # Check if builtin — match full import or any parent package
    is_builtin = module in JAVA_BUILTINS
    if not is_builtin:
        parts = module.split(".")
        # Build parent namespaces: com.openai.client → com.openai → com
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            if parent in JAVA_BUILTINS:
                is_builtin = True
                break
        # java.* and javax.* are always builtin
        if not is_builtin and parts[0] in ("java", "javax"):
            is_builtin = True

    return {
        "file": finding.get("path", ""),
        "line": finding.get("start", {}).get("line", 0),
        "module": module,
        "imported_item": None,
        "base_package": base_package,
        "is_builtin": is_builtin,
        "is_relative": is_relative,
        "import_type": import_type,
        "language": "java",
    }


# Map language to extractor function
IMPORT_EXTRACTORS = {
    "python": extract_python_import_info,
    "javascript": extract_js_import_info,
    "go": extract_go_import_info,
    "dotnet": extract_dotnet_import_info,
    "java": extract_java_import_info,
}


# =============================================================================
# MAIN SCANNING FUNCTIONS
# =============================================================================

def make_path_relative(file_path: str, checkout: Path) -> str:
    """Convert absolute file path to relative path from checkout root."""
    try:
        return str(Path(file_path).relative_to(checkout)).replace("\\", "/")
    except ValueError:
        # Path already relative or outside checkout
        return file_path.replace("\\", "/")


def _read_go_module_path(checkout: Path) -> str:
    """Read the Go module declaration from go.mod (e.g. 'github.com/8ff/gpt').
    Used to identify internal sub-package imports that should be classified as relative."""
    go_mod = checkout / "go.mod"
    if not go_mod.exists():
        return ""
    try:
        for line in go_mod.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("module "):
                parts = line.split()
                return parts[1].strip() if len(parts) >= 2 else ""
    except Exception:
        pass
    return ""


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
    
    # For Go: read the repo's own module path so internal sub-package imports
    # (e.g. github.com/8ff/gpt/pkg/...) are classified as relative, not third_party.
    go_module_path = _read_go_module_path(checkout) if "go" in languages else ""
    if go_module_path:
        print(f"[SCAN] Go module path detected: {go_module_path}")
    
    for lang in languages:
        # Get cached rule file path for this language
        rule_file = _get_rule_file_path(lang)
        if rule_file is not None:
            findings = run_semgrep(checkout, rule_file, lang)
            _go_mod = go_module_path if lang == "go" else ""
            results[lang] = categorize_imports(findings, lang, checkout, go_module_path=_go_mod)
        else:
            # Language not configured or rule file missing - return empty results
            results[lang] = {"third_party": [], "builtin": [], "relative": []}
    
    return results


def categorize_imports(findings: List[Dict], language: str, checkout: Path, go_module_path: str = "") -> Dict:
    """Categorize imports into third_party, builtin, and relative."""
    result = {
        "third_party": [],
        "builtin": [],
        "relative": []
    }
    
    # Get extractor function for this language dynamically
    extractor = IMPORT_EXTRACTORS.get(language)
    if not extractor:
        logger.warning("No extractor for language", extra={"language": language})
        return result
    
    null_count = 0
    for finding in findings:
        import_info = extractor(finding)
        
        if import_info is None:
            null_count += 1
            # Debug: Log first few failures with finding structure
            if null_count <= 3:
                metavars = finding.get("extra", {}).get("metavars", {})
                check_id = finding.get("check_id", "unknown")
                extra_keys = list(finding.get("extra", {}).keys())
                logger.debug("Extraction returned None", extra={
                    "check_id": check_id,
                    "extra_keys": extra_keys,
                    "metavars": str(metavars)
                })
                # Log first finding fully for debugging
                if null_count == 1:
                    import json
                    logger.debug("Full finding structure", extra={"finding": json.dumps(finding, default=str)[:1000]})
            continue
        
        # Make file path relative
        import_info["file"] = make_path_relative(import_info["file"], checkout)
        
        # Go: reclassify internal sub-package imports as relative.
        # A Go import is internal if it starts with the repo's own module path.
        # e.g. repo module = "github.com/8ff/gpt", import = "github.com/8ff/gpt/pkg/foo"
        if go_module_path and import_info.get("module", "").startswith(go_module_path + "/"):
            import_info["is_relative"] = True
        
        # Categorize
        if import_info.get("is_relative"):
            result["relative"].append(import_info)
        elif import_info.get("is_builtin"):
            result["builtin"].append(import_info)
        else:
            result["third_party"].append(import_info)
    
    # Debug summary
    if null_count > 0:
        logger.debug("Extraction failures", extra={"null_count": null_count, "total": len(findings)})
    logger.info("Categorization complete", extra={
        "language": language,
        "third_party": len(result['third_party']),
        "builtin": len(result['builtin']),
        "relative": len(result['relative'])
    })
    
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
    
    for lang, lang_data in scan_results.items():
        filtered[lang] = {
            "third_party": [],
            "builtin": lang_data.get("builtin", []),
            "relative": lang_data.get("relative", [])
        }
        
        for imp in lang_data.get("third_party", []):
            base_package = imp.get("base_package", "")
            
            # Fast check: base_package is most likely match
            if base_package and base_package in code_tokens:
                continue
            
            imported_item = imp.get("imported_item", "")
            if imported_item and imported_item in code_tokens:
                continue
            
            module = imp.get("module", "")
            if module:
                # Only split if base_package check failed (lazy evaluation)
                module_parts = module.split(".")
                if any(part in code_tokens for part in module_parts):
                    continue
            
            # Not local - keep it
            filtered[lang]["third_party"].append(imp)
    
    return filtered


def extract_packages_with_sources(filtered_results: Dict, languages: Set[str]) -> Dict:
    """Extract unique packages with their source file mappings and import details.
    
    Each package entry contains:
      - package: base package name
      - source_files: sorted list of files that import this package
      - import_details: list of {module, imported_item, file, line} for each import
    
    import_details preserves the sub-import granularity so downstream consumers
    (LLM validator, categorizer, branch tracer) can see exactly which components
    of a framework are used (e.g. AutoModelForCausalLM from transformers).
    """
    # Track source_files (set for O(1) dedup) and import_details (list) per package
    pkg_files = {lang: {} for lang in languages}
    pkg_details = {lang: {} for lang in languages}
    
    for lang in languages:
        if lang not in filtered_results:
            continue
        
        for imp in filtered_results[lang].get("third_party", []):
            base = imp.get("base_package", "")
            if not base:
                continue
            
            source_file = imp.get("file", "")
            
            # Collect source files (deduplicated)
            if base not in pkg_files[lang]:
                pkg_files[lang][base] = set()
                pkg_details[lang][base] = []
            
            if source_file:
                pkg_files[lang][base].add(source_file)
            
            # Collect import detail — compact record of each sub-import
            detail = {
                "module": imp.get("module", ""),
                "imported_item": imp.get("imported_item") or None,
                "file": source_file,
                "line": imp.get("line", 0),
            }
            pkg_details[lang][base].append(detail)
    
    # Convert to list format with sorted source_files + import_details
    result = {}
    for lang in languages:
        import_key = SUPPORTED_LANGUAGES.get(lang, f"{lang}_imports")
        result[import_key] = [
            {
                "package": pkg,
                "source_files": sorted(pkg_files[lang][pkg]),
                "import_details": pkg_details[lang][pkg],
            }
            for pkg in sorted(pkg_files.get(lang, {}).keys())
        ]
    
    # Ensure expected keys exist for response model compatibility
    for import_key in SUPPORTED_LANGUAGES.values():
        if import_key not in result:
            result[import_key] = []
    
    return result


# =============================================================================
# SCAN FUNCTIONS (Used by endpoints)
# =============================================================================

def scan_and_dedupe(checkout, languages: Set[str]) -> Dict:
    """
    Scan for imports and deduplicate results.
    
    Matches orchestrator's write_semgrep_findings workflow:
    1. Run semgrep import detection
    2. Deduplicate imports per category
    
    Returns scan results with summary (no filtering).
    """
    # Ensure checkout is a Path object
    checkout_path = Path(checkout) if isinstance(checkout, str) else checkout
    
    # Step 1: Run semgrep scan
    scan_results = scan_imports(checkout_path, languages)
    
    # Step 2: Deduplicate each category
    for lang in scan_results.keys():
        for category in ["third_party", "builtin", "relative"]:
            if category in scan_results[lang]:
                scan_results[lang][category] = deduplicate_imports(
                    scan_results[lang][category]
                )
    
    # Step 3: Count total files scanned (all files semgrep checked across languages)
    all_scanned_files: List[str] = []
    seen_scanned: set = set()
    scan_root = checkout_path
    if os.name == "nt":
        long_path = str(checkout_path.resolve())
        if not long_path.startswith("\\\\?\\"):
            long_path = "\\\\?\\" + long_path
        scan_root = Path(long_path)
    for lang in languages:
        exts = LANGUAGE_EXTENSIONS.get(lang, frozenset())
        for ext in exts:
            try:
                for fp in scan_root.rglob(f"*{ext}"):
                    rel = str(fp.relative_to(scan_root)).replace("\\", "/")
                    if rel not in seen_scanned:
                        seen_scanned.add(rel)
                        all_scanned_files.append(rel)
            except OSError:
                # Gracefully handle Windows long-path errors
                for root, _dirs, files in os.walk(str(scan_root)):
                    for fname in files:
                        if fname.endswith(ext):
                            try:
                                rel = os.path.relpath(
                                    os.path.join(root, fname), str(scan_root)
                                ).replace("\\", "/")
                                if rel not in seen_scanned:
                                    seen_scanned.add(rel)
                                    all_scanned_files.append(rel)
                            except (OSError, ValueError):
                                continue
    all_scanned_files.sort()
    
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
        "files_scanned_count": len(all_scanned_files),
        "files_scanned": all_scanned_files
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
        "filtered_external_packages": sum(
            len(import_packages.get(import_key, []))
            for import_key in SUPPORTED_LANGUAGES.values()
        )
    }
    
    return {
        "scan_results": scan_results,
        "filtered_results": filtered_results,
        "import_packages": import_packages,
        "summary": summary
    }
