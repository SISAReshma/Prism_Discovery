"""
Agentic Asset Scanner
=====================
Runs semgrep rules on traced files to detect agentic asset definitions
(Agent, Task, Crew, etc.) from code that uses agentic frameworks like
CrewAI, AutoGen, OpenAI Agents SDK, Pydantic AI, Smolagents, etc.

For each agentic library detected in the branch trace, scans the traced
files with the matching semgrep rule file and extracts metavariable values
(role, goal, backstory, description, etc.).

New rules can be added by creating YAML files under semgrep/{language}/
following the naming convention: {library}_agentic_rules.yml
"""

import ast
import re
import logging
import textwrap
from pathlib import Path
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

from aibom.config import SEMGREP_DIR

logger = logging.getLogger(__name__)

# =============================================================================
# FRAMEWORK ↔ RULE FILE MAPPING
# =============================================================================
# Maps normalized framework name → keyword(s) to match against rule file stems
# in the language folder (e.g. semgrep/python/crewai_agentic_rules.yml).
# Each library now has its own dedicated rule file.

_FRAMEWORK_RULE_KEYWORDS: Dict[str, List[str]] = {
    "crewai":            ["crewai"],
    "autogen":           ["autogen"],
    "ag2":               ["autogen"],        # ag2 uses same patterns as autogen
    "openai-agents-sdk": ["openai_agents"],
    "pydantic-ai":       ["pydantic_ai"],
    "smolagents":        ["smolagents"],
    "semantic-kernel":   ["semantic_kernel"],
    "langgraph":         ["langgraph"],
    "agency-swarm":      ["agency_swarm"],
    "taskweaver":        ["taskweaver"],
}


# =============================================================================
# RULE DISCOVERY
# =============================================================================

@lru_cache(maxsize=16)
def _get_agentic_rules_for_language(language: str) -> Tuple[Tuple[str, Path], ...]:
    """Cache agentic rule files for a given language. Returns tuple for hashability."""
    lang_dir = SEMGREP_DIR / language
    if not lang_dir.exists():
        logger.warning(f"[AGENTIC] Language directory not found: {lang_dir}")
        return ()
    return tuple(
        (rule_file.stem.lower(), rule_file)
        for rule_file in lang_dir.glob("*_agentic_rules*.yml")
    )


def find_agentic_rule(framework_name: str, language: str = "python") -> Optional[Path]:
    """Find the semgrep rule file matching an agentic framework.
    
    Looks in SEMGREP_DIR/{language}/ for files matching *_agentic_rules*.yml.
    
    Strategy:
    1. Check _FRAMEWORK_RULE_KEYWORDS for known mapping → match against rule stems
    2. Fall back to substring match on framework name in rule file names
    """
    cached_rules = _get_agentic_rules_for_language(language)
    if not cached_rules:
        return None

    fw_lower = framework_name.lower().replace("_", "-")

    # Strategy 1: Known keyword mapping
    keywords = _FRAMEWORK_RULE_KEYWORDS.get(fw_lower, [])
    for kw in keywords:
        for rule_name, rule_file in cached_rules:
            if kw in rule_name:
                return rule_file

    # Strategy 2: Substring match
    fw_normalized = fw_lower.replace("-", "_")
    for rule_name, rule_file in cached_rules:
        if fw_normalized in rule_name:
            return rule_file

    return None


def get_all_agentic_rules(language: str = "python") -> List[Path]:
    """Return all agentic rule file paths for a language."""
    return [rule_file for _, rule_file in _get_agentic_rules_for_language(language)]


# =============================================================================
# SOURCE FILE READING (handles semgrep "requires login" masking)
# =============================================================================

def _read_source_lines(
    file_path: str,
    start_line: int,
    end_line: int = 0,
) -> str:
    """Read source lines from a file.

    When semgrep returns 'requires login' instead of the matched code,
    we read the source file directly to get the actual content.
    Mirrors ``_read_source_line`` in ``ai_targeted_scanner``.

    Args:
        file_path: Absolute path to the source file.
        start_line: 1-indexed first line to read.
        end_line: 1-indexed last line to read (inclusive). If 0, equals start_line.

    Returns:
        The joined source lines, or "" on failure.
    """
    if not end_line or end_line < start_line:
        end_line = start_line
    try:
        p = Path(file_path)
        if not p.is_file():
            return ""
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        # Clamp to valid range
        s = max(start_line - 1, 0)
        e = min(end_line, len(lines))
        if s < e:
            return "\n".join(lines[s:e])
    except Exception:
        pass
    return ""


# =============================================================================
# AST-BASED FIELD EXTRACTION
# =============================================================================

# Fields we attempt to extract for each asset type.
_INTERESTING_FIELDS: Set[str] = {
    # Agent fields
    "role", "goal", "backstory", "name", "instructions",
    "system_message", "system_prompt", "description", "model",
    "tools", "verbose", "llm", "human_input_mode",
    # Task fields
    "expected_output", "agent", "context",
    # Crew / orchestration fields
    "agents", "tasks", "process",
    # General
    "llm_config", "code_execution_config",
    "shared_instructions", "agency_chart",
    "kernel", "max_round",
}


def _ast_value_to_str(node: ast.AST) -> str:
    """Convert an AST value node to a readable string.

    Handles string literals, numbers, booleans, lists, attribute chains,
    f-strings, calls, and names.  Falls back to ``ast.dump`` for uncommon nodes.
    """
    # --- String / bytes / numeric literal ---
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value  # return the raw string, no quotes
        return repr(node.value)

    # --- JoinedStr (f-string) ---
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                parts.append("{...}")
        return "".join(parts)

    # --- Name (variable reference) ---
    if isinstance(node, ast.Name):
        return node.id

    # --- Attribute chain  a.b.c ---
    if isinstance(node, ast.Attribute):
        parts_attr: List[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts_attr.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts_attr.append(cur.id)
        return ".".join(reversed(parts_attr))

    # --- List / Tuple ---
    if isinstance(node, (ast.List, ast.Tuple)):
        items = [_ast_value_to_str(el) for el in node.elts]
        return "[" + ", ".join(items) + "]"

    # --- Call  e.g.  Process.sequential ---
    if isinstance(node, ast.Call):
        func_str = _ast_value_to_str(node.func)
        return f"{func_str}(...)"

    # --- Dict ---
    if isinstance(node, ast.Dict):
        return "{...}"

    # --- Fallback ---
    try:
        return ast.unparse(node)
    except Exception:
        return repr(node)


def _extract_fields_from_ast(
    file_path: str,
    start_line: int,
    end_line: int,
) -> Dict[str, str]:
    """Parse source with Python AST and extract keyword arguments.

    Looks for class instantiation calls (``Agent(...)``, ``Task(...)`` etc.) in
    the given line range and returns a dict of keyword argument values.

    This is the primary mechanism for populating ``fields`` – semgrep metavars
    are merged on top afterwards (if they provide anything).
    """
    try:
        p = Path(file_path)
        if not p.is_file():
            return {}
        source = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}

    lines = source.splitlines()
    if not lines:
        return {}

    # Determine the full statement block: expand end_line until the statement
    # is syntactically complete (handles multi-line calls).
    s = max(start_line - 1, 0)
    e = min(end_line, len(lines))

    # Heuristic: extend end_line until parentheses balance or we hit a blank line
    paren_depth = 0
    extended_end = e
    for idx in range(s, min(len(lines), e + 30)):  # look up to 30 lines ahead
        line = lines[idx]
        paren_depth += line.count("(") - line.count(")")
        extended_end = idx + 1
        if paren_depth <= 0 and idx >= e - 1:
            break
    e = extended_end

    snippet = "\n".join(lines[s:e])
    # Dedent so the parser doesn't choke on indented code
    snippet = textwrap.dedent(snippet)

    try:
        tree = ast.parse(snippet, mode="exec")
    except SyntaxError:
        # Try wrapping in a dummy function to handle partial code
        try:
            tree = ast.parse(f"def _():\n" + textwrap.indent(snippet, "    "), mode="exec")
        except SyntaxError:
            return {}

    fields: Dict[str, str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Extract keyword arguments
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in _INTERESTING_FIELDS:
                val = _ast_value_to_str(kw.value)
                if val:
                    fields[kw.arg.lower()] = val

    return fields


# =============================================================================
# FINDING PROCESSOR
# =============================================================================

def _extract_metavar_values(finding: Dict) -> Dict[str, str]:
    """Extract all metavariable values from a semgrep finding.

    Semgrep stores metavariables like $ROLE, $GOAL, $NAME in:
      finding["extra"]["metavars"]["$ROLE"]["abstract_content"]

    Returns a dict like: {"role": "AI Security Researcher", "goal": "..."}
    """
    metavars = finding.get("extra", {}).get("metavars", {})
    result: Dict[str, str] = {}

    for key, info in metavars.items():
        # Strip the $ prefix and lowercase: "$ROLE" → "role"
        field_name = key.lstrip("$").lower()
        # Try multiple keys semgrep may use depending on version
        value = (
            info.get("abstract_content")
            or info.get("propagated_value", {}).get("svalue_abstract_content", "")
            or ""
        )
        if not value:
            # Last resort: read the matched source text from the code span
            # Some semgrep versions only provide start/end offsets in the metavar
            pass
        if value:
            # Clean surrounding quotes from string literals
            cleaned = value.strip().strip("\"'")
            if cleaned:
                result[field_name] = cleaned

    return result


def _find_enclosing_function_from_source(
    file_path: str,
    target_line: int,
) -> Optional[str]:
    """Read the source file and find the enclosing def/async def for a given line.

    Walks backwards from target_line looking for the nearest `def ` or `async def `.
    """
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None

    lines = source.splitlines()
    for i in range(min(target_line - 1, len(lines) - 1), -1, -1):
        stripped = lines[i].lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            match = re.match(r"(?:async\s+)?def\s+(\w+)", stripped)
            if match:
                return match.group(1)
    return None


def _process_agentic_finding(
    finding: Dict,
    checkout_dir: Path,
    framework: str,
) -> Dict:
    """Process a single semgrep finding into an agentic asset dict.

    Extracts:
    - asset_type from rule metadata
    - field values from metavariables AND AST-based extraction
    - enclosing function name from source
    - code snippet (reads source directly when semgrep returns 'requires login')
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})

    # File path handling
    file_path = finding.get("path", "")
    abs_file_path = file_path
    try:
        abs_path = Path(file_path)
        if abs_path.is_absolute():
            file_path = str(abs_path.relative_to(checkout_dir))
    except (ValueError, TypeError):
        pass

    start_line = finding.get("start", {}).get("line", 0)
    end_line = finding.get("end", {}).get("line", start_line)

    # -----------------------------------------------------------------
    # CODE SNIPPET: handle semgrep "requires login" masking
    # Same pattern as _process_finding in ai_targeted_scanner.py
    # -----------------------------------------------------------------
    code_lines = (extra.get("lines") or "").strip()

    if not code_lines or code_lines == "requires login":
        if start_line and abs_file_path:
            code_lines = _read_source_lines(abs_file_path, start_line, end_line)
            if code_lines:
                # Inject real code back so metavar extraction can use it
                extra = dict(extra)  # shallow copy
                extra["lines"] = code_lines
                finding = dict(finding, extra=extra)

    # -----------------------------------------------------------------
    # FIELD EXTRACTION: AST-based (primary) + semgrep metavars (overlay)
    # -----------------------------------------------------------------
    # 1. AST extraction – reads the source file directly, robust
    ast_fields = _extract_fields_from_ast(abs_file_path, start_line, end_line)

    # 2. Semgrep metavars – may be empty on community edition, but
    #    if available they can be more accurate for simple string values
    metavar_fields = _extract_metavar_values(finding)

    # Merge: AST first, metavar values override (they're from semgrep analysis)
    fields = {**ast_fields, **metavar_fields}

    # Determine asset_type and class from metadata and rule_id
    asset_type = metadata.get("asset_type", "other")
    rule_id = finding.get("check_id", "")

    # Infer class_name from the (now real) code snippet or rule_id
    class_name = _infer_class_name(code_lines, rule_id)

    # Find enclosing function by reading source
    enclosing_fn = _find_enclosing_function_from_source(abs_file_path, start_line)

    return {
        "asset_type": asset_type,
        "class_name": class_name,
        "function": enclosing_fn,
        "file": file_path.replace("\\", "/"),
        "line": start_line,
        "end_line": end_line,
        "fields": fields,
        "framework": metadata.get("framework", framework),
        "code_snippet": code_lines[:500] if code_lines else "",
        "rule_id": rule_id,
    }


def _infer_class_name(code_snippet: str, rule_id: str) -> str:
    """Infer the class name from the code snippet or rule ID.
    
    Tries to find the class instantiation call in the code,
    e.g. `Agent(role=...)` → "Agent", `Task(description=...)` → "Task".
    Falls back to extracting from the rule_id.
    """
    if code_snippet:
        match = re.search(r'\b([A-Z]\w+)\s*\(', code_snippet)
        if match:
            return match.group(1)

    # Fallback: extract from rule_id like "crewai-agent-definition" → "Agent"
    if rule_id:
        parts = rule_id.lower().split("-")
        class_hints = {
            "agent": "Agent", "task": "Task", "crew": "Crew",
            "assistant": "AssistantAgent", "conversable": "ConversableAgent",
            "userproxy": "UserProxyAgent", "groupchat": "GroupChat",
            "stategraph": "StateGraph", "agency": "Agency",
            "codeagent": "CodeAgent",
        }
        for part in parts:
            if part in class_hints:
                return class_hints[part]

    return "Unknown"


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def scan_agentic_assets(
    checkout_dir: str,
    branch_trace: Dict,
    frameworks_detected: Optional[Dict] = None,
) -> Dict:
    """Scan traced files for agentic asset definitions using semgrep.
    
    Uses the branch trace (which contains traced_files per library) and
    the frameworks detection result (which identifies agentic frameworks)
    to locate files worth scanning, then runs matching semgrep rules to
    extract Agent/Task/Crew definitions with their keyword arguments.
    
    Args:
        checkout_dir: Path to the checked-out repository.
        branch_trace: The ai_branch_trace session data.
            Has "branches" dict keyed by library name.
        frameworks_detected: The frameworks_detected session data (optional).
            Used to confirm which libraries are agentic.
    
    Returns:
        Dict with:
          - agentic_assets: list of asset dicts grouped by framework
          - all_assets: flat list of all assets
          - summary: counts and metadata
    """
    # Import here to avoid circular imports (ai_targeted_scanner imports from config too)
    from aibom.src.ai_targeted_scanner import run_semgrep, _build_file_cache

    logger.info("[AGENTIC] Starting agentic asset scan (semgrep)")

    checkout_path = Path(checkout_dir)
    branches = branch_trace.get("branches", {})

    # Determine which libraries are agentic
    agentic_libs: Dict[str, str] = {}  # lib_name → normalized framework key

    # Strategy 1: Use frameworks_detected if available (most reliable)
    if frameworks_detected:
        for fw in frameworks_detected.get("agentic_frameworks", []):
            pkg = fw.get("base_package", "")
            if pkg:
                agentic_libs[pkg] = pkg.lower().replace("_", "-")

    # Strategy 2: Fall back to branch trace categories
    if not agentic_libs:
        for lib_name, branch in branches.items():
            if branch.get("category", "").upper() == "AGENTIC_FRAMEWORK":
                agentic_libs[lib_name] = lib_name.lower().replace("_", "-")

    if not agentic_libs:
        logger.info("[AGENTIC] No agentic frameworks detected, skipping asset scan")
        return _empty_agentic_result()

    logger.info(f"[AGENTIC] Agentic libraries to scan: {list(agentic_libs.keys())}")

    # Build file cache once
    file_cache = _build_file_cache(checkout_path)

    all_assets: List[Dict] = []
    all_errors: List[str] = []
    files_scanned: Set[str] = set()
    scanned_pairs: Set[Tuple[str, str]] = set()  # (file, rule_name)

    for lib_name, framework_key in agentic_libs.items():
        # Determine language from branch trace (default to python)
        branch = branches.get(lib_name, {})
        language = (branch.get("language") or "python").lower()

        # Find the matching semgrep rule file
        rule_file = find_agentic_rule(framework_key, language=language)
        if not rule_file:
            logger.debug(f"[AGENTIC] No semgrep rule found for framework: {framework_key}")
            continue

        # Get traced files for this library from branch trace
        traced_files = branch.get("traced_files", [])

        if not traced_files:
            logger.debug(f"[AGENTIC] No traced files for {lib_name}")
            continue

        # Deduplicate: skip files already scanned with this rule
        rule_name = rule_file.name
        files_to_scan = [f for f in traced_files if (f, rule_name) not in scanned_pairs]
        scanned_pairs.update((f, rule_name) for f in files_to_scan)

        if not files_to_scan:
            continue

        logger.info(f"[AGENTIC] Scanning {len(files_to_scan)} files for {lib_name} "
                     f"with {rule_name}")

        files_scanned.update(files_to_scan)

        findings, error = run_semgrep(
            checkout_path, rule_file, files_to_scan, file_cache=file_cache
        )

        if error:
            err_msg = f"{lib_name}: {error}"
            logger.warning(f"[AGENTIC] Semgrep error: {err_msg}")
            all_errors.append(err_msg)
            continue

        if not findings:
            logger.debug(f"[AGENTIC] No findings for {lib_name}")
            continue

        logger.info(f"[AGENTIC] {len(findings)} raw findings for {lib_name}")

        # Process findings and deduplicate by (file, line, rule_id)
        seen: Set[Tuple[str, int, str]] = set()
        for f in findings:
            processed = _process_agentic_finding(f, checkout_path, framework_key)
            key = (processed["file"], processed["line"], processed["rule_id"])
            if key not in seen:
                seen.add(key)
                all_assets.append(processed)

    # Merge findings for the same instantiation (same file+line, different rules)
    merged_assets = _merge_overlapping_assets(all_assets)

    # Group assets by framework
    by_framework: Dict[str, Dict] = {}
    grouped_keys: Set[Tuple[str, int]] = set()
    for asset in merged_assets:
        fw = asset["framework"]
        if fw not in by_framework:
            by_framework[fw] = {"framework": fw, "agents": [], "tasks": [], "crews": [], "other": []}

        bucket = {
            "agent": "agents", "task": "tasks", "crew": "crews"
        }.get(asset["asset_type"], "other")
        by_framework[fw][bucket].append(asset)
        grouped_keys.add((asset["file"], asset["line"]))

    # Only include assets not already present in agentic_assets
    ungrouped_assets = [
        a for a in merged_assets if (a["file"], a["line"]) not in grouped_keys
    ]

    logger.info(f"[AGENTIC] Scan complete: {len(merged_assets)} assets found in "
                f"{len(files_scanned)} files across {len(by_framework)} frameworks")

    return {
        "agentic_assets": list(by_framework.values()),
        "all_assets": ungrouped_assets,
        "summary": {
            "total_assets": len(merged_assets),
            "total_agents": sum(1 for a in merged_assets if a["asset_type"] == "agent"),
            "total_tasks": sum(1 for a in merged_assets if a["asset_type"] == "task"),
            "total_crews": sum(1 for a in merged_assets if a["asset_type"] == "crew"),
            "frameworks_scanned": list(by_framework.keys()),
            "files_scanned": len(files_scanned),
            "errors": all_errors,
        },
    }


# =============================================================================
# MERGE OVERLAPPING FINDINGS
# =============================================================================

def _merge_overlapping_assets(assets: List[Dict]) -> List[Dict]:
    """Merge findings that point to the same code location.
    
    Semgrep fires separate rules for each kwarg (one for role=, one for goal=, etc.)
    but they all refer to the same Agent() call. Merge them into one asset
    with combined fields.
    
    Groups by (file, line, asset_type, framework) and merges field dicts.
    Keeps the longest code_snippet and first non-None function name.
    """
    groups: Dict[Tuple, Dict] = {}

    for asset in assets:
        key = (asset["file"], asset["line"], asset["asset_type"], asset["framework"])

        if key not in groups:
            groups[key] = dict(asset)  # shallow copy
        else:
            existing = groups[key]
            # Merge fields (new values don't overwrite existing ones)
            for field_name, field_value in asset.get("fields", {}).items():
                if field_name not in existing.get("fields", {}):
                    existing.setdefault("fields", {})[field_name] = field_value
            # Keep the longer snippet
            if len(asset.get("code_snippet", "")) > len(existing.get("code_snippet", "")):
                existing["code_snippet"] = asset["code_snippet"]
            # Keep function name if not set
            if not existing.get("function") and asset.get("function"):
                existing["function"] = asset["function"]
            # Keep the larger end_line
            if asset.get("end_line", 0) > existing.get("end_line", 0):
                existing["end_line"] = asset["end_line"]
            # Update class_name if the current one is more specific
            if existing.get("class_name") == "Unknown" and asset.get("class_name") != "Unknown":
                existing["class_name"] = asset["class_name"]

    return list(groups.values())


# =============================================================================
# EMPTY RESULT
# =============================================================================

def _empty_agentic_result() -> Dict:
    """Return empty result when no agentic frameworks are present."""
    return {
        "agentic_assets": [],
        "all_assets": [],
        "summary": {
            "total_assets": 0,
            "total_agents": 0,
            "total_tasks": 0,
            "total_crews": 0,
            "frameworks_scanned": [],
            "files_scanned": 0,
            "errors": [],
        },
    }
