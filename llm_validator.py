"""
LLM Validator for AI Library Classification
Validates and classifies libraries as AI-positive or non-AI using Groq LLM.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

from config import (
    LLM_BATCH_SIZE,
    LLM_MAX_TOKENS_PER_LIB,
    LLM_MAX_TOKENS_CAP,
    LLM_MIN_TOKENS,
    LLM_TEMPERATURE,
    LLM_SYSTEM_PROMPT,
    SUPPORTED_LANGUAGES,
)

# Load environment variables once at module load
load_dotenv(Path(__file__).parent / ".env")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
LLM_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

# Lazy-loaded client
_groq_client = None

# =============================================================================
# Client & Helpers
# =============================================================================

def get_groq_client():
    """Get or create Groq client (lazy loading)."""
    global _groq_client
    if _groq_client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in environment")
        from groq import Groq
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


def _empty_result() -> Dict:
    """Return empty validation result structure."""
    return {
        "ai_libraries": [],
        "non_ai_libraries": [],
        "total_classified": 0,
        "total_ai_positive": 0,
        "total_non_ai": 0,
        "model_used": LLM_MODEL
    }

# =============================================================================
# Single Entry Point
# =============================================================================

def validate_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict,
    resolved_packages: Optional[Dict] = None
) -> Optional[Dict]:
    """
    Main validation function - collects libraries, classifies, returns result.
    Args:
        manifest_deps: Dependencies from manifests {"python": [...], "javascript": [...]}
        import_packages: Import packages from /filtered-imports endpoint
        resolved_packages: Optional resolved/merged packages from /resolve-packages 
    Returns:
        Validation result or None if classification failed
    """
    # Step 1: Extract libraries and build source lookup from appropriate input
    libraries, source_lookup = _extract_libraries(
        manifest_deps, import_packages, resolved_packages
    )
    if not libraries:
        return _empty_result()
    
    # Step 2: Classify with LLM
    logger.info(f"Classifying {len(libraries)} libraries...")
    classifications = classify_libraries(libraries)
    
    if not classifications:
        return None
    
    # Step 3: Build result (single pass through classifications)
    return _build_result(classifications, source_lookup)

# =============================================================================
# Step 1: Extract Libraries
# =============================================================================

def _build_source_files_lookup(import_packages: Dict) -> Dict[str, List[str]]:
    """
    Build a lookup of package -> source_files from import_packages.
    This data comes from semgrep scan and has file locations.
    """
    source_lookup = {}
    
    # Use configured language keys for future extensibility
    for import_key in SUPPORTED_LANGUAGES.values():
        for imp in import_packages.get(import_key, []):
            pkg_name = imp.get("package", "")
            if pkg_name:
                if pkg_name not in source_lookup:
                    source_lookup[pkg_name] = []
                # Add source files, avoiding duplicates
                for f in imp.get("source_files", []):
                    if f and f not in source_lookup[pkg_name]:
                        source_lookup[pkg_name].append(f)
    
    return source_lookup


def _extract_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict,
    resolved_packages: Optional[Dict]
) -> Tuple[List[str], Dict[str, Dict]]:
    """
    Extract unique library names and source lookup from inputs.
    
    Returns:
        Tuple of (sorted library names, source file lookup dict)
    """
    # Build source files lookup from import_packages (has file locations)
    source_files_map = _build_source_files_lookup(import_packages)
    
    # Use resolved packages if available (already deduplicated)
    # Check for both possible data structures
    if resolved_packages:
        # Structure from package_resolver.py: {"resolved_packages": [...]}
        resolved_list = resolved_packages.get("resolved_packages", [])
        
        # Legacy structure: {"unified_packages": [...]}
        if not resolved_list:
            resolved_list = resolved_packages.get("unified_packages", [])
        
        if resolved_list:
            # Build lookup and collect names in single pass
            lookup = {}
            libraries = []
            for pkg in resolved_list:
                # Handle both key formats: "package" (new) or "library" (legacy)
                lib_name = pkg.get("package") or pkg.get("library", "")
                if lib_name:
                    libraries.append(lib_name)
                    # Get source files from import_packages lookup
                    pkg_source_files = source_files_map.get(lib_name, [])
                    # Also check import_names for alternate lookups
                    for import_name in pkg.get("import_names", []):
                        if import_name in source_files_map:
                            for f in source_files_map[import_name]:
                                if f not in pkg_source_files:
                                    pkg_source_files.append(f)
                    
                    lookup[lib_name] = {
                        "language": pkg.get("language"),
                        "source_files": pkg_source_files,
                        "import_names": pkg.get("import_names", []),
                        "is_used": pkg.get("is_used", True)
                    }
            
            return sorted(set(libraries)), lookup
    
    # If no resolved_packages provided, this is an error in the pipeline
    raise ValueError(
        "resolved_packages is required. Call /resolve-packages endpoint first."
    )
# =============================================================================
# Step 2: Classify with LLM
# =============================================================================

def call_llm_batch(
    items: List,
    system_prompt: str,
    user_message: str,
    item_formatter=None
) -> List[Dict]:
    """
    Generic LLM batch call - shared by validator and categorizer.
    
    Args:
        items: List of items to process (strings or dicts)
        system_prompt: System prompt for LLM
        user_message: User message prefix (items will be appended)
        item_formatter: Optional function to format each item (default: str)
    
    Returns:
        Parsed JSON array from LLM response
    """
    if not items:
        return []
    
    client = get_groq_client()
    
    # Format items for prompt
    formatter = item_formatter or str
    lib_list = "\n".join(f"- {formatter(item)}" for item in items)
    
    messages = [
        {"role": "system", "content": system_prompt.strip()},
        {"role": "user", "content": f"{user_message}\n{lib_list}"}
    ]
    
    # Token estimation
    max_tokens = min(
        max(LLM_MIN_TOKENS, len(items) * LLM_MAX_TOKENS_PER_LIB + 500),
        LLM_MAX_TOKENS_CAP
    )
    
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=LLM_TEMPERATURE,
            max_tokens=max_tokens
        )
        
        choice = response.choices[0]
        if choice.finish_reason == "length":
            logger.warning(f"Response truncated at {max_tokens} tokens")
        
        return _parse_llm_response(choice.message.content)
        
    except Exception as e:
        logger.error(f"LLM API error: {e}")
        return []


def process_in_batches(
    items: List,
    batch_processor,
    batch_size: int = LLM_BATCH_SIZE
) -> List[Dict]:
    """
    Generic batch processor - shared by validator and categorizer.
    Args:
        items: List of items to process
        batch_processor: Function to process each batch
        batch_size: Items per batch
    Returns:
        Combined results from all batches
    """
    if not items:
        return []
    
    # Single batch - no overhead
    if len(items) <= batch_size:
        return batch_processor(items)
    
    # Multiple batches
    results = []
    total_batches = -(-len(items) // batch_size)
    
    for batch_num, i in enumerate(range(0, len(items), batch_size), 1):
        batch = items[i:i + batch_size]
        logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} items)")
        results.extend(batch_processor(batch))
    
    return results


def classify_libraries(libraries: List[str]) -> List[Dict]:
    """
    Classify all libraries, batching if necessary.
    Args:
        libraries: Sorted list of unique library names
    Returns:
        List of classification results
    """
    return process_in_batches(libraries, _classify_batch)


def _classify_batch(libraries: List[str]) -> List[Dict]:
    """Classify a single batch of libraries using LLM."""
    return call_llm_batch(
        items=libraries,
        system_prompt=LLM_SYSTEM_PROMPT,
        user_message="Classify these libraries:"
    )

def _parse_llm_response(text: str) -> List[Dict]:
    """Extract JSON array from LLM response."""
    # Try markdown code block
    if "```json" in text:
        start = text.find("```json") + 7
        end = text.find("```", start)
        if end != -1:
            try:
                return json.loads(text[start:end].strip())
            except json.JSONDecodeError:
                pass
    
    # Try raw JSON array
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return []
    
    logger.error("No JSON array found in response")
    return []

# =============================================================================
# Step 3: Build Result
# =============================================================================

def _build_result(
    classifications: List[Dict],
    source_lookup: Dict[str, Dict]
) -> Dict:
    """
    Build final validation result in single pass through classifications.
    
    Args:
        classifications: LLM classification results
        source_lookup: lib_name → {language, source_files} mapping
    """
    ai_libraries = []
    non_ai = []
    
    for item in classifications:
        lib_name = item.get("library", "")
        is_ai = (
            item.get("classification") == "AI_POSITIVE" 
            and item.get("confidence") == "HIGH"
        )
        
        if is_ai:
            entry = {
                "library": lib_name,
                "confidence": "HIGH [default]",
                "reason": item.get("reason", ""),
                "source_files": []
            }
            # Enrich from lookup
            if lib_name in source_lookup:
                entry["source_files"] = source_lookup[lib_name]["source_files"]
                entry["language"] = source_lookup[lib_name]["language"]
            ai_libraries.append(entry)
        else:
            non_ai.append(lib_name)
    
    return {
        "ai_libraries": ai_libraries,
        "non_ai_libraries": non_ai,
        "total_classified": len(classifications),
        "total_ai_positive": len(ai_libraries),
        "total_non_ai": len(non_ai),
        "model_used": LLM_MODEL
    }