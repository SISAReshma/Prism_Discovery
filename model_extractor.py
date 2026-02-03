"""
Model Extractor Module - Optimized
Centralized model name extraction from semgrep findings.
Extensible patterns for different providers and formats.

"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Pattern
from functools import lru_cache

from config import (
    MODEL_METAVAR_PRIORITY,
    MODEL_FALSE_POSITIVES,
    MODEL_PROVIDER_PATTERNS,
    RULE_PROVIDER_KEYWORDS,
)

logger = logging.getLogger(__name__)


# =============================================================================
# PRE-COMPILED REGEX PATTERNS (compiled once at module load)
# =============================================================================

# Provider-specific patterns: (compiled_pattern, provider_name)
_CODE_PATTERNS: List[Tuple[Pattern, str]] = [
    # Replicate: replicate.run("owner/model:version", ...)
    (re.compile(r'\.run\s*\(\s*["\']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+[^"\']*)["\']', re.IGNORECASE), "replicate"),
    
    # Replicate stream: replicate.stream("owner/model:version", ...)
    (re.compile(r'\.stream\s*\(\s*["\']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+[^"\']*)["\']', re.IGNORECASE), "replicate"),
    
    # OpenAI/Anthropic/Google: model: "gpt-4", model: "claude-3", etc.
    (re.compile(r'model\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE), "generic"),
    
    # modelName: "gpt-4" (LangChain style)
    (re.compile(r'modelName\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE), "langchain"),
    
    # model_name: "gpt-4" (Python style)
    (re.compile(r'model_name\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE), "generic"),
    
    # getGenerativeModel({ model: "gemini-pro" })
    (re.compile(r'getGenerativeModel\s*\(\s*\{\s*model\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE), "google"),
    
    # HuggingFace: from_pretrained("model-name")
    (re.compile(r'from_pretrained\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "huggingface"),
    
    # OpenAI constructor: openai("gpt-4")
    (re.compile(r'openai\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "openai"),
    
    # Anthropic constructor: anthropic("claude-3")
    (re.compile(r'anthropic\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "anthropic"),
    
    # Google constructor: google("gemini-pro")
    (re.compile(r'google\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "google"),
]

# Message extraction patterns (pre-compiled)
_MESSAGE_PATTERNS: List[Pattern] = [
    # "model: gpt-4" or "model detected: gpt-4"
    re.compile(r'model[^:]*:\s*([a-zA-Z0-9_\-\.\/\:]+)$', re.IGNORECASE),
    
    # Quoted value: 'gpt-4' or "gpt-4"
    re.compile(r"['\"]([^'\"]+)['\"]"),
    
    # Replicate format in message: "stability-ai/stable-diffusion:abc123"
    re.compile(r'([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+:[a-f0-9]+)'),
]


# =============================================================================
# EXTRACTION FUNCTIONS
# =============================================================================

def extract_from_metavars(metavars: Dict) -> Optional[str]:
    """Extract model from semgrep metavariables (most reliable)."""
    for metavar_key in MODEL_METAVAR_PRIORITY:
        val = metavars.get(metavar_key, {}).get("abstract_content", "")
        if val and val.strip():
            logger.debug(f"[MODEL_EXTRACT] Found {metavar_key}='{val}'")
            return val.strip()
    return None


def extract_from_message(message: str) -> Optional[str]:
    """Extract model from semgrep message field using pre-compiled patterns."""
    if not message:
        return None
    
    for pattern in _MESSAGE_PATTERNS:
        if match := pattern.search(message):
            val = match.group(1)
            logger.debug(f"[MODEL_EXTRACT] Matched message pattern: '{val}'")
            return val
    
    return None


@lru_cache(maxsize=64)
def _get_provider_hint(rule_id: str) -> Optional[str]:
    """Get provider hint from rule ID (cached for repeated lookups)."""
    rule_lower = rule_id.lower()
    for keyword, provider in RULE_PROVIDER_KEYWORDS.items():
        if keyword in rule_lower:
            return provider
    return None


def extract_from_code(code: str, rule_id: str = "") -> Tuple[Optional[str], Optional[str]]:
    """
    Extract model from code snippet using pre-compiled patterns.
    Returns (model_name, provider) tuple.
    """
    if not code:
        return None, None
    
    provider_hint = _get_provider_hint(rule_id) if rule_id else None
    
    # If we have a provider hint, try matching patterns for that provider first
    if provider_hint:
        for pattern, provider in _CODE_PATTERNS:
            if provider == provider_hint or provider == "generic":
                if match := pattern.search(code):
                    val = match.group(1)
                    logger.debug(f"[MODEL_EXTRACT] Matched provider '{provider}' pattern: '{val}'")
                    return val, provider
    
    # Try all patterns
    for pattern, provider in _CODE_PATTERNS:
        if match := pattern.search(code):
            val = match.group(1)
            logger.debug(f"[MODEL_EXTRACT] Matched code pattern for '{provider}': '{val}'")
            return val, provider
    
    return None, None


def clean_model_value(value: str) -> Optional[str]:
    """Clean and validate a model value."""
    if not value:
        return None
    
    value = value.strip()
    
    # Remove "models/" prefix
    if value.startswith("models/"):
        value = value[7:]
    
    # Quick validation checks (ordered by likelihood of failure)
    if len(value) < 2:
        return None
    
    if value.lower() in MODEL_FALSE_POSITIVES:
        return None
    
    if value.startswith("$") or value.startswith("process.env"):
        return None
    
    return value


def extract_model_value(finding: Dict) -> Optional[str]:
    """
    Extract model name from a semgrep finding.
    Main entry point for model extraction.
    
    Priority:
    1. Metavariables ($MODEL, $VALUE, etc.)
    2. Message field
    3. Code extraction with provider patterns
    """
    extra = finding.get("extra") or {}
    metavars = extra.get("metavars") or {}
    rule_id = finding.get("check_id", "")
    
    logger.debug(f"[MODEL_EXTRACT] Processing finding: {rule_id}")
    logger.debug(f"[MODEL_EXTRACT] Metavars present: {list(metavars.keys())}")
    
    # 1. Try metavars first (most reliable)
    if model_value := extract_from_metavars(metavars):
        if cleaned := clean_model_value(model_value):
            logger.info(f"[MODEL_EXTRACT] ✓ Extracted model: '{cleaned}' (source: metavar)")
            return cleaned
    
    # 2. Try message field
    if model_value := extract_from_message(extra.get("message", "")):
        if cleaned := clean_model_value(model_value):
            logger.info(f"[MODEL_EXTRACT] ✓ Extracted model: '{cleaned}' (source: message)")
            return cleaned
    
    # 3. Try code extraction
    model_value, provider = extract_from_code(extra.get("lines", ""), rule_id)
    if model_value:
        if cleaned := clean_model_value(model_value):
            logger.info(f"[MODEL_EXTRACT] ✓ Extracted model: '{cleaned}' (provider: {provider or 'unknown'})")
            return cleaned
    
    logger.debug("[MODEL_EXTRACT] No model value found in this finding")
    return None


def extract_replicate_model(finding: Dict) -> Optional[Dict]:
    """
    Extract Replicate-specific model information.
    Returns dict with owner, model, version if available.
    
    Format: owner/model:version (e.g., "stability-ai/stable-diffusion:db21e45d...")
    """
    model_value = extract_model_value(finding)
    
    if not model_value:
        return None
    
    result = {
        "full_name": model_value,
        "owner": None,
        "model": None,
        "version": None
    }
    
    # Parse Replicate format: owner/model:version
    if "/" in model_value:
        owner, model_part = model_value.split("/", 1)
        result["owner"] = owner
        
        if ":" in model_part:
            model_name, version = model_part.split(":", 1)
            result["model"] = model_name
            result["version"] = version
        else:
            result["model"] = model_part
    else:
        result["model"] = model_value
    
    return result


def get_model_provider(model_name: str) -> str:
    """
    Determine the provider from a model name.
    Uses pre-built pattern sets for O(1) average lookup.
    """
    model_lower = model_name.lower()
    
    # Check each provider's patterns
    for provider, patterns in MODEL_PROVIDER_PATTERNS.items():
        if any(pattern in model_lower for pattern in patterns):
            return provider
    
    # Special case: Replicate format (owner/model)
    if "/" in model_name:
        return "replicate"
    
    return "unknown"
