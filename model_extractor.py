"""
Model Extractor Module
Centralized model name extraction from semgrep findings.
Extensible patterns for different providers and formats.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# =============================================================================
# PROVIDER-SPECIFIC EXTRACTION PATTERNS
# =============================================================================

# Each extractor returns (model_name, provider) or (None, None)
# Extractors are tried in order - first match wins

METAVAR_PRIORITY = [
    "$MODEL",
    "$MODEL_NAME", 
    "$MODEL_ID",
    "$VALUE",
    "$REPLICATE_MODEL",  # For replicate.run("model", ...)
]

# Provider-specific patterns for code extraction
# Format: (regex_pattern, provider_name, group_number)
PROVIDER_CODE_PATTERNS: List[Tuple[str, str, int]] = [
    # Replicate: replicate.run("owner/model:version", ...)
    (r'\.run\s*\(\s*["\']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+[^"\']*)["\']', "replicate", 1),
    
    # Replicate stream: replicate.stream("owner/model:version", ...)
    (r'\.stream\s*\(\s*["\']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+[^"\']*)["\']', "replicate", 1),
    
    # OpenAI/Anthropic/Google: model: "gpt-4", model: "claude-3", etc.
    (r'model\s*[=:]\s*["\']([^"\']+)["\']', "generic", 1),
    
    # modelName: "gpt-4" (LangChain style)
    (r'modelName\s*[=:]\s*["\']([^"\']+)["\']', "langchain", 1),
    
    # model_name: "gpt-4" (Python style)
    (r'model_name\s*[=:]\s*["\']([^"\']+)["\']', "generic", 1),
    
    # getGenerativeModel({ model: "gemini-pro" })
    (r'getGenerativeModel\s*\(\s*\{\s*model\s*:\s*["\']([^"\']+)["\']', "google", 1),
    
    # HuggingFace: from_pretrained("model-name")
    (r'from_pretrained\s*\(\s*["\']([^"\']+)["\']', "huggingface", 1),
    
    # OpenAI constructor: openai("gpt-4")
    (r'openai\s*\(\s*["\']([^"\']+)["\']', "openai", 1),
    
    # Anthropic constructor: anthropic("claude-3")
    (r'anthropic\s*\(\s*["\']([^"\']+)["\']', "anthropic", 1),
    
    # Google constructor: google("gemini-pro")
    (r'google\s*\(\s*["\']([^"\']+)["\']', "google", 1),
]

# Message extraction patterns (from semgrep message field)
MESSAGE_PATTERNS: List[Tuple[str, int]] = [
    # "model: gpt-4" or "model detected: gpt-4"
    (r'model[^:]*:\s*([a-zA-Z0-9_\-\.\/\:]+)$', 1),
    
    # Quoted value: 'gpt-4' or "gpt-4"
    (r"['\"]([^'\"]+)['\"]", 1),
    
    # Replicate format in message: "stability-ai/stable-diffusion:abc123"
    (r'([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+:[a-f0-9]+)', 1),
]

# False positives to filter out
FALSE_POSITIVES = {
    "model_name", "model", "name", "models", "model_id",
    "modelname", "model_type", "type", "api", "endpoint",
    "client", "config", "options", "params", "settings",
    "default", "none", "null", "undefined", "true", "false",
    "process", "env", "string", "object", "array",
    "$model", "$value", "$model_name",
}


# =============================================================================
# EXTRACTION FUNCTIONS
# =============================================================================

def extract_from_metavars(metavars: Dict) -> Optional[str]:
    """Extract model from semgrep metavariables (most reliable)."""
    for metavar_key in METAVAR_PRIORITY:
        val = metavars.get(metavar_key, {}).get("abstract_content", "")
        if val and val.strip():
            logger.debug(f"[MODEL_EXTRACT] Found {metavar_key}='{val}'")
            return val.strip()
    return None


def extract_from_message(message: str) -> Optional[str]:
    """Extract model from semgrep message field."""
    if not message:
        return None
    
    for pattern, group in MESSAGE_PATTERNS:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            val = match.group(group)
            logger.debug(f"[MODEL_EXTRACT] Matched message pattern: '{val}'")
            return val
    
    return None


def extract_from_code(code: str, rule_id: str = "") -> Tuple[Optional[str], Optional[str]]:
    """
    Extract model from code snippet.
    Returns (model_name, provider) tuple.
    """
    if not code:
        return None, None
    
    # Determine provider hint from rule_id
    provider_hint = None
    rule_lower = rule_id.lower()
    if "replicate" in rule_lower:
        provider_hint = "replicate"
    elif "openai" in rule_lower:
        provider_hint = "openai"
    elif "anthropic" in rule_lower:
        provider_hint = "anthropic"
    elif "google" in rule_lower or "gemini" in rule_lower:
        provider_hint = "google"
    elif "langchain" in rule_lower:
        provider_hint = "langchain"
    elif "huggingface" in rule_lower or "hf" in rule_lower:
        provider_hint = "huggingface"
    
    # Try provider-specific patterns first if we have a hint
    if provider_hint:
        for pattern, provider, group in PROVIDER_CODE_PATTERNS:
            if provider == provider_hint or provider == "generic":
                match = re.search(pattern, code, re.IGNORECASE)
                if match:
                    val = match.group(group)
                    logger.debug(f"[MODEL_EXTRACT] Matched provider '{provider}' pattern: '{val}'")
                    return val, provider
    
    # Try all patterns
    for pattern, provider, group in PROVIDER_CODE_PATTERNS:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            val = match.group(group)
            logger.debug(f"[MODEL_EXTRACT] Matched code pattern for '{provider}': '{val}'")
            return val, provider
    
    return None, None


def clean_model_value(value: str) -> Optional[str]:
    """Clean and validate a model value."""
    if not value:
        return None
    
    value = value.strip()
    
    # Remove prefix
    if value.startswith("models/"):
        value = value[7:]
    
    # Filter false positives
    if value.lower() in FALSE_POSITIVES:
        return None
    
    # Must have some meaningful content
    if len(value) < 2:
        return None
    
    # Filter out variable references
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
    extra = finding.get("extra", {}) or {}
    metavars = extra.get("metavars", {}) or {}
    rule_id = finding.get("check_id", "")
    
    logger.debug(f"[MODEL_EXTRACT] Processing finding: {rule_id}")
    logger.debug(f"[MODEL_EXTRACT] Metavars present: {list(metavars.keys())}")
    
    model_value = None
    provider = None
    
    # 1. Try metavars first (most reliable)
    model_value = extract_from_metavars(metavars)
    
    # 2. Try message field
    if not model_value:
        message = extra.get("message", "")
        model_value = extract_from_message(message)
    
    # 3. Try code extraction
    if not model_value:
        code = extra.get("lines", "")
        model_value, provider = extract_from_code(code, rule_id)
    
    # Clean and validate
    if model_value:
        cleaned = clean_model_value(model_value)
        if cleaned:
            logger.info(f"[MODEL_EXTRACT] ✓ Extracted model: '{cleaned}' (provider: {provider or 'unknown'})")
            return cleaned
        else:
            logger.debug(f"[MODEL_EXTRACT] Value '{model_value}' filtered as false positive")
    
    logger.debug(f"[MODEL_EXTRACT] No model value found in this finding")
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
    
    # Parse Replicate format
    result = {
        "full_name": model_value,
        "owner": None,
        "model": None,
        "version": None
    }
    
    # Split owner/model:version
    if "/" in model_value:
        parts = model_value.split("/", 1)
        result["owner"] = parts[0]
        
        model_part = parts[1]
        if ":" in model_part:
            model_parts = model_part.split(":", 1)
            result["model"] = model_parts[0]
            result["version"] = model_parts[1]
        else:
            result["model"] = model_part
    else:
        result["model"] = model_value
    
    return result


def get_model_provider(model_name: str) -> str:
    """
    Determine the provider from a model name.
    """
    model_lower = model_name.lower()
    
    # OpenAI patterns
    if any(p in model_lower for p in ["gpt-", "o1-", "o3-", "o4-", "text-embedding-", "dall-e", "whisper"]):
        return "openai"
    
    # Anthropic patterns
    if any(p in model_lower for p in ["claude-", "anthropic"]):
        return "anthropic"
    
    # Google patterns
    if any(p in model_lower for p in ["gemini-", "palm-", "bard"]):
        return "google"
    
    # Replicate patterns (owner/model format)
    if "/" in model_name:
        return "replicate"
    
    # Meta/Llama patterns
    if any(p in model_lower for p in ["llama-", "llama2", "llama3", "meta-llama"]):
        return "meta"
    
    # Mistral patterns
    if "mistral" in model_lower:
        return "mistral"
    
    # Cohere patterns
    if any(p in model_lower for p in ["command-", "cohere"]):
        return "cohere"
    
    return "unknown"
