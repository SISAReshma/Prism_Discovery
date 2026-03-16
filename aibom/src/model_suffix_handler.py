"""
Model Name Parser - Strips variant suffixes to find base models
Handles customized model names like gemma-3-4b-it-qat → gemma-3

Copied from Prism-AIBOM for use in AIBOM_endpoints.
"""
import re

# Comprehensive suffix dictionary with meanings
MODEL_SUFFIXES = {
    # Tuning/Purpose suffixes
    "base": "Untuned core model — not fine-tuned for a specific task. Often the raw pretrained weights.",
    "instruct": "Fine-tuned to follow instructions/prompts. Often better at direct answer tasks.",
    "chat": "Tuned for conversational interaction (dialogue history, coherent multi-turn).",
    "code": "Specialized for programming/code generation tasks.",
    "vision": "Multi-modal or visual-capable model (text + image).",
    "embedding": "Produces vector embeddings rather than generative outputs.",
    "distill": "Indicates a distilled (smaller/efficient) model from a larger teacher model.",
    "fine-tuned": "Explicitly customized for a particular domain or task.",
    "it": "Instruction tuned - fine-tuned to follow instructions.",
    "ft": "Fine-tuned for specific tasks or domains.",
    "turbo": "Optimized for faster inference with similar quality.",
    "mini": "Smaller, more efficient variant of the model.",
    "nano": "Very small variant for edge devices.",
    "pro": "Professional/enhanced variant with better capabilities.",
    "plus": "Enhanced variant with additional capabilities.",
    "ultra": "Top-tier variant with maximum capabilities.",
    
    # Quantization suffixes
    "q2": "2-bit quantization - smallest size, fastest, least accurate.",
    "q3": "3-bit quantization - very compact, fast inference.",
    "q4": "4-bit quantization - balanced size and quality.",
    "q5": "5-bit quantization - good quality with compression.",
    "q6": "6-bit quantization - high quality with moderate compression.",
    "q8": "8-bit quantization - near-original quality.",
    "qat": "Quantization-aware training - model trained with quantization in mind.",
    "fp16": "16-bit floating-point precision format.",
    "fp32": "32-bit floating-point precision format (full precision).",
    "int8": "8-bit integer quantization.",
    "int4": "4-bit integer quantization.",
    
    # Advanced quantization methods
    "k": "K-quant method — advanced quantization scheme used in llama.cpp.",
    "iq": "Importance Quantization — weighting importance for quantization.",
    "gguf": "GGUF format - efficient model format for llama.cpp.",
    "ggml": "GGML format - predecessor to GGUF.",
    "awq": "Activation-aware Weight Quantization - advanced quantization method.",
    "gptq": "GPT Quantization - quantization method for large language models.",
    
    # Precision variants
    "s": "Small block or lowest precision variant (fastest, least accurate).",
    "m": "Medium block / balanced precision.",
    "l": "Large block / higher precision (better quality).",
    "xs": "Extra small - minimal size variant.",
    "xxs": "Extra-extra small - smallest variant.",
    "xl": "Extra large - larger model variant.",
    "xxl": "Extra-extra large - largest model variant.",
    
    # Platform/Format suffixes
    "onnx": "ONNX format - optimized for cross-platform inference.",
    "openvino": "OpenVINO optimized model.",
    "tensorrt": "TensorRT optimized for NVIDIA GPUs.",
    "coreml": "Core ML format for Apple devices.",
    "onnxruntime": "ONNX Runtime optimized.",
    
    # Other common suffixes
    "uncased": "Text processing without case sensitivity.",
    "cased": "Text processing with case sensitivity.",
    "multilingual": "Supports multiple languages.",
    "en": "English language specific.",
    "v1": "Version 1",
    "v2": "Version 2",
    "v3": "Version 3",
    "alpha": "Alpha release version.",
    "beta": "Beta release version.",
    "preview": "Preview/early access version.",
    "latest": "Latest available version."
}

# Token window patterns (context length / max tokens)
TOKEN_WINDOW_SUFFIXES = {
    "2k": {"tokens": 2000, "meaning": "2,000 token context window"},
    "4k": {"tokens": 4000, "meaning": "4,000 token context window"},
    "8k": {"tokens": 8000, "meaning": "8,000 token context window"},
    "16k": {"tokens": 16000, "meaning": "16,000 token context window (extended)"},
    "32k": {"tokens": 32000, "meaning": "32,000 token context window (extended)"},
    "64k": {"tokens": 64000, "meaning": "64,000 token context window (large)"},
    "128k": {"tokens": 128000, "meaning": "128,000 token context window (very large)"},
    "200k": {"tokens": 200000, "meaning": "200,000 token context window (extra large)"},
    "1m": {"tokens": 1000000, "meaning": "1 million token context window"},
    "2m": {"tokens": 2000000, "meaning": "2 million token context window"},
}

# Parameter size patterns
PARAMETER_PATTERNS = {
    "m": "million parameters",
    "b": "billion parameters",
    "k": "thousand parameters"
}


def parse_suffix(suffix: str) -> dict:
    """
    Parse a single suffix and return its metadata.
    
    Args:
        suffix: Suffix string (e.g., "4b", "it", "qat", "16k")
    
    Returns:
        Dictionary with suffix info including type and meaning
    """
    suffix_lower = suffix.lower()
    
    # Check if it's a token window suffix (e.g., 16k, 32k, 128k)
    if suffix_lower in TOKEN_WINDOW_SUFFIXES:
        token_info = TOKEN_WINDOW_SUFFIXES[suffix_lower]
        return {
            "suffix": suffix,
            "type": "token_window",
            "meaning": token_info["meaning"],
            "token_count": token_info["tokens"]
        }
    
    # Check for dynamic token window pattern (e.g., 256k, 500k)
    token_match = re.match(r'^(\d+)k$', suffix_lower)
    if token_match:
        num = int(token_match.group(1))
        tokens = num * 1000
        return {
            "suffix": suffix,
            "type": "token_window",
            "meaning": f"{tokens:,} token context window",
            "token_count": tokens
        }
    
    # Check if it's a known suffix
    if suffix_lower in MODEL_SUFFIXES:
        return {
            "suffix": suffix,
            "type": "known",
            "meaning": MODEL_SUFFIXES[suffix_lower]
        }
    
    # Check if it's a parameter count (e.g., 4b, 125m, 70B)
    param_match = re.match(r'^(\d+\.?\d*)([mbMB])$', suffix)
    if param_match:
        number, unit = param_match.groups()
        unit_lower = unit.lower()
        unit_meaning = PARAMETER_PATTERNS.get(unit_lower, "parameters")
        return {
            "suffix": suffix,
            "type": "parameter_count",
            "meaning": f"{number} {unit_meaning}",
            "parameter_count": f"{number}{unit.upper()}"
        }
    
    # Check if it's a version number (e.g., 3, 3.1, 3.2)
    if re.match(r'^\d+(\.\d+)?$', suffix):
        return {
            "suffix": suffix,
            "type": "version",
            "meaning": f"Version {suffix}"
        }
    
    # Unknown suffix
    return {
        "suffix": suffix,
        "type": "unknown",
        "meaning": "Unknown suffix variant"
    }


def strip_model_name_incrementally(model_name: str):
    """
    Incrementally strip suffixes from model name (right to left).
    
    Args:
        model_name: Full model name (e.g., "gemma-3-4b-it-qat")
    
    Yields:
        Tuples of (stripped_name, removed_suffixes)
        Example: ("gemma-3-4b-it", ["qat"]), ("gemma-3-4b", ["it", "qat"]), ...
    """
    parts = model_name.split('-')
    
    # Don't strip if only 1-2 parts
    if len(parts) <= 2:
        return
    
    # Strip from right, one at a time
    removed_suffixes = []
    for i in range(len(parts) - 1, 1, -1):  # Keep at least first 2 parts
        removed_suffix = parts[i]
        removed_suffixes.insert(0, removed_suffix)  # Insert at beginning to maintain order
        
        stripped_name = '-'.join(parts[:i])
        yield stripped_name, removed_suffixes.copy()


def parse_model_name(full_name: str, base_name: str = None) -> dict:
    """
    Parse model name and extract variant information.
    
    Args:
        full_name: Full model name as detected in code
        base_name: Base model name if found via stripping (optional)
    
    Returns:
        Dictionary with parsed information
    """
    result = {
        "full_name": full_name,
        "base_name": base_name or full_name,
        "is_variant": base_name is not None and base_name != full_name,
        "suffixes": []
    }
    
    # If it's a variant, parse the removed suffixes
    if result["is_variant"]:
        full_parts = full_name.split('-')
        base_parts = base_name.split('-')
        
        # Suffixes are the parts that were removed
        removed_parts = full_parts[len(base_parts):]
        
        for suffix in removed_parts:
            suffix_info = parse_suffix(suffix)
            result["suffixes"].append(suffix_info)
        
        # Categorize suffixes
        result["parameter_count"] = None
        result["quantization"] = []
        result["tuning_type"] = []
        result["token_window"] = None
        result["version"] = None
        
        for suffix_info in result["suffixes"]:
            if suffix_info["type"] == "parameter_count":
                result["parameter_count"] = suffix_info.get("parameter_count")
            elif suffix_info["type"] == "token_window":
                result["token_window"] = suffix_info.get("token_count")
            elif suffix_info["suffix"].lower() in ["q2", "q3", "q4", "q5", "q6", "q8", "qat", "fp16", "fp32", "int8", "int4", "awq", "gptq"]:
                result["quantization"].append(suffix_info["suffix"])
            elif suffix_info["suffix"].lower() in ["base", "instruct", "chat", "code", "vision", "embedding", "it", "ft", "turbo", "mini", "nano", "pro", "plus", "ultra"]:
                result["tuning_type"].append(suffix_info["suffix"])
            elif suffix_info["type"] == "version":
                result["version"] = suffix_info["suffix"]
    
    return result


def extract_suffix_info(model_name: str) -> dict:
    """
    Extract and interpret suffix information from model name.
    
    Args:
        model_name: Full model name (e.g., "gpt-3.5-turbo-16k")
    
    Returns:
        Dictionary with parsed suffix information
    """
    result = {
        "has_suffixes": False,
        "parsed_suffixes": [],
        "token_window": None,
        "parameter_count": None,
        "quantization": None,
        "tuning_type": None,
        "display_notes": []
    }
    
    parts = model_name.split('-')
    if len(parts) <= 2:
        return result
    
    # Check the last few parts for known suffixes
    for i in range(len(parts) - 1, max(1, len(parts) - 4), -1):
        suffix = parts[i]
        parsed = parse_suffix(suffix)
        
        if parsed["type"] != "unknown":
            result["has_suffixes"] = True
            result["parsed_suffixes"].append(parsed)
            
            # Extract specific info based on type
            if parsed["type"] == "token_window":
                result["token_window"] = parsed.get("token_count")
                result["display_notes"].append(f"Context: {parsed['meaning']}")
            elif parsed["type"] == "parameter_count":
                result["parameter_count"] = parsed.get("parameter_count")
                result["display_notes"].append(f"Size: {parsed['meaning']}")
            elif parsed["type"] == "known":
                meaning = parsed["meaning"]
                # Categorize known suffixes
                if any(q in suffix.lower() for q in ["q2", "q3", "q4", "q5", "q6", "q8", "qat", "gptq", "awq"]):
                    result["quantization"] = suffix
                    result["display_notes"].append(f"Quantization: {meaning}")
                elif suffix.lower() in ["instruct", "it", "chat", "ft", "base", "turbo", "mini", "nano", "pro", "plus", "ultra"]:
                    result["tuning_type"] = suffix
                    result["display_notes"].append(f"Tuning: {meaning}")
                else:
                    result["display_notes"].append(meaning)
    
    return result
