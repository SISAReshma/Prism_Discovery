"""
Model Extractor Module - Optimized
Centralized model name extraction from semgrep findings.
Extensible patterns for different providers and formats.

"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Pattern
from functools import lru_cache

from aibom.config import (
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
    
    # SentenceTransformer("all-mpnet-base-v2") or SentenceTransformer('model/name')
    (re.compile(r'SentenceTransformer\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "huggingface"),
    
    # CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
    (re.compile(r'CrossEncoder\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "huggingface"),
    
    # Ollama: ollama.chat(model="qwen3:8b") / ollama.generate(model="llama3.1:8b")
    (re.compile(r'ollama\.\w+\s*\([^)]*model\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE), "ollama"),
    
    # Keras/TensorFlow: load_model("toxic.keras") / tf.keras.models.load_model("PI33.keras")
    (re.compile(r'load_model\s*\(\s*["\']([^"\']+\.(?:keras|h5|pb|savedmodel|tflite))["\']', re.IGNORECASE), "keras"),
    
    # Keras/TensorFlow: load_model with variable path containing model filename
    (re.compile(r'load_model\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "keras"),
    
    # Scikit-learn / joblib: pickle.load / joblib.load for .pkl model files
    (re.compile(r'(?:pickle|joblib)\.load\s*\(\s*(?:open\s*\(\s*)?["\']([^"\']+\.pkl)["\']', re.IGNORECASE), "sklearn"),
    
    # torch.load("model.pt") / torch.load("model.pth")
    (re.compile(r'torch\.load\s*\(\s*["\']([^"\']+\.(?:pt|pth|bin|safetensors))["\']', re.IGNORECASE), "pytorch"),
    
    # NLTK: nltk.download("punkt") / nltk.download('stopwords')
    (re.compile(r'nltk\.download\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "nltk"),
    
    # OpenAI constructor: openai("gpt-4")
    (re.compile(r'openai\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "openai"),
    
    # Anthropic constructor: anthropic("claude-3")
    (re.compile(r'anthropic\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "anthropic"),
    
    # Google constructor: google("gemini-pro")
    (re.compile(r'google\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "google"),

    # C# .GetXxxClient("model-name") — official OpenAI .NET SDK
    (re.compile(r'\.Get(?:Chat|Embedding|Image|Audio)Client\s*\(\s*"([^"]+)"', re.IGNORECASE), "openai"),

    # C# auto-property: Model { get; set; } = "gpt-4o";
    (re.compile(r'\{\s*get;\s*set;\s*\}\s*=\s*"([^"]+)"', re.IGNORECASE), "generic"),

    # C# method call with string first arg: .AddOpenAIChatCompletion("gpt-4o", ...)
    (re.compile(r'\.\w+\s*\(\s*"([^"]+)"\s*[,)]', re.IGNORECASE), "generic"),

    # C# new Type("model-name", ...) or target-typed new("model-name", ...)
    # Catches: new ModelInfo("gpt-4o", ...), new("o1-preview", ...), etc.
    (re.compile(r'\bnew\s*(?:[A-Za-z][A-Za-z0-9_]*\s*)?\(\s*"([^"]+)"', re.IGNORECASE), "generic"),

    # OpenAI REST API URL with embedded model name
    # e.g. "https://api.openai.com/v1/engines/text-davinci-003/completions"
    (re.compile(r'api\.openai\.com/v1/engines/([a-zA-Z0-9._-]+)', re.IGNORECASE), "openai"),
    (re.compile(r'api\.openai\.com/v1/models/([a-zA-Z0-9._-]+)', re.IGNORECASE), "openai"),

    # Anthropic REST API URL with model in path
    (re.compile(r'api\.anthropic\.com/v1/(?:messages|complete)[^"]*model["\s:=]+["\']([^"\']+)', re.IGNORECASE), "anthropic"),

    # Java builder pattern: .model("gpt-4") / .setModel("gpt-4") / .withModel("gpt-4")
    (re.compile(r'\.(?:model|setModel|withModel|modelName|setModelName)\s*\(\s*"([^"]+)"', re.IGNORECASE), "generic"),

    # Java enum-style model reference: OpenAiChatModelName.GPT_4_O
    (re.compile(r'(?:OpenAi(?:Chat)?ModelName|ChatModelName|EmbeddingModelName|ModelName)\.\s*([A-Z][A-Z0-9_]+)', re.IGNORECASE), "langchain"),

    # Known AI model name as a bare quoted string (pattern-regex fallback)
    # Uses prefix matching so versioned variants like gpt-4-32k-0613 are caught
    # Note: character classes include `:` for Ollama format (qwen3:8b)
    (re.compile(
        r'"(gpt-4[a-z0-9\-]*'                   # gpt-4, gpt-4o, gpt-4-turbo, gpt-4-32k-0613 …
        r'|gpt-3\.5[a-z0-9\-]*'                  # gpt-3.5-turbo, gpt-3.5-turbo-0613 …
        r'|o1-[a-z0-9\-]+|o3-[a-z0-9\-]+'        # o1-preview, o1-mini, o3-mini
        r'|dall-e[a-z0-9\-]*'                     # dall-e-2, dall-e-3
        r'|text-embedding[a-z0-9\-]*'             # text-embedding-ada-002, text-embedding-3-small
        r'|text-davinci[a-z0-9\-]*'               # text-davinci-003
        r'|text-curie[a-z0-9\-]*'                 # text-curie-001
        r'|text-babbage[a-z0-9\-]*'               # text-babbage-001
        r'|text-ada[a-z0-9\-]*'                   # text-ada-001
        r'|text-moderation[a-z0-9\-]*'            # text-moderation-latest
        r'|davinci-[a-z0-9\-]+'                   # davinci-002 (not bare "davinci")
        r'|curie-[a-z0-9\-]+'                     # curie-001
        r'|babbage-[a-z0-9\-]+'                   # babbage-002
        r'|ada-[a-z0-9\-]+'                       # ada-002  (not bare "ada")
        r'|whisper[a-z0-9\-]*'                    # whisper-1
        r'|tts-[a-z0-9\-]+'                       # tts-1, tts-1-hd
        r'|claude-[a-z0-9.\-]+'                   # claude-2, claude-3-opus, claude-3-5-sonnet
        r'|gemini-[a-z0-9.\-]+'                   # gemini-pro, gemini-1.5-pro
        r'|llama[a-z0-9.:_\-]+'                   # llama-3, llama3.1, llama3.1:8b
        r'|mistral[a-z0-9.:_\-]+'                 # mistral-large, mistral-medium
        r'|phi-[a-z0-9.:_\-]+'                    # phi-3, phi-3.5-mini
        r'|qwen[a-z0-9/:._\-]+'                   # qwen-2, qwen3:8b, qwen/qwen3-32b
        r'|deepseek[a-z0-9/:._\-]+'               # deepseek-coder, deepseek-r1:8b
        r'|stable-diffusion[a-z0-9.\-]*'          # stable-diffusion-xl
        r'|command-r[a-z0-9\-]*'                  # command-r, command-r-plus
        r')"',
        re.IGNORECASE
    ), "generic"),
]

# Strict allowlist of known AI model name prefixes.
# scan_file_for_models() validates every extracted string against this.
# This prevents broad patterns from catching HTTP methods, headers,
# log messages, format strings, API keys, etc.
_VALID_MODEL_RE = re.compile(
    r'^(?:'
    r'gpt-4[a-z0-9\-]*'                    # gpt-4, gpt-4o, gpt-4-turbo, gpt-4-32k-0613
    r'|gpt-3\.5[a-z0-9\-]*'               # gpt-3.5-turbo, gpt-3.5-turbo-0613
    r'|gpt-3[a-z0-9\-]*'                   # gpt-3
    r'|o1-[a-z0-9\-]+'                     # o1-preview, o1-mini
    r'|o3-[a-z0-9\-]+'                     # o3-mini
    r'|dall-e[a-z0-9\-]*'                  # dall-e-2, dall-e-3
    r'|text-embedding[a-z0-9\-]*'          # text-embedding-ada-002, text-embedding-3-small
    r'|text-davinci[a-z0-9\-]*'            # text-davinci-003
    r'|text-curie[a-z0-9\-]*'              # text-curie-001
    r'|text-babbage[a-z0-9\-]*'            # text-babbage-001
    r'|text-ada[a-z0-9\-]*'               # text-ada-001
    r'|text-moderation[a-z0-9\-]*'         # text-moderation-latest
    r'|davinci-[a-z0-9\-]+'               # davinci-002, davinci-instruct-beta
    r'|curie-[a-z0-9\-]+'                 # curie-002, curie-instruct-beta
    r'|babbage-[a-z0-9\-]+'               # babbage-002
    r'|ada-[a-z0-9\-]+'                   # ada-002
    r'|whisper[a-z0-9\-]*'               # whisper-1
    r'|tts-[a-z0-9\-]+'                   # tts-1, tts-1-hd
    r'|claude-[a-z0-9.\-]+'              # claude-2, claude-3-opus, claude-3-5-sonnet
    r'|gemini-[a-z0-9.\-]+'              # gemini-pro, gemini-1.5-pro
    r'|llama[a-z0-9.:_\-]+'              # llama-3, llama3.1, llama3.1:8b (Ollama)
    r'|mistral[a-z0-9.:_\-]+'            # mistral-large, mistral-medium
    r'|phi-[a-z0-9.:_\-]+'               # phi-3, phi-3.5-mini
    r'|qwen[a-z0-9/:._\-]+'              # qwen-2, qwen3:8b, qwen/qwen3-32b
    r'|deepseek[a-z0-9/:._\-]+'          # deepseek-coder, deepseek-r1:8b
    r'|stable-diffusion[a-z0-9.\-]*'   # stable-diffusion-xl
    r'|command-r[a-z0-9\-]*'           # command-r, command-r-plus
    r'|gpt2[a-z0-9\-]*'               # gpt2, gpt2-medium
    r'|bert[a-z0-9\-]*'               # bert-base, bert-large
    r'|t5-[a-z0-9\-]+'                 # t5-small, t5-large
    r'|codellama[a-z0-9.\-]*'          # codellama-7b
    r'|codestral[a-z0-9.\-]*'          # codestral-latest
    r'|starcoder[a-z0-9.\-]*'          # starcoder2
    r'|falcon[a-z0-9.\-]*'             # falcon-7b
    r'|yi-[a-z0-9.\-]+'               # yi-34b
    # HuggingFace model IDs (org/model format)
    r'|all-mpnet[a-z0-9.\-]*'          # all-mpnet-base-v2
    r'|all-MiniLM[a-z0-9.\-]*'         # all-MiniLM-L12-v2, all-MiniLM-L6-v2
    r'|[a-zA-Z][a-zA-Z0-9_\-]{1,}(?:/[a-zA-Z][a-zA-Z0-9._\-]{1,})+' # org/model HuggingFace IDs (min 2 chars each side)
    # Local model files
    r'|[a-zA-Z0-9_\-]+\.(?:keras|h5|pkl|pt|pth|onnx|safetensors|pb|tflite)' # toxic.keras, model.pkl, etc.
    # NLTK resources
    r'|punkt[a-z0-9_]*'                # punkt, punkt_tab
    r'|stopwords'                       # stopwords
    r'|wordnet'                         # wordnet
    r'|averaged_perceptron_tagger'      # averaged_perceptron_tagger
    r'|vader_lexicon'                   # vader_lexicon
    r')$',
    re.IGNORECASE
)


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
    
    # Strip surrounding quotes — semgrep includes them in abstract_content for string literals
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    
    if not value:
        return None
    
    # ── URL model extraction ──────────────────────────────────────────────
    # If the value looks like an AI provider API URL, extract just the model
    # name from the path.  e.g.:
    #   "https://api.openai.com/v1/engines/text-davinci-003/completions"
    #   → "text-davinci-003"
    if "api.openai.com" in value or "api.anthropic.com" in value or "googleapis.com" in value:
        # OpenAI engines URL:  .../engines/<model>/...
        m = re.search(r'api\.openai\.com/v1/engines/([a-zA-Z0-9._-]+)', value)
        if m:
            value = m.group(1)
        else:
            # OpenAI models URL:  .../models/<model>
            m = re.search(r'api\.openai\.com/v1/models/([a-zA-Z0-9._-]+)', value)
            if m:
                value = m.group(1)
    
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
    
    # ── Pattern-based false positive rejection ─────────────────────────────
    val_lower = value.lower()
    
    # Python attribute access: app_state.wrapped_model_path, self.model, etc.
    # Real models with dots are format "org/model" or "model.keras" — not "var.attr"
    if "." in value and "/" not in value:
        # Allow model files (.keras, .pkl, .h5, .pt, .pth, .onnx, .safetensors, .tflite, .pb)
        # and version dots (llama3.1:8b, gpt-3.5-turbo)
        if not re.search(r'\.(keras|pkl|h5|pt|pth|onnx|safetensors|tflite|pb)$', val_lower) \
           and not re.search(r'^[a-z].*\d+\.\d', val_lower):
            # Looks like Python attribute access (word.word pattern)
            if re.match(r'^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*', val_lower):
                return None
    
    # Bare variable names ending with common suffixes
    if re.match(r'^[a-z_][a-z0-9_]*_(path|model|dir|file|name|class|config|key|var|obj|instance|wrapper|handler|client|manager)$', val_lower):
        return None
    
    # ── Neural network layer / module path rejection ─────────────────────
    # PyTorch add_module("conv1/bn", ...) creates strings like "preact/relu",
    # "conv2/bn", "preact_bna/relu" that look like org/model but aren't.
    _NN_LAYER_PARTS = {
        "bn", "relu", "relu2", "norm", "conv", "conv1", "conv2", "conv3",
        "pool", "dropout", "fc", "linear", "act", "gelu", "silu", "sigmoid",
        "tanh", "softmax", "batchnorm", "layernorm", "groupnorm",
        "attention", "attn", "ffn", "mlp", "head", "layer",
        "preact", "preact_bna", "shortcut", "downsample", "upsample",
        "block", "stage", "branch", "neck", "backbone", "stem",
    }
    if "/" in value and not ":" in value:
        parts = val_lower.split("/")
        # If ALL parts are NN layer names, it's a module path not a model
        if all(p in _NN_LAYER_PARTS for p in parts):
            return None
        # If the last segment is a common NN layer name AND the first segment
        # is a short generic name (not a real org like "facebook", "microsoft")
        if len(parts) == 2 and parts[1] in _NN_LAYER_PARTS and len(parts[0]) < 12:
            # Check if first part looks like a layer prefix rather than an org
            if re.match(r'^(conv\d*|bn\d*|relu\d*|pool\d*|fc\d*|preact[a-z0-9_]*|block\d*|layer\d*|stage\d*|down\d*|up\d*)$', parts[0]):
                return None
    
    # ── Metric / logging path rejection ────────────────────────────────
    # wandb.log({"train/loss": ..., "val/loss": ...}) creates dict keys
    # that look like org/model but are ML metric logging paths.
    _METRIC_LOG_PARTS = {
        "train", "val", "validation", "test", "eval", "dev",
        "loss", "acc", "accuracy", "lr", "learning_rate",
        "mfu", "iter", "epoch", "step", "batch",
        "grad", "gradient", "norm", "weight", "bias",
        "f1", "precision", "recall", "auc", "roc",
        "perplexity", "ppl", "bleu", "rouge", "mse", "mae",
        "reward", "return", "score", "rate", "count",
    }
    if "/" in value and ":" not in value:
        parts = val_lower.split("/")
        if all(p in _METRIC_LOG_PARTS for p in parts):
            return None

    # ── Non-model file extension rejection ──────────────────────────────
    # Strings like "subdir/nested_file.txt" are file paths, not models.
    # Only allow known model file extensions; reject everything else.
    if re.search(r'\.[a-z]{1,4}$', val_lower):
        if not re.search(r'\.(keras|h5|pkl|pt|pth|onnx|safetensors|pb|tflite|bin|joblib|pickle)$', val_lower):
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


def scan_file_for_models(filepath: str, checkout_dir: str = "") -> List[Dict]:
    """
    Scan a single source file for AI model string literals using Python regex.
    Used as a reliable fallback when semgrep returns no findings.

    Returns list of dicts with keys: line, model, file, code_snippet, rule_id, rule_category.
    """
    results: List[Dict] = []
    seen: Set[tuple] = set()

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        logger.warning(f"[REGEX_SCAN] Cannot read {filepath}: {e}")
        return results

    # Build relative path for display
    rel_path = filepath
    try:
        if checkout_dir:
            rel_path = str(Path(filepath).relative_to(Path(checkout_dir))).replace("\\", "/")
    except (ValueError, TypeError):
        pass

    for lineno, raw_line in enumerate(lines, 1):
        line_stripped = raw_line.strip()
        if not line_stripped:
            continue
        for pattern, _ in _CODE_PATTERNS:
            for match in pattern.finditer(raw_line):
                candidate = match.group(1) if match.lastindex else match.group(0)
                candidate = clean_model_value(candidate)
                if not candidate:
                    continue
                # Reject non-model strings: format strings, HTTP methods,
                # headers, log messages, API keys, spaces, etc.
                if not _VALID_MODEL_RE.match(candidate):
                    continue
                key = (lineno, candidate)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "line": lineno,
                    "model": candidate,
                    "file": rel_path,
                    "code_snippet": line_stripped[:200],
                    "rule_id": "regex-model-scan",
                    "rule_category": "model_detection",
                })

    return results
