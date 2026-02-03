"""
AIBOM Configuration Constants
Centralized constants and mappings for the AIBOM API

Organization:
- Core imports & path utilities at top
- Constants grouped by domain (API, Cache, Timeouts, Limits, etc.)
- Provider patterns consolidated (single source of truth)
- Language/file configs grouped together
"""
from pathlib import Path as _Path
from typing import Literal

# =============================================================================
# PATH UTILITIES (computed once at import)
# =============================================================================

_MODULE_DIR: _Path = _Path(__file__).parent.resolve()

def _discover_semgrep_dir() -> _Path:
    """Discover semgrep directory once at import time."""
    candidates = (
        _MODULE_DIR / "semgrep",
        _MODULE_DIR.parent / "Prism-AIBOM" / "semgrep",
        _MODULE_DIR.parent / "semgrep",
    )
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return candidates[0]

def normalize_path(path: str) -> str:
    """Normalize path separators to forward slashes and strip leading ./"""
    return path.replace("\\", "/").lstrip("./") if path else ""

# Cached semgrep directory - computed once at module load
SEMGREP_DIR: _Path = _discover_semgrep_dir()

# =============================================================================
# CACHE DIRECTORIES (all cache paths in one place)
# =============================================================================

CACHE_DIR: _Path = _MODULE_DIR / ".cache"                      # PyPI imports cache
CACHE_FILE: _Path = CACHE_DIR / "pypi_imports_cache.json"
MODEL_CACHE_DIR: _Path = _MODULE_DIR / ".model_cache"          # Model card cache
DEPRECATION_CACHE_DIR: _Path = _MODULE_DIR / ".deprecation_cache"  # Deprecation data

# =============================================================================
# TIMEOUTS (all timeout values consolidated - seconds)
# =============================================================================

# GitHub
GITHUB_CLONE_TIMEOUT: int = 120
GITHUB_API_TIMEOUT: int = 15

# Semgrep
SEMGREP_TIMEOUT_SECONDS: int = 300  # 5 minutes

# Model cards
MODEL_CARD_TIMEOUT: int = 30
README_FETCH_TIMEOUT: int = 15

# =============================================================================
# CACHE DURATIONS (all cache expiry values - days)
# =============================================================================

CACHE_DURATION_DAYS: int = 7          # PyPI import name cache
MODEL_CACHE_EXPIRY_DAYS: int = 7      # Model card cache

# =============================================================================
# SIZE LIMITS (all size constraints consolidated)
# =============================================================================

MAX_UPLOAD_SIZE_MB: int = 500
MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 500MB
MAX_WHEEL_DOWNLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB for PyPI wheels
SEMGREP_MAX_MEMORY_MB: int = 2048

# =============================================================================
# FILE COUNT LIMITS
# =============================================================================

MAX_ZIP_FILE_COUNT: int = 50000
MAX_LOCAL_FILE_COUNT: int = 10000
DEPRECATION_MAX_CHAIN_DEPTH: int = 10  # Max depth for replacement chain tracing

# =============================================================================
# SOURCE TYPES & ENDPOINTS
# =============================================================================

SOURCE_TYPES = Literal["repo_public", "repo_private", "zip", "local"]

ENDPOINT_MAP: dict = {
    "repo_public": "/validate/repo_public",
    "repo_private": "/validate/repo_private",
    "zip": "/validate/zip",
    "local": "/validate/local",
}

# =============================================================================
# API BASE URLS (all external API endpoints)
# =============================================================================

GITHUB_API_BASE: str = "https://api.github.com"
HUGGINGFACE_API_BASE: str = "https://huggingface.co/api/models"
HUGGINGFACE_RAW_BASE: str = "https://huggingface.co"
AZURE_AI_CATALOG_API: str = "https://ai.azure.com/api/catalog/models"

# =============================================================================
# GITHUB AUTHENTICATION
# =============================================================================

VALID_PAT_PREFIXES: tuple = ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_")

# =============================================================================
# TEMP DIRECTORY
# =============================================================================

TEMP_DIR_PREFIX: str = "aibom_"

# Directories to skip when counting files (frozenset for O(1) lookup + immutability)
SKIP_DIRECTORIES: frozenset = frozenset({
    'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git'
})

# =============================================================================
# CODE FILE EXTENSIONS (all source file types)
# =============================================================================

CODE_FILE_EXTENSIONS: frozenset = frozenset({
    # Python
    '.py', '.pyx', '.pxd', '.pyi',
    # JavaScript/TypeScript
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    # Web
    '.html', '.htm', '.css', '.scss', '.sass', '.less',
    # Other languages
    '.java', '.kt', '.kts', '.scala',
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
    '.cs', '.fs', '.go', '.rs', '.rb', '.php', '.swift', '.m', '.mm',
    # Config/Data
    '.json', '.yaml', '.yml', '.toml', '.xml',
    # Shell/SQL
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.sql',
})

# =============================================================================
# SEMGREP CONFIGURATION
# =============================================================================

# Language to rule file mapping (relative to semgrep/ directory)
SEMGREP_RULE_FILES: dict = {
    "python": "python/python_imports.yml",
    "javascript": "javascript/javascript_imports.yml",
    # Add new languages here: "go": "go/go_imports.yml",
}

# File extensions to strip from stems (for import matching)
FILE_STEM_EXTENSIONS: tuple = (".py", ".ipynb", ".js", ".ts", ".jsx", ".tsx")

# Common source directory markers (for extracting relative paths)
PATH_MARKERS: tuple = ("src", "lib", "app", "components", "scripts")

# =============================================================================
# LANGUAGE DETECTION & MANIFEST CONFIGURATION
# =============================================================================
#packages endpoint
# File extensions for each language (frozenset for immutability + O(1) lookup)
LANGUAGE_EXTENSIONS: dict = {
    "python": frozenset({".py", ".pyx", ".pyi", ".ipynb"}),
    "javascript": frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}),
    # Add new languages here:
    # "go": frozenset({".go"}),
    # "rust": frozenset({".rs"}),
}
#packages endpoint
# Pre-computed reverse mapping: extension -> language (for O(1) lookup)
EXT_TO_LANG: dict = {
    ext: lang 
    for lang, extensions in LANGUAGE_EXTENSIONS.items() 
    for ext in extensions
}
#packages endpoint
# Manifest files for each language (pre-lowercased frozensets for O(1) lookup)
MANIFEST_FILES: dict = {
    "python": frozenset({
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "pipfile.lock",
    }),
    "javascript": frozenset({
        "package.json",
        "package-lock.json",
        #"yarn.lock",
        #"pnpm-lock.yaml",
    }),
    # Add new languages here:
    # "go": frozenset({"go.mod"}),
    # "rust": frozenset({"cargo.toml"}),
}

# =============================================================================
# BUILTIN MODULES (for import classification)
# =============================================================================

# Python standard library modules (frozenset for O(1) lookup)
PYTHON_BUILTINS: frozenset = frozenset({
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
})

# JavaScript/Node.js builtin modules (frozenset for O(1) lookup)
JS_BUILTINS: frozenset = frozenset({
    "fs", "path", "http", "https", "url", "os", "util", "events", "stream",
    "crypto", "buffer", "querystring", "readline", "zlib", "child_process",
    "cluster", "dns", "net", "tls", "dgram", "console", "process", "assert",
    "module", "vm", "worker_threads", "perf_hooks", "inspector", "async_hooks",
    "node:fs", "node:path", "node:http", "node:https", "node:url", "node:os",
    "node:util", "node:events", "node:stream", "node:crypto", "node:buffer",
    "node:child_process", "node:process", "node:assert", "node:module",
})

# =============================================================================
# SUPPORTED LANGUAGES
# =============================================================================

# Language configuration: maps language name to its import key in import_packages
# Add new languages here to support them across the codebase
SUPPORTED_LANGUAGES: dict = {
    "python": "python_imports",
    "javascript": "javascript_imports",
    # Future: "rust": "rust_imports", "go": "go_imports", etc.
}

# JavaScript/TypeScript language variants for normalization (frozenset for O(1) lookup)
JS_LANGUAGE_VARIANTS: frozenset = frozenset({"javascript", "typescript", "js", "ts"})

# =============================================================================
# LLM VALIDATION CONFIGURATION
# =============================================================================

# LLM Provider settings
LLM_BATCH_SIZE = 30  # Libraries per batch to avoid token limits
LLM_MAX_TOKENS_PER_LIB = 60  # Estimated tokens per library in response
LLM_MAX_TOKENS_CAP = 8000  # Maximum tokens for response
LLM_MIN_TOKENS = 2000  # Minimum tokens for response
LLM_TEMPERATURE = 0  # Deterministic responses

# System prompt for AI library classification (optimized for concise, accurate responses)
LLM_SYSTEM_PROMPT = """Classify libraries as AI_POSITIVE or NON_AI.

AI_POSITIVE = DIRECTLY for AI/ML:
• ML/DL frameworks (torch, tensorflow, keras)
• LLM/Transformer libs (transformers, langchain, llama-index)
• AI provider SDKs (openai, anthropic, cohere, replicate)
• Vector DBs (chromadb, pinecone, qdrant, weaviate)
• AI orchestration (autogen, crewai, semantic-kernel)

NON_AI = utilities, web frameworks, data processing (numpy, pandas, flask, react)

Return ONLY JSON array:
[{"library":"name","classification":"AI_POSITIVE"|"NON_AI","confidence":"HIGH"|"MEDIUM"|"LOW","reason":"max 5 words"}]"""

# System prompt for AI library categorization
LLM_CATEGORIZATION_PROMPT = """Categorize each AI/ML library into ONE category:

1. AI_PROVIDER: LLM APIs, AI SDKs (openai, anthropic, google-generativeai, cohere, replicate)
2. ML_ALGORITHM: Classical ML (scikit-learn, xgboost, lightgbm, catboost)
3. DL_ALGORITHM: Deep learning frameworks (torch, tensorflow, keras, jax)
4. AI_ORCHESTRATION: RAG, agents, chains (langchain, llama-index, autogen, crewai)
5. VECTOR_DB: Embedding storage (chromadb, pinecone, qdrant, weaviate, faiss)
6. DATA_PROCESSING: AI-focused data utils (datasets, tokenizers, sentence-transformers)

Use PRIMARY purpose if multi-category. Return ONLY JSON:
[{"library":"name","category":"CATEGORY","confidence":"HIGH"|"MEDIUM"|"LOW","reason":"max 8 words"}]"""

# Valid categories for categorization validation (uppercase)
VALID_CATEGORIES: frozenset = frozenset({
    "AI_PROVIDER", "ML_ALGORITHM", "DL_ALGORITHM",
    "AI_ORCHESTRATION", "VECTOR_DB", "DATA_PROCESSING", "UNKNOWN"
})

# AI Library Categories (lowercase version for empty category responses)
AI_CATEGORIES: frozenset = frozenset({c.lower() for c in VALID_CATEGORIES})

# =============================================================================
# PACKAGE NAME → IMPORT NAME MAPPINGS
# Static mappings for packages where PyPI name ≠ import name (avoids PyPI calls)
# =============================================================================

KNOWN_PACKAGE_MAPPINGS: dict = {
    # Google AI packages
    "google-genai": ["google"],
    "google-ai-generativelanguage": ["google"],
    "google-cloud-aiplatform": ["google", "vertexai"],
    "google-cloud-storage": ["google"],
    "google-generativeai": ["google"],
    
    # AI/LLM frameworks
    "openai": ["openai"],
    "anthropic": ["anthropic"],
    "langchain": ["langchain"],
    "langchain-core": ["langchain_core"],
    "langchain-community": ["langchain_community"],
    "langchain-openai": ["langchain_openai"],
    "langchain-anthropic": ["langchain_anthropic"],
    "transformers": ["transformers"],
    "torch": ["torch"],
    "tensorflow": ["tensorflow", "tf"],
    "tensorflow-gpu": ["tensorflow", "tf"],
    
    # Image processing
    "Pillow": ["PIL"],
    "pillow": ["PIL"],
    "opencv-python": ["cv2"],
    "opencv-contrib-python": ["cv2"],
    
    # Machine Learning
    "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"],
    
    # Data science
    "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"],
    "beautifulsoup4": ["bs4"],
    
    # Deep Learning
    "torchvision": ["torchvision"],
    
    # NLP
    "sentence-transformers": ["sentence_transformers"],
    
    # Others
    "PyYAML": ["yaml"],
    "pyyaml": ["yaml"],
    "protobuf": ["google.protobuf"],
}

# =============================================================================
# AI PROVIDER PATTERNS (SINGLE SOURCE OF TRUTH)
# =============================================================================
# These patterns are used by multiple modules:
# - ai_targeted_scanner.py: rule discovery
# - model_extractor.py: provider classification from model names
# - model_deprecation_checker.py: provider detection for deprecation data

# Master provider keywords for rule discovery (frozensets for O(1) membership)
PROVIDER_KEYWORDS: dict = {
    "openai": frozenset({"openai", "gpt", "chatgpt", "davinci", "babbage", "dall-e", "whisper", "tts"}),
    "anthropic": frozenset({"anthropic", "claude"}),
    "google": frozenset({"google", "gemini", "gemma", "palm", "vertex", "generativeai", "imagen", "veo", "bard"}),
    "huggingface": frozenset({"huggingface", "transformers", "hf"}),
    "meta": frozenset({"meta", "llama", "llama2", "llama3", "meta-llama"}),
    "mistral": frozenset({"mistral"}),
    "cohere": frozenset({"cohere", "command"}),
    "replicate": frozenset({"replicate"}),
    "langchain": frozenset({"langchain"}),
    "pinecone": frozenset({"pinecone"}),
    "ai_sdk": frozenset({"ai_sdk", "ai-sdk", "ai"}),
}

# Pre-computed normalized keywords for O(1) provider lookup
NORMALIZED_PROVIDER_KEYWORDS: dict = {
    kw.replace("-", "_").replace("@", ""): provider
    for provider, keywords in PROVIDER_KEYWORDS.items()
    for kw in keywords
}

# Model name prefix patterns (for extracting provider from model strings like "gpt-4", "claude-3")
# Uses prefix matching: model.startswith(prefix)
MODEL_PROVIDER_PREFIXES_PATTERNS: dict = {
    "openai": ("gpt-", "o1-", "o3-", "o4-", "text-embedding-", "dall-e", "whisper"),
    "anthropic": ("claude-",),
    "google": ("gemini-", "palm-",),
    "meta": ("llama-", "llama2", "llama3", "meta-llama"),
    "mistral": ("mistral",),
    "cohere": ("command-",),
}

# Rule ID keywords to provider mapping (for semgrep rule matching)
RULE_PROVIDER_KEYWORDS: dict = {
    "replicate": "replicate",
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "google",
    "gemini": "google",
    "langchain": "langchain",
    "huggingface": "huggingface",
    "hf": "huggingface",
}

# Known provider prefixes for AIBOM cache file matching (tuple for iteration order)
MODEL_PROVIDER_PREFIXES: tuple = (
    "openai_", "anthropic_", "google_", "huggingface_", "azure_", "meta_", "mistral_", "cohere_"
)

# Deprecated status keywords (frozenset for O(1) lookup)
DEPRECATED_STATUSES: frozenset = frozenset({"deprecated", "shutdown", "legacy"})

# Severity thresholds for deprecation (days until shutdown)
DEPRECATION_SEVERITY_THRESHOLDS: dict = {
    "CRITICAL": 0,   # Already shutdown or ≤0 days
    "HIGH": 30,      # ≤30 days
    "MEDIUM": 90,    # ≤90 days
}

# =============================================================================
# MODEL EXTRACTOR CONFIGURATION
# =============================================================================

# Metavar keys to check in semgrep findings, in priority order
MODEL_METAVAR_PRIORITY: tuple = (
    "$MODEL",
    "$MODEL_NAME", 
    "$MODEL_ID",
    "$VALUE",
    "$REPLICATE_MODEL",
)

# False positives to filter out during model extraction (frozenset for O(1) lookup)
MODEL_FALSE_POSITIVES: frozenset = frozenset({
    "model_name", "model", "name", "models", "model_id",
    "modelname", "model_type", "type", "api", "endpoint",
    "client", "config", "options", "params", "settings",
    "default", "none", "null", "undefined", "true", "false",
    "process", "env", "string", "object", "array",
    "$model", "$value", "$model_name",
})

# =============================================================================
# DEPRECATED ALIASES (for backward compatibility - prefer new names)
# =============================================================================

# These are kept for backward compatibility with modules that import old names
# TODO: Update imports in consuming modules and remove these aliases

# model_extractor.py uses MODEL_PROVIDER_PATTERNS (now MODEL_PROVIDER_PREFIXES_PATTERNS)
MODEL_PROVIDER_PATTERNS: dict = {
    provider: frozenset(prefixes) 
    for provider, prefixes in MODEL_PROVIDER_PREFIXES_PATTERNS.items()
}

# model_deprecation_checker.py uses DEPRECATION_PROVIDER_PATTERNS
DEPRECATION_PROVIDER_PATTERNS: dict = {
    provider: PROVIDER_KEYWORDS.get(provider, frozenset())
    for provider in ("anthropic", "openai", "google")
}

