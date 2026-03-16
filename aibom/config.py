"""
AIBOM Configuration Constants
Centralized constants and mappings for the AIBOM API

Organization:
- Core imports & path utilities at top
- Constants grouped by domain (API, Cache, Timeouts, Limits, etc.)
- Provider patterns consolidated (single source of truth)
- Language/file configs grouped together
"""
import os
from pathlib import Path as _Path
from typing import Dict, FrozenSet, List, Tuple

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
SEMGREP_TIMEOUT_SECONDS: int = 300  # 5 minutespo

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
MAX_ZIP_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB per file (zip bomb protection)
DEPRECATION_MAX_CHAIN_DEPTH: int = 10  # Max depth for replacement chain tracing

# =============================================================================
# API BASE URLS (all external API endpoints)
# =============================================================================

GITHUB_API_BASE: str = "https://api.github.com"
HUGGINGFACE_API_BASE: str = "https://huggingface.co/api/models"
HUGGINGFACE_RAW_BASE: str = "https://huggingface.co"
AZURE_AI_CATALOG_API: str = "https://ai.azure.com/api/catalog/models"

# =============================================================================
# AWS CONFIGURATION
# =============================================================================

class AWS:
    """AWS configuration for the application"""
    SECRET_NAME = os.environ.get('AWSSECRETNAME')
    REGION = os.environ.get('AWSREGION')
    ACCESS_KEY_ID = os.environ.get('AWSACCESSKEYID')
    SECRET_ACCESS_KEY = os.environ.get('AWSSECRETACCESSKEY')
    S3_BUCKET = os.environ.get('AWSS3BUCKET', '').strip() or None
    CLOUDWATCH_LOG_GROUP = "/airflow/prismaibom"
    LAMBDA_RESULT_POSTING_ARN = os.environ.get('AWSLAMBDARESULTPOSTINGARN')

# =============================================================================
# GITHUB AUTHENTICATION
# =============================================================================

VALID_PAT_PREFIXES: Tuple[str, ...] = ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_")

# =============================================================================
# TEMP DIRECTORY
# =============================================================================

TEMP_DIR_PREFIX: str = "aibom_"

# Directories to skip when counting files (frozenset for O(1) lookup + immutability)
SKIP_DIRECTORIES: FrozenSet[str] = frozenset({
    'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', '.git',
    'target', '.gradle', '.mvn',
})

# =============================================================================
# CODE FILE EXTENSIONS (all source file types)
# =============================================================================

CODE_FILE_EXTENSIONS: FrozenSet[str] = frozenset({
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
SEMGREP_RULE_FILES: Dict[str, str] = {
    "python": "python/python_imports.yml",
    "javascript": "javascript/javascript_imports.yml",
    "go": "go/go_imports.yml",
    "dotnet": "dotnet/dotnet_imports.yml",
    "java": "java/java_imports.yml",
}

# File extensions to strip from stems (for import matching)
FILE_STEM_EXTENSIONS: Tuple[str, ...] = (".py", ".ipynb", ".js", ".ts", ".jsx", ".tsx")

# Common source directory markers (for extracting relative paths)
PATH_MARKERS: Tuple[str, ...] = ("src", "lib", "app", "components", "scripts")

# =============================================================================
# LANGUAGE DETECTION & MANIFEST CONFIGURATION
# =============================================================================
#packages endpoint
# File extensions for each language (frozenset for immutability + O(1) lookup)
LANGUAGE_EXTENSIONS: Dict[str, FrozenSet[str]] = {
    "python": frozenset({".py", ".pyx", ".pyi", ".ipynb"}),
    "javascript": frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}),
    "go": frozenset({".go"}),
    "dotnet": frozenset({".cs", ".fs", ".vb"}),
    "java": frozenset({".java"}),
    # Add new languages here:
    # "rust": frozenset({".rs"}),
}
#packages endpoint
# Pre-computed reverse mapping: extension -> language (for O(1) lookup)
EXT_TO_LANG: Dict[str, str] = {
    ext: lang 
    for lang, extensions in LANGUAGE_EXTENSIONS.items() 
    for ext in extensions
}
#packages endpoint
# Manifest files for each language (pre-lowercased frozensets for O(1) lookup)
MANIFEST_FILES: Dict[str, FrozenSet[str]] = {
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
    "go": frozenset({
        "go.mod",
        "go.sum",
    }),
    "dotnet": frozenset({
        "packages.config",
        "directory.build.props",
        "directory.packages.props",
        "packages.lock.json",
        "nuget.config",
        "global.json",
    }),
    "java": frozenset({
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    }),
    # Add new languages here:
    # "rust": frozenset({"cargo.toml"}),
}

# =============================================================================
# BUILTIN MODULES (for import classification)
# =============================================================================

# Python standard library modules (frozenset for O(1) lookup)
PYTHON_BUILTINS: FrozenSet[str] = frozenset({
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
JS_BUILTINS: FrozenSet[str] = frozenset({
    "fs", "path", "http", "https", "url", "os", "util", "events", "stream",
    "crypto", "buffer", "querystring", "readline", "zlib", "child_process",
    "cluster", "dns", "net", "tls", "dgram", "console", "process", "assert",
    "module", "vm", "worker_threads", "perf_hooks", "inspector", "async_hooks",
    "node:fs", "node:path", "node:http", "node:https", "node:url", "node:os",
    "node:util", "node:events", "node:stream", "node:crypto", "node:buffer",
    "node:child_process", "node:process", "node:assert", "node:module",
})

# Go standard library packages (frozenset for O(1) lookup)
GO_BUILTINS: FrozenSet[str] = frozenset({
    "fmt", "os", "io", "net", "log", "sync", "time", "math", "sort",
    "strings", "strconv", "bytes", "bufio", "errors", "context", "flag",
    "path", "regexp", "runtime", "reflect", "testing", "unsafe",
    "encoding", "encoding/json", "encoding/xml", "encoding/csv", "encoding/base64",
    "encoding/binary", "encoding/gob", "encoding/hex", "encoding/pem",
    "net/http", "net/url", "net/smtp", "net/rpc",
    "os/exec", "os/signal", "os/user",
    "io/ioutil", "io/fs",
    "path/filepath",
    "crypto", "crypto/sha256", "crypto/sha512", "crypto/md5", "crypto/tls",
    "crypto/aes", "crypto/rsa", "crypto/rand", "crypto/hmac", "crypto/x509",
    "database/sql",
    "html", "html/template",
    "text/template", "text/scanner", "text/tabwriter",
    "archive/zip", "archive/tar",
    "compress/gzip", "compress/zlib", "compress/flate",
    "container/heap", "container/list", "container/ring",
    "debug/elf", "debug/dwarf",
    "image", "image/png", "image/jpeg", "image/gif",
    "math/big", "math/rand",
    "mime", "mime/multipart",
    "sync/atomic",
    "unicode", "unicode/utf8", "unicode/utf16",
    "log/syslog",
    "go/ast", "go/parser", "go/token", "go/format", "go/build",
    "embed", "syscall", "plugin",
})

# .NET / C# builtin namespaces (frozenset for O(1) lookup)
DOTNET_BUILTINS: FrozenSet[str] = frozenset({
    "System", "System.Collections", "System.Collections.Generic",
    "System.Collections.Concurrent", "System.Collections.Immutable",
    "System.Collections.ObjectModel", "System.Collections.Specialized",
    "System.ComponentModel", "System.ComponentModel.DataAnnotations",
    "System.Configuration", "System.Data", "System.Data.Common",
    "System.Diagnostics", "System.Diagnostics.CodeAnalysis",
    "System.Drawing", "System.Dynamic", "System.Globalization",
    "System.IO", "System.IO.Compression", "System.IO.Pipes",
    "System.Linq", "System.Linq.Expressions",
    "System.Net", "System.Net.Http", "System.Net.Mail",
    "System.Net.NetworkInformation", "System.Net.Security",
    "System.Net.Sockets", "System.Net.WebSockets",
    "System.Numerics", "System.Reflection", "System.Reflection.Emit",
    "System.Resources", "System.Runtime", "System.Runtime.CompilerServices",
    "System.Runtime.InteropServices", "System.Runtime.Serialization",
    "System.Security", "System.Security.Claims", "System.Security.Cryptography",
    "System.Security.Principal", "System.ServiceProcess",
    "System.Text", "System.Text.Encoding", "System.Text.Json",
    "System.Text.Json.Serialization", "System.Text.RegularExpressions",
    "System.Threading", "System.Threading.Tasks", "System.Threading.Channels",
    "System.Transactions", "System.Web", "System.Windows",
    "System.Xml", "System.Xml.Linq", "System.Xml.Serialization",
    "Microsoft.CSharp", "Microsoft.VisualBasic",
    "Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Options", "Microsoft.Extensions.Primitives",
    "Microsoft.AspNetCore", "Microsoft.AspNetCore.Builder",
    "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Http",
    "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Routing",
})

# Java standard library packages (frozenset for O(1) lookup)
JAVA_BUILTINS: FrozenSet[str] = frozenset({
    # java.lang is auto-imported, but include for completeness
    "java.lang", "java.lang.annotation", "java.lang.invoke", "java.lang.ref",
    "java.lang.reflect", "java.lang.module",
    "java.util", "java.util.concurrent", "java.util.concurrent.atomic",
    "java.util.concurrent.locks", "java.util.function", "java.util.logging",
    "java.util.regex", "java.util.stream", "java.util.zip", "java.util.jar",
    "java.io", "java.nio", "java.nio.channels", "java.nio.charset",
    "java.nio.file", "java.nio.file.attribute",
    "java.net", "java.net.http",
    "java.math",
    "java.time", "java.time.format", "java.time.temporal", "java.time.zone",
    "java.text",
    "java.sql",
    "java.security", "java.security.cert", "java.security.spec",
    "javax.crypto", "javax.crypto.spec",
    "javax.net", "javax.net.ssl",
    "javax.sql",
    "javax.xml", "javax.xml.parsers", "javax.xml.transform",
    "javax.annotation",
    "java.beans",
    "java.applet",
    "java.awt", "java.awt.event",
    "javax.swing",
    "java.rmi",
    "java.lang.management",
    "java.util.prefs",
    "java.util.spi",
})

# =============================================================================
# SUPPORTED LANGUAGES
# =============================================================================

# Language configuration: maps language name to its import key in import_packages
# Add new languages here to support them across the codebase
SUPPORTED_LANGUAGES: Dict[str, str] = {
    "python": "python_imports",
    "javascript": "javascript_imports",
    "go": "go_imports",
    "dotnet": "dotnet_imports",
    "java": "java_imports",
    # Future: "rust": "rust_imports", etc.
}

# JavaScript/TypeScript language variants for normalization (frozenset for O(1) lookup)
JS_LANGUAGE_VARIANTS: FrozenSet[str] = frozenset({"javascript", "typescript", "js", "ts"})

# =============================================================================
# LLM VALIDATION CONFIGURATION
# =============================================================================

# LLM Provider settings
LLM_MODEL: str = "openai/gpt-oss-20b"  # Groq model identifier
LLM_API_KEY_MIN_LENGTH: int = 20  # Minimum valid API key length
LLM_BATCH_SIZE: int = int(os.getenv("LLM_BATCH_SIZE", "50"))  # Libraries per batch (configurable)
LLM_MAX_TOKENS_PER_LIB: int = 100  # Estimated tokens per library in response
LLM_MAX_TOKENS_CAP: int = 8000  # Maximum tokens for response
LLM_MIN_TOKENS: int = 2000  # Minimum tokens for response
LLM_TEMPERATURE: float = 0.0  # Deterministic responses

# System prompt for AI library classification (optimized for concise, accurate responses)
LLM_SYSTEM_PROMPT: str = """You are a classification assistant that labels programming libraries based on whether they are:

1. AI_POSITIVE — libraries directly used for AI/ML tasks (training, inference, models, embeddings, vector DBs, orchestration),
2. API_POSITIVE — libraries commonly used to make HTTP/API calls, i.e., network client or API client libs across languages
3. BOTH — libraries that are both AI/ML related and used for API calls
4. NON_RELEVANT — utilities, UI, data processing, framework code not used for AI or API calls

Classify each library name provided into exactly one of:
AI_POSITIVE | API_POSITIVE | BOTH | NON_RELEVANT

Return ONLY a JSON array like:

[
  {
    "library":"<name>",
    "classification":"AI_POSITIVE"|"API_POSITIVE"|"BOTH"|"NON_RELEVANT",
    "confidence":"HIGH"|"MEDIUM"|"LOW",
    "reason":"max 5 words"
  }
]

Definitions and examples:

AI_POSITIVE includes:
• ML/DL frameworks (torch, tensorflow, keras) 
• LLM/Transformer libs (transformers, langchain, llama-index) 
• AI provider SDKs for inference (openai, anthropic, cohere)  
• Vector DBs and embedding tools (chromadb, pinecone, qdrant, weaviate) 
• AI orchestration frameworks

API_POSITIVE includes:
• HTTP/network client libs (requests, httpx, aiohttp, urllib3, Axios, node-fetch, got, fetch-related)
• API server frameworks that expose HTTP endpoints (flask, fastapi, express, django-rest-framework, hapi, koa, gin, echo)
• Official API client libraries for external services (GitHub API, Google API, Kubernetes API, boto3, etc.)
• REST/GraphQL/RPC clients and wrappers (graphql-request, grpcio, zeep)
• WebSocket libraries (websockets, socket.io, ws)

BOTH applies if the library is:
• An AI SDK that also provides built-in HTTP client functionality  
• An API client specifically for an AI service

NON_RELEVANT applies if:
• The library is utility, UI, data processing, build tooling, etc.

Use concise reasons."""

# System prompt for unified library categorization (AI + API in one LLM call)
LLM_CATEGORIZATION_PROMPT: str = """You will receive a list of libraries. Each is labeled [AI], [API], or [BOTH].

For [AI] libraries, assign ONE AI category:
1. AI_PROVIDER: LLM APIs, AI SDKs (openai, anthropic, google-generativeai, cohere, replicate)
2. ML_ALGORITHM: Classical ML (scikit-learn, xgboost, lightgbm, catboost)
3. DL_ALGORITHM: Deep learning frameworks (torch, tensorflow, keras, jax)
4. AI_ORCHESTRATION: RAG, agents, chains (langchain, llama-index, autogen, crewai)
5. VECTOR_DB: Embedding storage (chromadb, pinecone, qdrant, weaviate, faiss)
6. DATA_PROCESSING: AI-focused data utils (datasets, tokenizers, sentence-transformers)

For [API] libraries, assign ONE API category:
1. HTTP_CLIENT: Outbound HTTP/REST calls (requests, httpx, aiohttp, urllib3, axios, node-fetch, got)
2. API_FRAMEWORK: Web frameworks that serve HTTP endpoints (flask, fastapi, django, express, koa, gin, echo)
3. GRAPHQL: GraphQL clients or servers (graphql-request, apollo-client, strawberry, ariadne)
4. GRPC: gRPC/Protocol Buffer communication (grpcio, grpc-js, protobuf)
5. WEBSOCKET: WebSocket or real-time communication (websockets, socket.io, ws, channels)
6. CLOUD_SDK: Cloud provider SDKs (boto3, google-cloud-*, azure-sdk, aws-sdk)
7. API_WRAPPER: Service-specific API clients (twilio, stripe, sendgrid, slack-sdk)

For [BOTH] libraries, return TWO entries — one with the best AI category and one with the best API category.
Example for [BOTH] openai:
  {"library":"openai","category":"AI_PROVIDER","confidence":"HIGH","reason":"LLM inference SDK"},
  {"library":"openai","category":"HTTP_CLIENT","confidence":"HIGH","reason":"Built-in API HTTP client"}

Return ONLY JSON:
[{"library":"name","category":"CATEGORY","confidence":"HIGH"|"MEDIUM"|"LOW","reason":"max 8 words"}]"""

# Valid AI categories for categorization validation (uppercase)
VALID_CATEGORIES: FrozenSet[str] = frozenset({
    "AI_PROVIDER", "ML_ALGORITHM", "DL_ALGORITHM",
    "AI_ORCHESTRATION", "VECTOR_DB", "DATA_PROCESSING", "UNKNOWN"
})

# AI Library Categories (lowercase version for empty category responses)
AI_CATEGORIES: FrozenSet[str] = frozenset({c.lower() for c in VALID_CATEGORIES})

# Valid API categories for validation (uppercase)
VALID_API_CATEGORIES: FrozenSet[str] = frozenset({
    "HTTP_CLIENT", "API_FRAMEWORK", "GRAPHQL",
    "GRPC", "WEBSOCKET", "CLOUD_SDK", "API_WRAPPER", "UNKNOWN"
})

# API Library Categories (lowercase version for empty category responses)
API_CATEGORIES: FrozenSet[str] = frozenset({c.lower() for c in VALID_API_CATEGORIES})

# =============================================================================
# MODEL TAGGING (maps library category → model tag: LLM / DL / ML / AI)
# =============================================================================

# Map AI library category → model tag
CATEGORY_TO_MODEL_TAG: Dict[str, str] = {
    "AI_PROVIDER": "LLM",
    "AI_ORCHESTRATION": "LLM",
    "DL_ALGORITHM": "DL",
    "VECTOR_DB": "DL",
    "ML_ALGORITHM": "ML",
    "DATA_PROCESSING": "ML",
    "UNKNOWN": "AI",
}

# Model name patterns for fallback tagging (when no parent library is known)
# Checked in order: first match wins
MODEL_TAG_PATTERNS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    # LLM model name prefixes
    (("gpt", "o1-", "o3-", "o4-",
      "claude-", "gemini-", "llama", "mistral", "phi-",
      "command-r", "deepseek", "qwen", "yi-",
      "text-davinci", "text-curie", "text-babbage", "text-ada",
      "text-embedding", "dall-e", "whisper", "tts-",
      "codellama", "codestral", "starcoder", "falcon"), "LLM"),
    # DL model names / file extensions
    (("bert", "resnet", "vgg", "yolo", "stable-diffusion",
      "t5-", "roberta", "distilbert", "mobilenet", "efficientnet",
      "inception", "densenet", "squeezenet", "alexnet",
      ".pt", ".pth", ".keras", ".h5", ".pb", ".tflite",
      ".onnx", ".safetensors", ".bin"), "DL"),
    # ML model file extensions
    ((".pkl", ".joblib", ".pickle", "xgboost", "lightgbm", "catboost"), "ML"),
)

# =============================================================================
# PACKAGE NAME → IMPORT NAME MAPPINGS
# Static mappings for packages where PyPI name ≠ import name (avoids PyPI calls)
# =============================================================================

KNOWN_PACKAGE_MAPPINGS: Dict[str, List[str]] = {
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
PROVIDER_KEYWORDS: Dict[str, FrozenSet[str]] = {
    "openai": frozenset({"openai", "gpt", "chatgpt", "davinci", "babbage", "curie", "ada", "dall-e", "whisper", "tts"}),
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
    "mistral": frozenset({"mistral", "mistralai"}),
    "groq": frozenset({"groq"}),
    "together": frozenset({"together", "togetherai", "together-ai"}),
    "perplexity": frozenset({"perplexity"}),
    "fireworks": frozenset({"fireworks", "fireworks-ai"}),
    "ollama": frozenset({"ollama"}),
    "litellm": frozenset({"litellm"}),
    "vllm": frozenset({"vllm"}),
    "lmstudio": frozenset({"lmstudio", "lm-studio", "lm_studio"}),
    "localai": frozenset({"localai", "local-ai", "local_ai"}),
    "llama_cpp": frozenset({"llama_cpp", "llama-cpp", "llama.cpp", "llamacpp"}),
    "gpt4all": frozenset({"gpt4all", "gpt-4-all"}),
    "koboldcpp": frozenset({"koboldcpp", "koboldai", "kobold"}),
    "jan": frozenset({"jan", "jan-ai"}),
    "llamafile": frozenset({"llamafile"}),
    "exllamav2": frozenset({"exllamav2", "exllama"}),
    "ctransformers": frozenset({"ctransformers"}),
    "tgi": frozenset({"tgi", "text-generation-inference"}),
    "triton": frozenset({"triton", "triton-inference-server", "tritonclient"}),
    "mlflow": frozenset({"mlflow"}),
    "onnxruntime": frozenset({"onnxruntime", "onnx", "ort"}),
}

# Pre-computed normalized keywords for O(1) provider lookup
NORMALIZED_PROVIDER_KEYWORDS: Dict[str, str] = {
    kw.replace("-", "_").replace("@", ""): provider
    for provider, keywords in PROVIDER_KEYWORDS.items()
    for kw in keywords
}

# Model name prefix patterns (for extracting provider from model strings like "gpt-4", "claude-3")
# Uses prefix matching: model.startswith(prefix)
MODEL_PROVIDER_PREFIXES_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "openai": ("gpt-", "o1-", "o3-", "o4-", "text-embedding-", "text-davinci-", "text-curie-", "text-babbage-", "text-ada-", "dall-e", "whisper", "chatgpt-"),
    "anthropic": ("claude-",),
    "google": ("gemini-", "palm-",),
    "meta": ("llama-", "llama2", "llama3", "meta-llama"),
    "mistral": ("mistral",),
    "cohere": ("command-",),
    "groq": ("llama-", "mixtral-", "gemma-"),
    "together": ("togethercomputer/",),
    "perplexity": ("pplx-",),
}

# Rule ID keywords to provider mapping (for semgrep rule matching)
RULE_PROVIDER_KEYWORDS: Dict[str, str] = {
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
MODEL_PROVIDER_PREFIXES: Tuple[str, ...] = (
    "openai_", "anthropic_", "google_", "huggingface_", "azure_", "meta_", "mistral_", "cohere_"
)

# Deprecated status keywords (frozenset for O(1) lookup)
DEPRECATED_STATUSES: FrozenSet[str] = frozenset({"deprecated", "shutdown", "legacy"})

# Severity thresholds for deprecation (days until shutdown)
DEPRECATION_SEVERITY_THRESHOLDS: Dict[str, int] = {
    "CRITICAL": 0,   # Already shutdown or ≤0 days
    "HIGH": 30,      # ≤30 days
    "MEDIUM": 90,    # ≤90 days
}

# =============================================================================
# MODEL EXTRACTOR CONFIGURATION
# =============================================================================

# Metavar keys to check in semgrep findings, in priority order
MODEL_METAVAR_PRIORITY: Tuple[str, ...] = (
    "$MODEL",
    "$MODEL_NAME", 
    "$MODEL_ID",
    "$VALUE",
    "$REPLICATE_MODEL",
)

# False positives to filter out during model extraction (frozenset for O(1) lookup)
MODEL_FALSE_POSITIVES: FrozenSet[str] = frozenset({
    # Generic variable/param names
    "model_name", "model", "name", "models", "model_id",
    "modelname", "model_type", "type", "api", "endpoint",
    "client", "config", "options", "params", "settings",
    "default", "none", "null", "undefined", "true", "false",
    "process", "env", "string", "object", "array",
    "$model", "$value", "$model_name",
    # Variable references mistaken for models
    "model_path", "model_dir", "model_file", "model_class",
    "nli_model", "cross_encoder_model", "base_model", "wrapped_model",
    "hf", "repo", "eval_loss", "train_loss", "val_loss", "loss",
    "base_wrapped_path", "guardrail_wrapped_path", "secured_wrapped_path",
    "wrapped_model_path", "checkpoint", "checkpoint_path",
    # Generic method/function names
    "predict", "fit", "transform", "encode", "decode",
    "forward", "backward", "train", "eval", "test",
    "save", "load", "get", "set", "put", "post", "delete",
    "input", "output", "result", "response", "request",
    "data", "batch", "sample", "text", "label", "score",
})

# =============================================================================
# API CALL SCANNING CONFIGURATION
# =============================================================================

# API category keywords for rule discovery (maps API category → library keywords)
# Used by api_targeted_scanner to match API libraries to their rule categories
API_CATEGORY_KEYWORDS: Dict[str, FrozenSet[str]] = {
    "http_client": frozenset({
        "requests", "httpx", "aiohttp", "urllib3", "urllib", "http",
        "axios", "node-fetch", "got", "superagent", "fetch",
        "okhttp", "resttemplate", "webclient", "apache-httpclient",
        "httpclient", "restsharp", "flurl", "resty",
    }),
    "api_framework": frozenset({
        "flask", "fastapi", "django", "django-rest-framework", "starlette",
        "express", "koa", "hapi", "next", "nestjs", "fastify",
        "spring", "spring-boot", "spring-web", "spring-webflux", "jaxrs",
        "gin", "echo", "chi", "mux", "fiber", "gorilla",
        "aspnet", "aspnetcore", "minimal-api",
    }),
    "graphql": frozenset({
        "graphql", "graphene", "strawberry", "ariadne",
        "apollo", "graphql-request", "urql", "relay",
        "graphql-java", "graphql-dotnet", "gqlgen",
    }),
    "grpc": frozenset({
        "grpc", "grpcio", "grpc-js", "protobuf", "proto",
        "grpc-java", "grpc-dotnet", "grpc-go",
    }),
    "websocket": frozenset({
        "websocket", "websockets", "ws", "socket.io", "socketio",
        "socket-io", "channels", "signalr",
    }),
    "cloud_sdk": frozenset({
        "boto3", "botocore", "aws-sdk", "aws",
        "google-cloud", "gcloud", "firebase",
        "azure", "azure-sdk", "azure-storage",
    }),
    "api_wrapper": frozenset({
        "stripe", "twilio", "sendgrid", "slack-sdk", "slack",
        "github", "octokit", "twitter", "telegram",
        "shopify", "paypal", "braintree",
    }),
}

# Pre-computed normalized API keywords for O(1) category lookup
NORMALIZED_API_KEYWORDS: Dict[str, str] = {
    kw.replace("-", "_").replace("@", "").replace(".", "_"): category
    for category, keywords in API_CATEGORY_KEYWORDS.items()
    for kw in keywords
}

# AI provider API endpoint URL patterns (for direct HTTP call detection)
AI_API_ENDPOINT_PATTERNS: Dict[str, str] = {
    # Cloud AI providers
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
    "aiplatform.googleapis.com": "google",
    ".openai.azure.com": "azure_openai",
    "api.cohere.ai": "cohere",
    "api.cohere.com": "cohere",
    "api-inference.huggingface.co": "huggingface",
    "huggingface.co/api": "huggingface",
    "api.replicate.com": "replicate",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "api.together.xyz": "together",
    "api.together.ai": "together",
    "api.perplexity.ai": "perplexity",
    "api.fireworks.ai": "fireworks",
    # Local model servers
    "localhost:11434": "ollama",           # Ollama
    "localhost:1234": "lmstudio",           # LM Studio
    "localhost:8080": "localai",            # LocalAI / TGI / llamafile
    "localhost:8000": "vllm",               # vLLM / Triton
    "localhost:5000": "textgen_webui",       # text-generation-webui / MLflow
    "localhost:5001": "koboldcpp",           # KoboldAI / koboldcpp
    "localhost:8501": "tf_serving",          # TensorFlow Serving
    "localhost:1337": "jan",                # Jan AI
    "127.0.0.1:11434": "ollama",
    "127.0.0.1:1234": "lmstudio",
    "127.0.0.1:8080": "localai",
    "127.0.0.1:8000": "vllm",
}

# AI API call type classifications
AI_API_CALL_TYPES: FrozenSet[str] = frozenset({
    "chat_completion", "messages_api", "generate_content",
    "embedding", "image_generation", "audio", "streaming",
    "multi_provider", "inference", "local_inference",
    "direct_http", "base_url_config", "env_config",
    "api_key_config", "chat_completion_url", "embedding_url",
    "completion_url", "models_url", "sdk_init",
    "vector_db", "ai_sdk", "provider_init",
    "chat_model", "chain_invoke",
    # Local model types
    "local_model_load",  # Loading models from disk (from_pretrained, torch.load, etc.)
})

# Metavar keys to check for API URL/endpoint extraction, in priority order
API_METAVAR_PRIORITY: Tuple[str, ...] = (
    "$URL",
    "$ROUTE",
    "$TARGET",
    "$URI",
    "$SERVICE",
    "$HOST",
    "$RESOURCE",
    "$PATH",
    "$ENDPOINT",
    "$CONN",
)

# False positives to filter out during API endpoint extraction
API_FALSE_POSITIVES: FrozenSet[str] = frozenset({
    "url", "route", "path", "endpoint", "target", "host",
    "uri", "address", "service", "resource", "connection",
    "$url", "$route", "$target", "$uri", "$service",
    "none", "null", "undefined", "true", "false",
    "string", "object", "any",
})

# =============================================================================
# DEPRECATED ALIASES (for backward compatibility - prefer new names)
# =============================================================================

# These are kept for backward compatibility with modules that import old names
# TODO: Update imports in consuming modules and remove these aliases

# model_extractor.py uses MODEL_PROVIDER_PATTERNS (now MODEL_PROVIDER_PREFIXES_PATTERNS)
MODEL_PROVIDER_PATTERNS: Dict[str, FrozenSet[str]] = {
    provider: frozenset(prefixes) 
    for provider, prefixes in MODEL_PROVIDER_PREFIXES_PATTERNS.items()
}

# model_deprecation_checker.py uses DEPRECATION_PROVIDER_PATTERNS
DEPRECATION_PROVIDER_PATTERNS: Dict[str, FrozenSet[str]] = {
    provider: PROVIDER_KEYWORDS.get(provider, frozenset())
    for provider in ("anthropic", "openai", "google")
}