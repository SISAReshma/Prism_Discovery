"""
AIBOM Configuration Constants
Centralized constants and mappings for the AIBOM API
"""

from typing import Literal

# =============================================================================
# SOURCE TYPES
# =============================================================================

SOURCE_TYPES = Literal["repo_public", "repo_private", "zip", "local"]

# Mapping of source types to their validate endpoints
ENDPOINT_MAP = {
    "repo_public": "/validate/repo_public",
    "repo_private": "/validate/repo_private",
    "zip": "/validate/zip",
    "local": "/validate/local"
}

# =============================================================================
# FILE/UPLOAD LIMITS
# =============================================================================

MAX_UPLOAD_SIZE_MB = 500
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 500MB

MAX_ZIP_FILE_COUNT = 50000
MAX_LOCAL_FILE_COUNT = 10000

# =============================================================================
# TEMP DIRECTORY
# =============================================================================

TEMP_DIR_PREFIX = "aibom_"

# Directories to skip when counting files
SKIP_DIRECTORIES = {'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}

# Code file extensions (for detecting source files)
CODE_FILE_EXTENSIONS = {
    # Python
    '.py', '.pyx', '.pxd', '.pyi',
    # JavaScript/TypeScript
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    # Web
    '.html', '.htm', '.css', '.scss', '.sass', '.less',
    # Other languages
    '.java', '.kt', '.kts', '.scala',
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
    '.cs', '.fs',
    '.go',
    '.rs',
    '.rb',
    '.php',
    '.swift',
    '.m', '.mm',
    # Config/Data
    '.json', '.yaml', '.yml', '.toml', '.xml',
    # Shell
    '.sh', '.bash', '.zsh', '.fish', '.ps1',
    # SQL
    '.sql',
}

# =============================================================================
# SEMGREP CONFIGURATION
# =============================================================================

# Semgrep scanner settings
SEMGREP_MAX_MEMORY_MB = 2048
SEMGREP_TIMEOUT_SECONDS = 300  # 5 minutes

# Language to rule file mapping (relative to semgrep/ directory)
# Format: {"language_name": "folder/rule_file.yml"}
SEMGREP_RULE_FILES = {
    "python": "python/python_imports.yml",
    "javascript": "javascript/javascript_imports.yml",
    # Add new languages here:
    # "go": "go/go_imports.yml",
    # "rust": "rust/rust_imports.yml",
}

# Language-specific import extractors (maps to function names in semgrep_scanner)
SEMGREP_IMPORT_EXTRACTORS = {
    "python": "extract_python_import_info",
    "javascript": "extract_js_import_info",
}

# =============================================================================
# GITHUB
# =============================================================================

GITHUB_API_BASE = "https://api.github.com"
GITHUB_CLONE_TIMEOUT = 120  # seconds
GITHUB_API_TIMEOUT = 15  # seconds

# Valid PAT prefixes
VALID_PAT_PREFIXES = ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_")

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
