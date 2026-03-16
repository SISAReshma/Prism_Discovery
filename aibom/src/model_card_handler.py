"""
Model Card Handler - Fetches model cards with iterative suffix stripping
Sources: Local Cache → HuggingFace → Azure AI Foundry

Optimized version with:
- Pre-indexed cache for O(1) lookups
- Configurable API URLs and timeouts
- Reduced cyclomatic complexity
- Eliminated duplicate code
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Generator, Tuple
from functools import lru_cache

import certifi
import requests

from aibom.config import (
    MODEL_CACHE_EXPIRY_DAYS,
    MODEL_CACHE_DIR,
    HUGGINGFACE_API_BASE,
    HUGGINGFACE_RAW_BASE,
    AZURE_AI_CATALOG_API,
    MODEL_CARD_TIMEOUT,
    README_FETCH_TIMEOUT,
    MODEL_PROVIDER_PREFIXES,
)
from aibom.src.model_suffix_handler import (
    strip_model_name_incrementally,
    parse_suffix,
    extract_suffix_info
)
from core.log_sanitizer import sanitize_sensitive

logger = logging.getLogger(__name__)


# =============================================================================
# SECURE HTTP UTILITIES
# =============================================================================

def _make_secure_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs
) -> requests.Response:
    """
    Make an HTTPS request with explicit certificate verification.
    
    Args:
        url: The URL to request
        method: HTTP method (GET, POST, etc.)
        headers: Optional headers dict
        timeout: Request timeout in seconds
        **kwargs: Additional arguments passed to requests
    
    Returns:
        requests.Response object
    
    Raises:
        requests.RequestException: On network/HTTP errors
    """
    # Explicitly use certifi's certificate bundle for SSL verification
    kwargs.setdefault('verify', certifi.where())
    kwargs.setdefault('timeout', timeout)
    
    if headers:
        kwargs['headers'] = headers
    
    if method.upper() == "GET":
        return requests.get(url, **kwargs)
    elif method.upper() == "POST":
        return requests.post(url, **kwargs)
    else:
        return requests.request(method, url, **kwargs)


def _normalize_model_id(name: str) -> str:
    """Normalize model ID for filename matching."""
    return name.replace("/", "_").replace(":", "_").replace(".", "-").lower()


class ModelCache:
    """
    File-based model card cache with pre-indexed lookups.
    
    Indexes all cache file formats:
    - *_aibom.json (pre-generated AIBOM files)
    - {provider}_{model}.json (individual provider model files)
    - *_models.json (multi-model collection files, e.g. google_models.json)
    - {org}__{model}.json (HuggingFace saved cache files)
    """
    
    def __init__(self, cache_dir: Path = MODEL_CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._aibom_index: Optional[Dict[str, Path]] = None
        self._collection_index: Optional[Dict[str, Dict]] = None
    
    def _build_aibom_index(self) -> Dict[str, Path]:
        """Build index of all cache files: normalized_name -> file_path."""
        index: Dict[str, Path] = {}
        
        # Skip hidden files and multi-model collection files
        collection_suffix = "_models.json"
        
        for cache_file in self.cache_dir.glob("*.json"):
            filename = cache_file.name
            # Skip hidden files (e.g. .google_model_cache.json, .pypi_cache.json)
            if filename.startswith("."):
                continue
            # Skip multi-model collection files (indexed separately)
            if filename.endswith(collection_suffix):
                continue
            
            filename_lower = filename.lower()
            
            # Handle *_aibom.json files
            if filename_lower.endswith("_aibom.json"):
                name_part = filename_lower.replace("_aibom.json", "")
            else:
                # Handle individual provider/cached files (e.g. azure_gpt-4.json, huggingface_bert-base-uncased.json)
                name_part = filename_lower.replace(".json", "")
            
            # Strip provider prefix and index by normalized model name
            for prefix in MODEL_PROVIDER_PREFIXES:
                if name_part.startswith(prefix):
                    model_name = _normalize_model_id(name_part[len(prefix):])
                    index[model_name] = cache_file
                    # Also index with provider prefix for fuzzy matching
                    index[_normalize_model_id(name_part)] = cache_file
                    break
            else:
                normalized = _normalize_model_id(name_part)
                index[normalized] = cache_file
                # For org__model files (e.g. microsoft__phi-3.5-mini-instruct),
                # also index by just the model name part
                if "__" in name_part:
                    model_only = name_part.split("__", 1)[1]
                    index[_normalize_model_id(model_only)] = cache_file
        
        return index
    
    def _build_collection_index(self) -> Dict[str, Dict]:
        """Build index from multi-model collection files (*_models.json): model_id -> model data."""
        index: Dict[str, Dict] = {}
        
        for collection_file in self.cache_dir.glob("*_models.json"):
            # Skip hidden files
            if collection_file.name.startswith("."):
                continue
            try:
                with open(collection_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                provider = data.get("provider", collection_file.stem.replace("_models", ""))
                models = data.get("models", [])
                for model_entry in models:
                    model_id = model_entry.get("model_id", "")
                    if not model_id:
                        continue
                    normalized = _normalize_model_id(model_id)
                    model_entry_copy = dict(model_entry)
                    model_entry_copy["_provider"] = provider
                    model_entry_copy["_collection_file"] = collection_file.name
                    index[normalized] = model_entry_copy
            except Exception as e:
                logger.warning(f"Error loading collection file {collection_file}: {e}")
        
        return index
    
    @property
    def aibom_index(self) -> Dict[str, Path]:
        """Lazy-loaded file-based cache index."""
        if self._aibom_index is None:
            self._aibom_index = self._build_aibom_index()
        return self._aibom_index
    
    @property
    def collection_index(self) -> Dict[str, Dict]:
        """Lazy-loaded collection-based cache index."""
        if self._collection_index is None:
            self._collection_index = self._build_collection_index()
        return self._collection_index
    
    def invalidate_index(self) -> None:
        """Invalidate all cache indices (call after adding new files)."""
        self._aibom_index = None
        self._collection_index = None
    
    def _get_cache_path(self, model_id: str) -> Path:
        """Get cache file path for model ID."""
        safe_id = model_id.replace("/", "__").replace("\\", "__")
        return self.cache_dir / f"{safe_id}.json"
    
    def _load_aibom_file(self, cache_file: Path, source: str) -> Optional[Dict]:
        """Load and tag an AIBOM file."""
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"AIBOM cache hit ({source}): {cache_file.name}")
            data["_lookup_source"] = source
            data["_cache_file"] = cache_file.name
            return data
        except Exception as e:
            logger.warning(f"Error reading AIBOM cache {cache_file}: {e}")
            return None
    
    def get_aibom(self, model_id: str) -> Optional[Dict]:
        """
        Search for model in cache (exact match).
        Checks file-based index first, then collection index.
        O(1) lookup using pre-built indices.
        """
        safe_id = _normalize_model_id(model_id)
        
        # Check file-based index
        if cache_file := self.aibom_index.get(safe_id):
            return self._load_aibom_file(cache_file, "local_aibom_cache")
        
        # Check multi-model collection index
        if collection_entry := self.collection_index.get(safe_id):
            result = dict(collection_entry)
            result["_lookup_source"] = "local_collection_cache"
            logger.info(f"Collection cache hit: {model_id} from {result.get('_collection_file', '?')}")
            return result
        
        return None
    
    def search_aibom_fuzzy(self, model_id: str) -> Optional[Dict]:
        """
        Fuzzy search for model - matches if model_id is contained in indexed name.
        Checks both file-based and collection indices.
        O(n) worst case, but typically fast due to early termination.
        """
        safe_id = _normalize_model_id(model_id)
        
        # Fuzzy search file-based index
        for indexed_name, cache_file in self.aibom_index.items():
            if safe_id in indexed_name or indexed_name in safe_id:
                return self._load_aibom_file(cache_file, "local_aibom_cache_fuzzy")
        
        # Fuzzy search collection index
        for indexed_name, entry in self.collection_index.items():
            if safe_id in indexed_name or indexed_name in safe_id:
                result = dict(entry)
                result["_lookup_source"] = "local_collection_cache_fuzzy"
                logger.info(f"Collection cache fuzzy hit: {model_id} from {result.get('_collection_file', '?')}")
                return result
        
        return None
    
    def get(self, model_id: str) -> Optional[Dict]:
        """
        Get cached model card if exists and not expired.
        Checks AIBOM format first, then regular cache.
        """
        # First check AIBOM cache (pre-generated)
        if aibom := self.get_aibom(model_id):
            return aibom
        
        # Then check regular cache
        cache_path = self._get_cache_path(model_id)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            
            # Check expiry
            cached_time = datetime.fromisoformat(cached.get("cached_at", "2000-01-01"))
            if datetime.now() - cached_time > timedelta(days=MODEL_CACHE_EXPIRY_DAYS):
                logger.info(f"Cache expired for {model_id}")
                return None
            
            result = cached.get("data", cached)
            result["_lookup_source"] = "cache"
            result["_cached_at"] = cached.get("cached_at")
            return result
            
        except Exception as e:
            logger.warning(f"Error reading cache for {model_id}: {e}")
            return None
    
    def save(self, model_id: str, data: Dict, source: str = "unknown") -> bool:
        """Save model card to cache."""
        cache_path = self._get_cache_path(model_id)
        
        try:
            cache_entry = {
                "model_id": model_id,
                "source": source,
                "cached_at": datetime.now().isoformat(),
                "data": data
            }
            
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2, default=str)
            
            logger.info(f"Cached model card for {model_id} from {source}")
            return True
            
        except Exception as e:
            logger.error(f"Error caching model {model_id}: {e}")
            return False


class HuggingFaceProvider:
    """Fetch model cards from HuggingFace Hub API."""
    
    @classmethod
    def fetch(cls, model_id: str, hf_token: Optional[str] = None) -> Optional[Dict]:
        """
        Fetch model metadata from HuggingFace API.
        Returns:
            Model card dict with '_lookup_source' set, or None if not found
        """
        url = f"{HUGGINGFACE_API_BASE}/{model_id}"
        headers = {"Authorization": f"Bearer {hf_token}"} if hf_token else {}
        
        try:
            response = _make_secure_request(url, headers=headers, timeout=MODEL_CARD_TIMEOUT)
            
            # Handle common failure cases
            if response.status_code in (404, 401):
                logger.debug(f"Model not accessible on HuggingFace ({response.status_code}): {model_id}")
                return None
            
            if response.status_code != 200:
                logger.debug(f"HuggingFace API returned {response.status_code} for {model_id}")
                return None
            
            data = response.json()
            
            result = {
                "model_id": data.get("id", model_id),
                "model_name": data.get("modelId", model_id),
                "author": data.get("author"),
                "pipeline_tag": data.get("pipeline_tag"),
                "tags": data.get("tags", []),
                "library_name": data.get("library_name"),
                "license": data.get("license"),
                "downloads": data.get("downloads", 0),
                "likes": data.get("likes", 0),
                "created_at": data.get("createdAt"),
                "last_modified": data.get("lastModified"),
                "siblings": data.get("siblings", []),
                "card_data": data.get("cardData", {}),
                "spaces": data.get("spaces", []),
                "gated": data.get("gated", False),
                "disabled": data.get("disabled", False),
                "_lookup_source": "huggingface",
                "_raw_response": data
            }
            
            # Try to fetch README
            result["has_model_card"] = cls._fetch_readme(model_id, result, headers)
            
            return result
            
        except requests.Timeout:
            logger.error("Timeout fetching model from HuggingFace", extra={"model_id": model_id})
            return None
        except Exception as e:
            # Sanitize error to prevent token leakage
            logger.error("Error fetching model from HuggingFace", extra={"model_id": model_id, "error": sanitize_sensitive(str(e))})
            return None
    
    @classmethod
    def _fetch_readme(cls, model_id: str, result: Dict, headers: Dict) -> bool:
        """Fetch README content and add to result. Returns True if found."""
        readme_url = f"{HUGGINGFACE_RAW_BASE}/{model_id}/raw/main/README.md"
        try:
            readme_response = _make_secure_request(readme_url, headers=headers, timeout=README_FETCH_TIMEOUT)
            if readme_response.status_code == 200:
                result["readme_content"] = readme_response.text
                return True
        except Exception:
            pass
        return False


class AzureAIFoundryProvider:
    """Fetch model info from Azure AI Foundry catalog."""
    
    @classmethod
    def fetch(cls, model_id: str) -> Optional[Dict]:
        """Attempt to fetch model from Azure AI Foundry."""
        try:
            search_url = f"{AZURE_AI_CATALOG_API}?search={model_id}"
            
            response = _make_secure_request(
                search_url,
                timeout=MODEL_CARD_TIMEOUT,
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
            )
            
            if response.status_code != 200:
                logger.debug(f"Azure catalog returned {response.status_code}")
                return None
            
            data = response.json()
            models = data.get("models", data.get("items", []))
            
            if not models:
                return None
            
            # Find exact or close match
            model_id_lower = model_id.lower()
            for model in models:
                name = model.get("name", "").lower()
                if model_id_lower in name or name in model_id_lower:
                    return {
                        "model_id": model.get("id", model_id),
                        "model_name": model.get("name"),
                        "description": model.get("description"),
                        "publisher": model.get("publisher"),
                        "version": model.get("version"),
                        "task": model.get("task"),
                        "license": model.get("license"),
                        "_lookup_source": "azure_ai_foundry"
                    }
            
            return None
            
        except Exception as e:
            logger.debug(f"Azure AI Foundry fetch error for {model_id}: {e}")
            return None


# =============================================================================
# LOOKUP STRATEGY
# =============================================================================

def _try_providers(
    model_name: str,
    cache: ModelCache,
    hf_token: Optional[str],
    try_azure: bool
) -> Tuple[Optional[Dict], str]:
    """
    Try all providers for a model name.
    Returns (result, source) or (None, "").
    """
    # 1. Local AIBOM cache
    if cached := cache.get_aibom(model_name):
        return cached, "local_aibom_cache"
    
    # 2. Fuzzy AIBOM cache match
    if cached := cache.search_aibom_fuzzy(model_name):
        return cached, "local_aibom_cache_fuzzy"
    
    # 3. HuggingFace
    if hf_result := HuggingFaceProvider.fetch(model_name, hf_token):
        cache.save(model_name, hf_result, source="huggingface")
        return hf_result, "huggingface"
    
    # 4. Azure AI Foundry
    if try_azure:
        if azure_result := AzureAIFoundryProvider.fetch(model_name):
            cache.save(model_name, azure_result, source="azure_ai_foundry")
            return azure_result, "azure_ai_foundry"
    
    return None, ""


def fetch_model_card(
    model_name: str,
    hf_token: Optional[str] = None,
    cache: Optional[ModelCache] = None,
    try_stripping: bool = True,
    try_azure: bool = True
) -> Dict[str, Any]:
    """
    Fetch model card with cascading lookup strategy.
    
    Lookup order:
    1. Local AIBOM cache (exact match)
    2. Local AIBOM cache (fuzzy match)
    3. HuggingFace API
    4. Azure AI Foundry
    5. Strip suffixes and retry 1-4
    
    Args:
        model_name: Full model name (e.g., "gpt-3.5-turbo-16k")
        hf_token: Optional HuggingFace API token
        cache: ModelCache instance (will create one if None)
        try_stripping: Whether to try suffix stripping if not found
        try_azure: Whether to try Azure AI Foundry
    
    Returns:
        Dict with model_card_found, model_card, lookup_source, etc.
    """
    if cache is None:
        cache = ModelCache()
    
    result = {
        "model_card_found": False,
        "original_model_name": model_name,
        "base_model_name": model_name,
        "stripped_suffixes": [],
        "suffix_info": [],
        "model_card": None,
        "lookup_source": None,
        "iterations_required": 0
    }
    
    iteration = 0
    
    # Try with original name first
    iteration += 1
    logger.info(f"Iteration {iteration}: Trying providers for: {model_name}")
    
    model_card, source = _try_providers(model_name, cache, hf_token, try_azure)
    if model_card:
        result["model_card_found"] = True
        result["model_card"] = model_card
        result["lookup_source"] = source
        result["iterations_required"] = iteration
        return result
    
    # Try with stripped suffixes
    if try_stripping:
        for stripped_name, removed_suffixes in strip_model_name_incrementally(model_name):
            iteration += 1
            logger.info(f"Iteration {iteration}: Trying stripped name: {stripped_name}")
            
            model_card, source = _try_providers(stripped_name, cache, hf_token, try_azure)
            if model_card:
                result["model_card_found"] = True
                result["base_model_name"] = stripped_name
                result["stripped_suffixes"] = removed_suffixes
                result["model_card"] = model_card
                result["lookup_source"] = f"{source}_stripped"
                result["iterations_required"] = iteration
                result["suffix_info"] = [parse_suffix(s) for s in removed_suffixes]
                return result
    
    # Not found - extract suffix info for reference
    result["iterations_required"] = iteration
    suffix_info_full = extract_suffix_info(model_name)
    if suffix_info_full.get("has_suffixes"):
        result["suffix_info"] = suffix_info_full.get("parsed_suffixes", [])
    
    return result


def process_models_for_cards(
    model_names: List[str],
    hf_token: Optional[str] = None,
    try_stripping: bool = True,
    try_azure: bool = True
) -> Dict[str, Any]:
    """
    Process multiple model names and fetch their model cards.
    
    Returns:
        Dict with models_processed, found_count, results, summary
    """
    cache = ModelCache()
    
    results: List[Dict] = []
    found_count = 0
    source_counts: Dict[str, int] = {}
    
    for model_name in model_names:
        result = fetch_model_card(
            model_name=model_name,
            hf_token=hf_token,
            cache=cache,
            try_stripping=try_stripping,
            try_azure=try_azure
        )
        
        results.append(result)
        
        if result["model_card_found"]:
            found_count += 1
            source = result["lookup_source"] or "unknown"
            source_counts[source] = source_counts.get(source, 0) + 1
    
    total = len(model_names)
    return {
        "models_processed": total,
        "found_count": found_count,
        "not_found_count": total - found_count,
        "results": results,
        "summary": {
            "source_breakdown": source_counts,
            "success_rate": f"{(found_count / total * 100):.1f}%" if total else "0%"
        }
    }


__all__ = [
    "ModelCache",
    "HuggingFaceProvider",
    "AzureAIFoundryProvider",
    "fetch_model_card",
    "process_models_for_cards"
]
