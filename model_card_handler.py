"""
Model Card Handler - Fetches model cards with iterative suffix stripping
Sources: Local Cache → HuggingFace → Azure AI Foundry

Adapted from Prism-AIBOM for AIBOM_endpoints API.
"""
import os
import json
import re
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import logging

from model_suffix_handler import (
    strip_model_name_incrementally,
    parse_suffix,
    extract_suffix_info
)

logger = logging.getLogger(__name__)

# Cache settings
CACHE_EXPIRY_DAYS = 7
# Correct cache path: .model_cache (hidden directory) in Prism-AIBOM
MODEL_CACHE_PATH = Path(__file__).parent.parent / "Prism-AIBOM" / ".model_cache"


def _normalize_model_id(name: str) -> str:
    """Normalize model ID for filename matching."""
    return name.replace('/', '_').replace(':', '_').replace('.', '-').lower()


class ModelCache:
    """
    File-based model card cache.
    Matches Prism-AIBOM's cache format with pre-generated AIBOMs.
    """
    
    def __init__(self, cache_dir: Path = MODEL_CACHE_PATH):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, model_id: str) -> Path:
        """Get cache file path for model ID (sanitized)."""
        # Sanitize model ID for filesystem (replace / with _)
        safe_id = model_id.replace("/", "__").replace("\\", "__")
        return self.cache_dir / f"{safe_id}.json"
    
    def get_aibom(self, model_id: str) -> Optional[Dict]:
        """
        Search for pre-generated AIBOM in cache (exact match).
        Looks for files like openai_gpt-3-5-turbo_aibom.json
        
        Args:
            model_id: Model name to search for (e.g., "gpt-3.5-turbo")
        
        Returns:
            AIBOM data dict if found, None otherwise
        """
        safe_id = _normalize_model_id(model_id)
        
        # Search through all AIBOM files in cache
        for cache_file in self.cache_dir.glob("*_aibom.json"):
            filename = cache_file.name.lower()
            # Extract model name from filename (format: provider_modelname_aibom.json)
            name_part = filename.replace('_aibom.json', '')
            # Provider prefix removal
            for prefix in ['openai_', 'anthropic_', 'google_', 'huggingface_', 'azure_']:
                if name_part.startswith(prefix):
                    name_part = name_part[len(prefix):]
                    break
            
            # Compare normalized versions
            if name_part == safe_id:
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    logger.info(f"AIBOM cache hit: {cache_file.name}")
                    data["_lookup_source"] = "local_aibom_cache"
                    data["_cache_file"] = str(cache_file.name)
                    return data
                except Exception as e:
                    logger.warning(f"Error reading AIBOM cache: {e}")
        
        return None
    
    def search_aibom_fuzzy(self, model_id: str) -> Optional[Dict]:
        """
        Fuzzy search for AIBOM in cache - matches if model_id is contained in filename.
        Used for stripped model name matching.
        
        Args:
            model_id: Base model name to search for
        
        Returns:
            AIBOM data dict if found, None otherwise
        """
        safe_id = _normalize_model_id(model_id)
        
        for cache_file in self.cache_dir.glob("*_aibom.json"):
            filename = cache_file.name.lower()
            name_part = filename.replace('_aibom.json', '')
            
            # Check if the safe_id matches the model part of the filename
            for prefix in ['openai_', 'anthropic_', 'google_', 'huggingface_', 'azure_']:
                if name_part.startswith(prefix):
                    model_part = name_part[len(prefix):]
                    if model_part == safe_id or safe_id in model_part:
                        try:
                            with open(cache_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            logger.info(f"AIBOM fuzzy match: {cache_file.name} for '{model_id}'")
                            data["_lookup_source"] = "local_aibom_cache_fuzzy"
                            data["_cache_file"] = str(cache_file.name)
                            return data
                        except Exception as e:
                            logger.warning(f"Error reading AIBOM cache: {e}")
                    break
        
        return None
    
    def get(self, model_id: str) -> Optional[Dict]:
        """
        Get cached model card if exists and not expired.
        Checks both AIBOM format and regular cache format.
        
        Returns:
            Model card dict with 'source' set to 'cache', or None
        """
        # First check AIBOM cache (pre-generated)
        aibom = self.get_aibom(model_id)
        if aibom:
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
            if datetime.now() - cached_time > timedelta(days=CACHE_EXPIRY_DAYS):
                logger.info(f"Cache expired for {model_id}")
                return None
            
            # Return cached data with source tag
            result = cached.get("data", cached)
            result["_lookup_source"] = "cache"
            result["_cached_at"] = cached.get("cached_at")
            return result
            
        except Exception as e:
            logger.warning(f"Error reading cache for {model_id}: {e}")
            return None
    
    def save(self, model_id: str, data: Dict, source: str = "unknown") -> bool:
        """
        Save model card to cache.
        
        Args:
            model_id: Model identifier
            data: Model card data
            source: Where the data came from (huggingface, azure, etc.)
        
        Returns:
            True if saved successfully
        """
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
    """
    Fetch model cards from HuggingFace Hub API.
    """
    
    API_BASE = "https://huggingface.co/api/models"
    
    @classmethod
    def fetch(cls, model_id: str, hf_token: Optional[str] = None) -> Optional[Dict]:
        """
        Fetch model metadata from HuggingFace API.
        
        Args:
            model_id: Model identifier (e.g., "openai/gpt-3.5-turbo")
            hf_token: Optional HuggingFace API token
        
        Returns:
            Model card dict with '_lookup_source' set, or None if not found
        """
        url = f"{cls.API_BASE}/{model_id}"
        
        headers = {}
        if hf_token:
            headers["Authorization"] = f"Bearer {hf_token}"
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 404:
                logger.debug(f"Model not found on HuggingFace: {model_id}")
                return None
            
            if response.status_code == 401:
                # 401 usually means model doesn't exist or is private/gated
                # Not necessarily an invalid token
                logger.debug(f"Model not accessible on HuggingFace (401): {model_id}")
                return None
            
            if response.status_code != 200:
                logger.debug(f"HuggingFace API returned {response.status_code} for {model_id}")
                return None
            
            data = response.json()
            
            # Structure the response
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
                "_raw_response": data  # Keep raw response
            }
            
            # Try to fetch README/model card content
            readme_url = f"https://huggingface.co/{model_id}/raw/main/README.md"
            try:
                readme_response = requests.get(readme_url, headers=headers, timeout=15)
                if readme_response.status_code == 200:
                    result["readme_content"] = readme_response.text
                    result["has_model_card"] = True
                else:
                    result["has_model_card"] = False
            except Exception:
                result["has_model_card"] = False
            
            return result
            
        except requests.Timeout:
            logger.error(f"Timeout fetching {model_id} from HuggingFace")
            return None
        except Exception as e:
            logger.error(f"Error fetching {model_id} from HuggingFace: {e}")
            return None


class AzureAIFoundryProvider:
    """
    Fetch model info from Azure AI Foundry catalog.
    Note: This is a simplified implementation without Playwright.
    For full scraping, see Prism-AIBOM's model_fetcher.py
    """
    
    CATALOG_API = "https://ai.azure.com/api/catalog/models"
    
    @classmethod
    def fetch(cls, model_id: str) -> Optional[Dict]:
        """
        Attempt to fetch model from Azure AI Foundry.
        
        Note: This is a basic implementation. Azure AI Foundry
        may require authentication or browser-based access.
        
        Args:
            model_id: Model identifier
        
        Returns:
            Model info dict or None
        """
        # Azure AI Foundry uses different naming conventions
        # This is a simplified check - full implementation requires Playwright
        
        try:
            # Try the public catalog API endpoint
            search_url = f"{cls.CATALOG_API}?search={model_id}"
            
            response = requests.get(search_url, timeout=30, headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0"
            })
            
            if response.status_code != 200:
                logger.debug(f"Azure catalog returned {response.status_code}")
                return None
            
            data = response.json()
            
            # Check if we got results
            models = data.get("models", data.get("items", []))
            if not models:
                return None
            
            # Find exact or close match
            for model in models:
                name = model.get("name", "").lower()
                if model_id.lower() in name or name in model_id.lower():
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


def fetch_model_card(
    model_name: str,
    hf_token: Optional[str] = None,
    cache: Optional[ModelCache] = None,
    try_stripping: bool = True,
    try_azure: bool = True
) -> Dict[str, Any]:
    """
    Fetch model card with cascading lookup strategy (matches Prism-AIBOM).
    
    Lookup order (Prism-AIBOM workflow):
    1. Local AIBOM cache (exact match) - Pre-generated AIBOMs for OpenAI, Anthropic, etc.
    2. HuggingFace API (for open-source models)
    3. Azure AI Foundry (for Azure-hosted models)
    4. Strip suffixes and try local AIBOM cache again
    5. Strip suffixes and retry HF/Azure
    
    Args:
        model_name: Full model name (e.g., "gpt-3.5-turbo-16k")
        hf_token: Optional HuggingFace API token
        cache: ModelCache instance (will create one if None)
        try_stripping: Whether to try suffix stripping if not found
        try_azure: Whether to try Azure AI Foundry
    
    Returns:
        Dict with:
        - model_card_found: bool
        - original_model_name: str
        - base_model_name: str (may differ if stripping worked)
        - stripped_suffixes: List of removed suffixes
        - suffix_info: List of parsed suffix meanings
        - model_card: Dict or None
        - lookup_source: str (local_aibom_cache, huggingface, azure, etc.)
        - iterations_required: int
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
    
    # ===== STEP 1: Check local AIBOM cache first (exact match) =====
    iteration += 1
    logger.info(f"Step 1: Checking local AIBOM cache for: {model_name}")
    cached_aibom = cache.get_aibom(model_name)
    if cached_aibom:
        result["model_card_found"] = True
        result["model_card"] = cached_aibom
        result["lookup_source"] = "local_aibom_cache"
        result["iterations_required"] = iteration
        return result
    
    # ===== STEP 2: Try HuggingFace with full name =====
    iteration += 1
    logger.info(f"Step 2: Trying HuggingFace for: {model_name}")
    hf_result = HuggingFaceProvider.fetch(model_name, hf_token)
    if hf_result:
        cache.save(model_name, hf_result, source="huggingface")
        result["model_card_found"] = True
        result["model_card"] = hf_result
        result["lookup_source"] = "huggingface"
        result["iterations_required"] = iteration
        return result
    
    # ===== STEP 3: Try Azure AI Foundry with full name =====
    if try_azure:
        iteration += 1
        logger.info(f"Step 3: Trying Azure AI Foundry for: {model_name}")
        azure_result = AzureAIFoundryProvider.fetch(model_name)
        if azure_result:
            cache.save(model_name, azure_result, source="azure_ai_foundry")
            result["model_card_found"] = True
            result["model_card"] = azure_result
            result["lookup_source"] = "azure_ai_foundry"
            result["iterations_required"] = iteration
            return result
    
    # ===== STEP 4 & 5: Strip suffixes and retry =====
    if try_stripping:
        for stripped_name, removed_suffixes in strip_model_name_incrementally(model_name):
            iteration += 1
            logger.info(f"Step 4/5: Trying stripped name: {stripped_name} (removed: {removed_suffixes})")
            
            # Try local AIBOM cache with stripped name
            cached_aibom = cache.get_aibom(stripped_name)
            if cached_aibom:
                result["model_card_found"] = True
                result["base_model_name"] = stripped_name
                result["stripped_suffixes"] = removed_suffixes
                result["model_card"] = cached_aibom
                result["lookup_source"] = "local_aibom_cache_stripped"
                result["iterations_required"] = iteration
                
                # Parse suffix info
                for suffix in removed_suffixes:
                    result["suffix_info"].append(parse_suffix(suffix))
                
                return result
            
            # Also try fuzzy match in AIBOM cache
            cached_aibom = cache.search_aibom_fuzzy(stripped_name)
            if cached_aibom:
                result["model_card_found"] = True
                result["base_model_name"] = stripped_name
                result["stripped_suffixes"] = removed_suffixes
                result["model_card"] = cached_aibom
                result["lookup_source"] = "local_aibom_cache_fuzzy"
                result["iterations_required"] = iteration
                
                for suffix in removed_suffixes:
                    result["suffix_info"].append(parse_suffix(suffix))
                
                return result
            
            # Try HuggingFace with stripped name
            hf_result = HuggingFaceProvider.fetch(stripped_name, hf_token)
            if hf_result:
                cache.save(stripped_name, hf_result, source="huggingface")
                result["model_card_found"] = True
                result["base_model_name"] = stripped_name
                result["stripped_suffixes"] = removed_suffixes
                result["model_card"] = hf_result
                result["lookup_source"] = "huggingface_stripped"
                result["iterations_required"] = iteration
                
                for suffix in removed_suffixes:
                    result["suffix_info"].append(parse_suffix(suffix))
                
                return result
            
            # Try Azure with stripped name
            if try_azure:
                azure_result = AzureAIFoundryProvider.fetch(stripped_name)
                if azure_result:
                    cache.save(stripped_name, azure_result, source="azure_ai_foundry")
                    result["model_card_found"] = True
                    result["base_model_name"] = stripped_name
                    result["stripped_suffixes"] = removed_suffixes
                    result["model_card"] = azure_result
                    result["lookup_source"] = "azure_ai_foundry_stripped"
                    result["iterations_required"] = iteration
                    
                    for suffix in removed_suffixes:
                        result["suffix_info"].append(parse_suffix(suffix))
                    
                    return result
    
    # Not found anywhere
    result["iterations_required"] = iteration
    
    # Still extract suffix info from original name for reference
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
    
    Args:
        model_names: List of model names to lookup
        hf_token: Optional HuggingFace API token
        try_stripping: Whether to try suffix stripping
        try_azure: Whether to try Azure AI Foundry
    
    Returns:
        Dict with:
        - models_processed: int
        - found_count: int
        - not_found_count: int
        - results: List of fetch results
        - summary: Dict with source breakdown
    """
    cache = ModelCache()
    
    results = []
    found_count = 0
    source_counts = {}
    
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
            source = result["lookup_source"]
            source_counts[source] = source_counts.get(source, 0) + 1
    
    return {
        "models_processed": len(model_names),
        "found_count": found_count,
        "not_found_count": len(model_names) - found_count,
        "results": results,
        "summary": {
            "source_breakdown": source_counts,
            "success_rate": f"{(found_count / len(model_names) * 100):.1f}%" if model_names else "0%"
        }
    }


# Expose for imports
__all__ = [
    "ModelCache",
    "HuggingFaceProvider", 
    "AzureAIFoundryProvider",
    "fetch_model_card",
    "process_models_for_cards"
]
