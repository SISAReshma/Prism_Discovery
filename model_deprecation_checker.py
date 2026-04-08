"""
Model Deprecation Checker - Optimized
Validates models against deprecation databases with O(1) lookups.
Builds replacement chains lazily for memory efficiency.

"""
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, FrozenSet
from datetime import datetime
import logging

# Import from same directory to avoid path issues
import sys
_module_dir = Path(__file__).parent
if str(_module_dir) not in sys.path:
    sys.path.insert(0, str(_module_dir))

from config import (
    DEPRECATION_CACHE_DIR,
    DEPRECATION_MAX_CHAIN_DEPTH,
    DEPRECATION_SEVERITY_THRESHOLDS,
    DEPRECATION_PROVIDER_PATTERNS,
    DEPRECATED_STATUSES,
)

logger = logging.getLogger(__name__)


class ModelDeprecationChecker:
    """
    Check models against provider deprecation databases.
    
    Performance optimizations:
    - O(1) model lookups via pre-built index
    - Lazy replacement chain building
    - Cached provider detection
    """
    
    def __init__(self):
        """Initialize checker and load provider data."""
        self.deprecation_data: Dict[str, Dict] = {}
        self.model_index: Dict[str, Dict] = {}  # model_name -> {provider, deprecation_data}
        self.replacement_chains: Dict[str, Dict] = {}  # Lazy-loaded chains
        self._load_all_providers()
        self._build_model_index()
    
    def _load_all_providers(self) -> None:
        """Load deprecation data from all provider JSON files."""
        if not DEPRECATION_CACHE_DIR.exists():
            logger.warning(f"No deprecation cache directory: {DEPRECATION_CACHE_DIR}")
            return
        
        for json_file in DEPRECATION_CACHE_DIR.glob("*_deprecations.json"):
            provider_name = json_file.stem.replace("_deprecations", "").lower()
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    self.deprecation_data[provider_name] = json.load(f)
                logger.info(f"Loaded {provider_name} deprecation data")
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")
    
    def _build_model_index(self) -> None:
        """
        Build O(1) lookup index: model_name -> deprecation info.
        Replaces O(n) linear search through all deprecations.
        """
        for provider, data in self.deprecation_data.items():
            deprecations = data.get("deprecations", [])
            
            for dep in deprecations:
                model_id = dep.get("model_or_system", "")
                if not model_id:
                    continue
                
                # Index by normalized name
                normalized = self._normalize_model_name(model_id)
                
                # Store full deprecation data with provider
                self.model_index[normalized] = {
                    "provider": provider,
                    "data": dep,
                    "original_id": model_id
                }
    
    @staticmethod
    @lru_cache(maxsize=512)
    def _normalize_model_name(model_name: str) -> str:
        """Normalize model name for matching (cached for performance)."""
        return model_name.replace("_", "-").lower()
    
    def _get_replacement_chain(self, model_id: str, provider: str) -> Dict:
        """
        Get or build replacement chain lazily (only when requested).
        Reduces initialization time from O(n) to O(1) for unused models.
        """
        cache_key = f"{provider}:{model_id}"
        
        if cache_key in self.replacement_chains:
            return self.replacement_chains[cache_key]
        
        # Build chain on demand
        data = self.deprecation_data.get(provider, {})
        deprecations = data.get("deprecations", [])
        
        # Build lookup for this provider
        model_lookup = {dep.get("model_or_system", ""): dep for dep in deprecations}
        
        chain = self._trace_replacement_chain(model_id, model_lookup)
        self.replacement_chains[cache_key] = chain
        
        return chain
    
    def _trace_replacement_chain(self, model_id: str, model_lookup: Dict) -> Dict:
        """
        Recursively trace replacement chain to find final active model.
        Returns chain info with depth and final replacement.
        """
        chain = [model_id]
        visited = {model_id}
        current = model_id
        
        for _ in range(DEPRECATION_MAX_CHAIN_DEPTH):
            model_data = model_lookup.get(current)
            if not model_data:
                break
            
            replacement = model_data.get("recommended_replacement")
            if not replacement:
                break
            
            # Handle "model1 or model2" format - take first option
            if " or " in replacement:
                replacement = replacement.split(" or ")[0].strip()
            
            # Check if replacement is also deprecated
            if replacement not in model_lookup:
                # Not in deprecation list = likely active
                chain.append(replacement)
                return {
                    "chain": chain,
                    "final_replacement": replacement,
                    "depth": len(chain) - 1
                }
            
            # Prevent circular references
            if replacement in visited:
                logger.warning(f"Circular replacement for {model_id}")
                break
            
            chain.append(replacement)
            visited.add(replacement)
            current = replacement
        
        # Return partial chain if no final active replacement
        return {
            "chain": chain,
            "final_replacement": chain[-1] if len(chain) > 1 else None,
            "depth": len(chain) - 1
        }
    
    def check_model(self, model_name: str, provider: Optional[str] = None) -> Optional[Dict]:
        """
        Check if a model is deprecated/retired (O(1) lookup).
        
        Args:
            model_name: Model identifier to check
            provider: Optional provider hint (anthropic, openai, google)
        
        Returns:
            Deprecation info dict or None if model is active/not found
        """
        normalized = self._normalize_model_name(model_name)
        
        # O(1) index lookup
        indexed = self.model_index.get(normalized)
        if not indexed:
            return None
        
        # Verify provider if specified
        if provider and indexed["provider"] != provider.lower():
            return None
        
        dep = indexed["data"]
        provider_name = indexed["provider"]
        status = dep.get("status", "").lower()
        
        # Only return if actually deprecated
        if status not in DEPRECATED_STATUSES:
            return None
        
        # Get replacement chain (lazy-loaded)
        chain_info = self._get_replacement_chain(indexed["original_id"], provider_name)
        
        # Build response
        return self._build_deprecation_response(dep, provider_name, status, chain_info)
    
    def _build_deprecation_response(
        self, 
        dep: Dict, 
        provider: str, 
        status: str, 
        chain_info: Dict
    ) -> Dict:
        """Build standardized deprecation response (extracted for clarity)."""
        days_until_shutdown = self._calculate_days_until_shutdown(dep)
        severity = self._calculate_severity(status, days_until_shutdown)
        
        return {
            "model_id": dep.get("model_or_system"),
            "provider": provider,
            "status": status,
            "is_deprecated": status in DEPRECATED_STATUSES,
            "severity": severity,
            "announcement_date": dep.get("announcement_date"),
            "shutdown_date": dep.get("shutdown_date"),
            "days_until_shutdown": days_until_shutdown,
            "recommended_replacement": dep.get("recommended_replacement"),
            "final_replacement": chain_info.get("final_replacement"),
            "replacement_chain": chain_info.get("chain", []),
            "category": dep.get("category"),
            "type": dep.get("type"),
            "notes": dep.get("notes", ""),
            "deprecated_price": dep.get("deprecated_price")
        }
    
    @staticmethod
    @lru_cache(maxsize=256)
    def _detect_provider(model_name: str) -> Optional[str]:
        """
        Detect provider from model name patterns (cached).
        Uses config-based patterns for maintainability.
        """
        model_lower = model_name.lower()
        
        for provider, patterns in DEPRECATION_PROVIDER_PATTERNS.items():
            if any(pattern in model_lower for pattern in patterns):
                return provider
        
        return None
    
    @staticmethod
    def _calculate_severity(status: str, days_until_shutdown: Optional[int]) -> str:
        """
        Calculate risk severity based on status and shutdown date.
        Uses config-based thresholds.
        """
        if status == "shutdown":
            return "CRITICAL"
        
        if status == "deprecated":
            if days_until_shutdown is not None:
                if days_until_shutdown <= DEPRECATION_SEVERITY_THRESHOLDS["CRITICAL"]:
                    return "CRITICAL"
                elif days_until_shutdown <= DEPRECATION_SEVERITY_THRESHOLDS["HIGH"]:
                    return "HIGH"
                elif days_until_shutdown <= DEPRECATION_SEVERITY_THRESHOLDS["MEDIUM"]:
                    return "MEDIUM"
            return "HIGH"  # No date = HIGH risk
        
        if status == "legacy":
            return "LOW"
        
        return "INFO"
    
    @staticmethod
    def _calculate_days_until_shutdown(dep: Dict) -> Optional[int]:
        """Calculate days until shutdown from ISO date string."""
        shutdown_date_str = dep.get("shutdown_date")
        if not shutdown_date_str:
            return None
        
        try:
            shutdown_date = datetime.strptime(shutdown_date_str, "%Y-%m-%d")
            delta = shutdown_date - datetime.now()
            return delta.days
        except (ValueError, TypeError):
            return None
    
    def get_all_deprecated_models(self, provider: Optional[str] = None) -> List[Dict]:
        """
        Get all deprecated models, optionally filtered by provider.
        Uses pre-built index for faster filtering.
        """
        results = []
        
        # Filter by provider if specified
        target_providers = [provider.lower()] if provider else self.deprecation_data.keys()
        
        for model_name, indexed in self.model_index.items():
            if indexed["provider"] not in target_providers:
                continue
            
            dep = indexed["data"]
            status = dep.get("status", "").lower()
            
            if status in DEPRECATED_STATUSES:
                results.append({
                    "model_id": dep.get("model_or_system"),
                    "provider": indexed["provider"],
                    "status": status,
                    "shutdown_date": dep.get("shutdown_date"),
                    "recommended_replacement": dep.get("recommended_replacement")
                })
        
        return results


@lru_cache(maxsize=1)
def get_deprecation_checker() -> ModelDeprecationChecker:
    """Get or create singleton deprecation checker instance."""
    return ModelDeprecationChecker()


def check_model_deprecation(model_name: str, provider: Optional[str] = None) -> Optional[Dict]:
    """
    Check if a model is deprecated/retired.
    
    Args:
        model_name: Model identifier
        provider: Optional provider hint
    
    Returns:
        Deprecation info dict or None
    """
    checker = get_deprecation_checker()
    return checker.check_model(model_name, provider)


def check_models_deprecation(model_names: List[str]) -> Dict:
    """
    Check multiple models for deprecation.
    
    Args:
        model_names: List of model names to check
    
    Returns:
        Dict with results for each model
    """
    checker = get_deprecation_checker()
    results = []
    deprecated_count = 0
    
    for model_name in model_names:
        result = checker.check_model(model_name)
        
        results.append({
            "model_name": model_name,
            "deprecation_found": result is not None,
            "deprecation_info": result
        })
        
        if result:
            deprecated_count += 1
    
    return {
        "models_checked": len(model_names),
        "deprecated_count": deprecated_count,
        "active_count": len(model_names) - deprecated_count,
        "results": results
    }


__all__ = [
    "ModelDeprecationChecker",
    "get_deprecation_checker",
    "check_model_deprecation",
    "check_models_deprecation"
]
