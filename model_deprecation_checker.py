"""
Model Deprecation Checker
Validates models against deprecation databases and identifies risks.
Builds recursive replacement chains to find active alternatives.

Adapted from Prism-AIBOM for AIBOM_endpoints API.
"""
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Deprecation cache directory - using Prism-AIBOM's .deprecation_cache
DEPRECATION_CACHE_DIR = Path(__file__).parent.parent / "Prism-AIBOM" / ".deprecation_cache"


class ModelDeprecationChecker:
    """Check models against provider deprecation databases."""
    
    def __init__(self):
        """Initialize deprecation checker and load all provider data."""
        self.deprecation_data = {}
        self.replacement_chains = {}
        self._load_all_providers()
        self._build_replacement_chains()
    
    def _load_all_providers(self):
        """Load deprecation data from all provider JSON files."""
        if not DEPRECATION_CACHE_DIR.exists():
            logger.warning(f"No deprecation cache directory found at {DEPRECATION_CACHE_DIR}")
            return
        
        for json_file in DEPRECATION_CACHE_DIR.glob("*_deprecations.json"):
            provider_name = json_file.stem.replace("_deprecations", "")
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.deprecation_data[provider_name.lower()] = data
                    logger.info(f"Loaded {provider_name} deprecation data")
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")
    
    def _build_replacement_chains(self):
        """
        Build recursive replacement chains for all providers.
        Maps deprecated models to their final active replacement.
        
        Example: claude-3-opus-20240229 → claude-opus-4 → claude-opus-4-5 (active)
        """
        for provider, data in self.deprecation_data.items():
            logger.debug(f"Building replacement chains for {provider}...")
            self.replacement_chains[provider] = {}
            
            # Get deprecations list
            deprecations = data.get("deprecations", [])
            
            # Build model lookup
            model_lookup = {}
            for dep in deprecations:
                model_id = dep.get("model_or_system", "")
                model_lookup[model_id] = dep
            
            # For each deprecated model, trace replacement chain
            for dep in deprecations:
                model_id = dep.get("model_or_system", "")
                status = dep.get("status", "").lower()
                
                if status in ["deprecated", "shutdown", "legacy"]:
                    chain = self._trace_replacement_chain(model_id, model_lookup)
                    self.replacement_chains[provider][model_id] = chain
    
    def _trace_replacement_chain(self, model_id: str, model_lookup: Dict) -> Dict:
        """
        Recursively trace replacement chain to find final active model.
        
        Returns:
            Dict with chain info
        """
        chain = [model_id]
        visited = {model_id}
        current = model_id
        max_depth = 10  # Prevent infinite loops
        
        for _ in range(max_depth):
            model_data = model_lookup.get(current)
            if not model_data:
                break
            
            replacement = model_data.get("recommended_replacement")
            if not replacement:
                break
            
            # Handle multiple replacements like "gpt-5 or gpt-4.1"
            if " or " in replacement:
                replacement = replacement.split(" or ")[0].strip()
            
            # Check if replacement is also deprecated
            replacement_data = model_lookup.get(replacement)
            if not replacement_data:
                # Replacement not in deprecation list = likely active
                chain.append(replacement)
                return {
                    "chain": chain,
                    "final_replacement": replacement,
                    "depth": len(chain) - 1
                }
            
            # Continue tracing if replacement is also deprecated
            if replacement in visited:
                # Circular reference detected
                logger.warning(f"Circular replacement detected for {model_id}")
                break
            
            chain.append(replacement)
            visited.add(replacement)
            current = replacement
        
        # Return chain even if no final active replacement
        final = chain[-1] if len(chain) > 1 else None
        return {
            "chain": chain,
            "final_replacement": final,
            "depth": len(chain) - 1
        }
    
    def check_model(self, model_name: str, provider: str = None) -> Optional[Dict]:
        """
        Check if a model is deprecated, retired, or retiring soon.
        
        Args:
            model_name: Model identifier to check
            provider: Optional provider hint (anthropic, openai, etc.)
        
        Returns:
            Deprecation info dict or None if model is active/not found
        """
        # Normalize model name for matching
        model_name_normalized = self._normalize_model_name(model_name)
        
        # Try to detect provider if not specified
        if not provider:
            provider = self._detect_provider(model_name)
        
        if not provider or provider not in self.deprecation_data:
            # Try all providers
            for prov in self.deprecation_data.keys():
                result = self._check_in_provider(model_name_normalized, prov)
                if result:
                    return result
            return None
        
        return self._check_in_provider(model_name_normalized, provider)
    
    def _normalize_model_name(self, model_name: str) -> str:
        """Normalize model name for matching."""
        # Convert underscores to hyphens, lowercase
        return model_name.replace("_", "-").lower()
    
    def _check_in_provider(self, model_name: str, provider: str) -> Optional[Dict]:
        """Check model in a specific provider's deprecation data."""
        data = self.deprecation_data.get(provider)
        if not data:
            return None
        
        deprecations = data.get("deprecations", [])
        
        for dep in deprecations:
            dep_model = dep.get("model_or_system", "").lower()
            
            # EXACT match only - no partial matching to avoid false positives
            # e.g., "gpt-4" should NOT match "chatgpt-4o-latest" or "gpt-4-turbo-preview"
            if dep_model == model_name:
                status = dep.get("status", "").lower()
                
                # Get replacement chain
                chain_info = self.replacement_chains.get(provider, {}).get(dep.get("model_or_system", ""), {})
                
                # Calculate severity
                severity = self._calculate_severity(dep, status)
                
                # Calculate days until shutdown
                days_until_shutdown = self._calculate_days_until_shutdown(dep)
                
                return {
                    "model_id": dep.get("model_or_system"),
                    "provider": provider,
                    "status": status,
                    "is_deprecated": status in ["deprecated", "shutdown", "legacy"],
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
        
        return None
    
    def _detect_provider(self, model_name: str) -> Optional[str]:
        """Detect provider from model name patterns."""
        model_lower = model_name.lower()
        
        if "claude" in model_lower:
            return "anthropic"
        elif any(x in model_lower for x in ["gpt", "davinci", "babbage", "o1", "o3", "o4", "dall-e", "whisper", "tts"]):
            return "openai"
        elif any(x in model_lower for x in ["gemini", "gemma", "palm", "imagen", "veo"]):
            return "google"
        
        return None
    
    def _calculate_severity(self, dep: Dict, status: str) -> str:
        """Calculate risk severity based on status and shutdown date."""
        if status == "shutdown":
            return "CRITICAL"  # Already past shutdown
        
        if status == "deprecated":
            days = self._calculate_days_until_shutdown(dep)
            if days is not None:
                if days <= 0:
                    return "CRITICAL"
                elif days <= 30:
                    return "HIGH"
                elif days <= 90:
                    return "MEDIUM"
            return "HIGH"  # Deprecated without date = HIGH
        
        if status == "legacy":
            return "LOW"
        
        return "INFO"
    
    def _calculate_days_until_shutdown(self, dep: Dict) -> Optional[int]:
        """Calculate days until shutdown."""
        shutdown_date_str = dep.get("shutdown_date")
        if not shutdown_date_str:
            return None
        
        try:
            shutdown_date = datetime.strptime(shutdown_date_str, "%Y-%m-%d")
            today = datetime.now()
            delta = shutdown_date - today
            return delta.days
        except (ValueError, TypeError):
            return None
    
    def get_all_deprecated_models(self, provider: str = None) -> List[Dict]:
        """Get all deprecated models, optionally filtered by provider."""
        results = []
        
        providers = [provider] if provider else self.deprecation_data.keys()
        
        for prov in providers:
            if prov not in self.deprecation_data:
                continue
            
            data = self.deprecation_data[prov]
            for dep in data.get("deprecations", []):
                status = dep.get("status", "").lower()
                if status in ["deprecated", "shutdown", "legacy"]:
                    results.append({
                        "model_id": dep.get("model_or_system"),
                        "provider": prov,
                        "status": status,
                        "shutdown_date": dep.get("shutdown_date"),
                        "recommended_replacement": dep.get("recommended_replacement")
                    })
        
        return results


@lru_cache(maxsize=1)
def get_deprecation_checker() -> ModelDeprecationChecker:
    """Get or create singleton deprecation checker instance."""
    return ModelDeprecationChecker()


def check_model_deprecation(model_name: str, provider: str = None) -> Optional[Dict]:
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
        
        if result:
            deprecated_count += 1
            results.append({
                "model_name": model_name,
                "deprecation_found": True,
                "deprecation_info": result
            })
        else:
            results.append({
                "model_name": model_name,
                "deprecation_found": False,
                "deprecation_info": None
            })
    
    return {
        "models_checked": len(model_names),
        "deprecated_count": deprecated_count,
        "active_count": len(model_names) - deprecated_count,
        "results": results
    }


# Expose for imports
__all__ = [
    "ModelDeprecationChecker",
    "get_deprecation_checker",
    "check_model_deprecation",
    "check_models_deprecation"
]
