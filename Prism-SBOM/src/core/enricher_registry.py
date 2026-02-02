"""
Enricher registry for automatic discovery and loading of package enrichers.
"""
import importlib
import inspect
import pkgutil
import logging
from pathlib import Path
from typing import Dict, List, Type, Optional

from src.enrichers.base import BaseEnricher

# Map ecosystem name -> Enricher instance
# e.g. "pypi" -> PythonEnricher()
_ENRICHER_CACHE: Dict[str, BaseEnricher] = {}

def get_enricher(ecosystem: str) -> Optional[BaseEnricher]:
    """
    Get the appropriate enricher for a given ecosystem.
    
    Args:
        ecosystem: Ecosystem name (e.g., "pypi", "npm")
        
    Returns:
        Enricher instance if found, None otherwise.
    """
    if not _ENRICHER_CACHE:
        _discover_enrichers()
        
    return _ENRICHER_CACHE.get(ecosystem.lower())

def _discover_enrichers():
    """
    Auto-discover and instantiate all available enrichers.
    """
    global _ENRICHER_CACHE
    
    # Path to enrichers directory
    # Assumes this file is in src/core/, so enrichers is in ../enrichers/
    enrichers_path = Path(__file__).parent.parent / "enrichers"
    
    if not enrichers_path.exists():
        print(f"[WARNING] Enrichers directory not found: {enrichers_path}")
        return

    # Iterate over all .py files in the enrichers directory
    for module_info in pkgutil.iter_modules([str(enrichers_path)]):
        if module_info.name == "base":  # Skip base class definition
            continue
            
        try:
            # Import the module
            module_name = f"src.enrichers.{module_info.name}"
            module = importlib.import_module(module_name)
            
            # Find classes that inherit from BaseEnricher
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseEnricher) and obj is not BaseEnricher:
                    try:
                        # Instantiate the enricher
                        instance = obj()
                        
                        # Register for all supported ecosystems
                        for eco in instance.supported_ecosystems:
                            _ENRICHER_CACHE[eco.lower()] = instance
                            # print(f"[DEBUG] Registered enricher for {eco}: {name}")
                            
                    except Exception as e:
                        print(f"[ERROR] Failed to instantiate enricher {name}: {e}")
                        
        except Exception as e:
            print(f"[ERROR] Failed to load enricher module {module_info.name}: {e}")
