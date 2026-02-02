"""
Cataloger registry for automatic discovery and loading of catalogers.

This module provides functionality to:
1. Scan the src/catalogers directory
2. Dynamically import cataloger modules
3. Register all classes inheriting from BaseCataloger
"""

import importlib
import inspect
import pkgutil
import logging
from pathlib import Path
from typing import List, Type

from src.catalogers.base import BaseCataloger

def discover_catalogers() -> List[BaseCataloger]:
    """
    Auto-discover and instantiate all available catalogers.
    
    Returns:
        List of instantiated cataloger objects (e.g., [PythonCataloger(), NpmCataloger()])
    """
    catalogers = []
    
    # Path to catalogers directory
    # Assumes this file is in src/core/, so catalogers is in ../catalogers/
    catalogers_path = Path(__file__).parent.parent / "catalogers"
    
    if not catalogers_path.exists():
        print(f"[WARNING] Catalogers directory not found: {catalogers_path}")
        return []

    # Iterate over all .py files in the catalogers directory
    for module_info in pkgutil.iter_modules([str(catalogers_path)]):
        if module_info.name == "base":  # Skip base class definition
            continue
            
        try:
            # Import the module
            module_name = f"src.catalogers.{module_info.name}"
            module = importlib.import_module(module_name)
            
            # Find classes that inherit from BaseCataloger
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseCataloger) and obj is not BaseCataloger:
                    try:
                        # Instantiate the cataloger
                        instance = obj()
                        catalogers.append(instance)
                        # print(f"[DEBUG] Registered cataloger: {name} (language={instance.language})")
                    except Exception as e:
                        print(f"[ERROR] Failed to instantiate cataloger {name}: {e}")
                        
        except Exception as e:
            print(f"[ERROR] Failed to load cataloger module {module_info.name}: {e}")
            
    return catalogers
