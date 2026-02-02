"""
Base interface for package enrichers.

Enrichers are responsible for adding metadata to packages discovered by catalogers.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseEnricher(ABC):
    """
    Abstract base class for all package enrichers.
    
    Enrichers take a package dictionary (from a cataloger) and add 
    additional metadata (license details, descriptions, external refs, etc.)
    """
    
    @property
    @abstractmethod
    def supported_ecosystems(self) -> list[str]:
        """
        Return list of ecosystems this enricher supports.
        E.g. ["pypi"], ["npm"]
        """
        pass

    @abstractmethod
    def enrich(self, pkg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a package with additional metadata.
        
        Args:
            pkg: The package dictionary to enrich
            
        Returns:
            The enriched package dictionary
        """
        pass
