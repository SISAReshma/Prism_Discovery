"""
Base cataloger interface for all language-specific catalogers.

All catalogers must inherit from BaseCataloger and implement:
- detect(root: str) -> bool
- catalog(repo_root: str, **kwargs) -> Dict

This ensures a consistent interface across all languages.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional


class BaseCataloger(ABC):
    """
    Abstract base class for all language catalogers.
    
    Each language cataloger (Python, JavaScript, Java, etc.) must inherit from this
    class and implement the required methods.
    
    Example:
        class PythonCataloger(BaseCataloger):
            @property
            def language(self):
                return "python"
            
            @property
            def ecosystem(self):
                return "pypi"
            
            def detect(self, root: str) -> bool:
                return Path(root).joinpath("requirements.txt").exists()
            
            def catalog(self, repo_root: str, **kwargs) -> Dict:
                # Implementation...
                return {"packages": [...], "manifests": [...]}
    """
    
    @property
    @abstractmethod
    def language(self) -> str:
        """
        Return the language name this cataloger handles.
        
        Returns:
            Language name (e.g., "python", "javascript")
        """
        pass
    
    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """
        Return the ecosystem name for this language.
        
        Returns:
            Ecosystem name (e.g., "pypi", "npm")
        """
        pass
    
    @abstractmethod
    def detect(self, root: str) -> bool:
        """
        Check if this cataloger should run on the given project.
        
        Args:
            root: Path to project root directory
            
        Returns:
            True if this cataloger applies to the project, False otherwise
            
        Example:
            def detect(self, root: str) -> bool:
                # Python project if it has requirements.txt or setup.py
                root_path = Path(root)
                return (root_path / "requirements.txt").exists() or \
                       (root_path / "setup.py").exists()
        """
        pass
    
    @abstractmethod
    def catalog(self, repo_root: str, **kwargs) -> Dict[str, Any]:
        """
        Scan the project and return package information.
        
        Args:
            repo_root: Path to repository root
            **kwargs: Additional arguments (token, nvd_api_key, etc.)
            
        Returns:
            Dictionary with:
                - "packages": List of package dictionaries
                - "manifests": List of manifest file paths found
                
        Example:
            {
                "packages": [
                    {
                        "name": "requests",
                        "version": "2.31.0",
                        "language": "python",
                        "type": "library",
                        "purl": "pkg:pypi/requests@2.31.0",
                        ...
                    }
                ],
                "manifests": ["/path/to/requirements.txt"]
            }
        """
        pass
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<{self.__class__.__name__} language={self.language} ecosystem={self.ecosystem}>"
