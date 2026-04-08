"""
Language registry for catalogers and manifest detection.

Single source of truth for:
- Supported languages
- Manifest file names
- Cataloger classes
- PURL / deps.dev ecosystem mapping
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Iterable
import importlib
import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LanguageDefinition:
    language: str
    ecosystem: str  # OSV ecosystem name (case-sensitive where applicable)
    purl_type: str  # PURL / deps.dev ecosystem name (lowercase)
    manifest_files: List[str]
    cataloger: Optional[str] = None  # import path "module.Class"


LANGUAGE_REGISTRY: List[LanguageDefinition] = [
    LanguageDefinition(
        language="python",
        ecosystem="PyPI",
        purl_type="pypi",
        manifest_files=["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock", "poetry.lock"],
        cataloger="sbom.src.catalogers.python_cataloger.PythonCataloger",
    ),
    LanguageDefinition(
        language="javascript",
        ecosystem="npm",
        purl_type="npm",
        manifest_files=["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        cataloger="sbom.src.catalogers.npm_cataloger.NpmCataloger",
    ),
    LanguageDefinition(
        language="conda",
        ecosystem="conda",
        purl_type="conda",
        manifest_files=["environment.yml", "environment.yaml", "conda.yml", "conda.yaml"],
        cataloger="sbom.src.catalogers.conda_cataloger.CondaCataloger",
    ),
    LanguageDefinition(
        language="go",
        ecosystem="Go",
        purl_type="golang",
        manifest_files=["go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock", "vendor/modules.txt"],
        cataloger="sbom.src.catalogers.go_cataloger.GoCataloger",
    ),
    LanguageDefinition(
        language="java",
        ecosystem="Maven",
        purl_type="maven",
        manifest_files=["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "buildscript-gradle.lockfile"],
        cataloger="sbom.src.catalogers.java_cataloger.JavaCataloger",
    ),
    LanguageDefinition(
        language="rust",
        ecosystem="crates.io",
        purl_type="cargo",
        manifest_files=["Cargo.toml", "Cargo.lock"],
        cataloger="sbom.src.catalogers.rust_cataloger.RustCataloger",
    ),
    LanguageDefinition(
        language="dotnet",
        ecosystem="NuGet",
        purl_type="nuget",
        manifest_files=["packages.lock.json", "*.csproj", "*.fsproj", "*.vbproj", "packages.config", "Directory.Packages.props"],
        cataloger="sbom.src.catalogers.nuget_cataloger.NuGetCataloger",
    ),
    LanguageDefinition(
        language="ruby",
        ecosystem="RubyGems",
        purl_type="gem",
        manifest_files=["Gemfile", "Gemfile.lock", "*.gemspec"],
        cataloger="sbom.src.catalogers.ruby_cataloger.RubyCataloger",
    ),
    LanguageDefinition(
        language="php",
        ecosystem="Packagist",
        purl_type="composer",
        manifest_files=["composer.json", "composer.lock"],
        cataloger="sbom.src.catalogers.php_cataloger.PHPCataloger",
    ),
    LanguageDefinition(
        language="swift",
        ecosystem="CocoaPods",
        purl_type="cocoapods",
        manifest_files=["Podfile", "Podfile.lock", "Package.swift", "Package.resolved"],
        cataloger="sbom.src.catalogers.swift_cataloger.SwiftCataloger",
    ),
    LanguageDefinition(
        language="cpp",
        ecosystem="Conan",
        purl_type="conan",
        manifest_files=["conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json", "vcpkg-configuration.json", "CMakeLists.txt"],
        cataloger="sbom.src.catalogers.cpp_cataloger.CppCataloger",
    ),
]


def get_language_definitions() -> List[LanguageDefinition]:
    return list(LANGUAGE_REGISTRY)


def get_manifest_files_for_language(language: str) -> List[str]:
    """Get manifest files for a specific language."""
    lang_lower = language.lower()
    for entry in LANGUAGE_REGISTRY:
        if entry.language.lower() == lang_lower:
            return list(entry.manifest_files)
    return []


def get_supported_manifest_files() -> Dict[str, List[str]]:
    return {lang.language: list(lang.manifest_files) for lang in LANGUAGE_REGISTRY}


def get_all_manifest_files() -> List[str]:
    files: List[str] = []
    for lang in LANGUAGE_REGISTRY:
        files.extend(lang.manifest_files)
    return files


def get_language_for_manifest(filename: str) -> Optional[str]:
    import fnmatch
    name = filename.lower()
    for lang in LANGUAGE_REGISTRY:
        for f in lang.manifest_files:
            # Support both exact match and glob patterns (e.g., *.csproj)
            if name == f.lower() or fnmatch.fnmatch(name, f.lower()):
                return lang.language
    return None


def get_purl_type(language: str) -> str:
    lang = (language or "").lower()
    for entry in LANGUAGE_REGISTRY:
        if entry.language.lower() == lang:
            return entry.purl_type
    return lang or "unknown"


# Alias map for common language name variations
ALIAS_MAP = {
    "py": "python",
    "js": "javascript",
    "node": "javascript",
    "npm": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "tsx": "javascript",
    "jsx": "javascript",
    "golang": "go",
    "mod": "go",
    "maven": "java",
    "gradle": "java",
    "mvn": "java",
    "cargo": "rust",
    "crate": "rust",
    "crates": "rust",
    "csharp": "dotnet",
    "c#": "dotnet",
    "fsharp": "dotnet",
    "f#": "dotnet",
    "vb": "dotnet",
    "vbnet": "dotnet",
    "nuget": "dotnet",
    ".net": "dotnet",
    "rb": "ruby",
    "gem": "ruby",
    "gems": "ruby",
    "bundler": "ruby",
    "rubygems": "ruby",
    "composer": "php",
    "packagist": "php",
    "c": "cpp",
    "c++": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "conan": "cpp",
    "vcpkg": "cpp",
    "cmake": "cpp",
}


def get_ecosystem(language: str) -> str:
    """
    Get OSV ecosystem name for a given language.
    
    Args:
        language: Language name (e.g., "python", "py", "javascript", "js")
                  or ecosystem name (e.g., "PyPI", "npm")
        
    Returns:
        Ecosystem name in OSV format (e.g., "PyPI", "npm")
        Returns "unknown" if not recognized
        
    Examples:
        >>> get_ecosystem("python")
        'PyPI'
        >>> get_ecosystem("pypi")
        'PyPI'
        >>> get_ecosystem("js")
        'npm'
    """
    if not language:
        return "unknown"
    
    lower = language.lower()
    
    # Check if it's already a valid ecosystem name (normalize to OSV format)
    ecosystem_normalize = {
        # Python
        "pypi": "PyPI",
        "python": "PyPI",
        # JavaScript
        "npm": "npm",
        "javascript": "npm",
        "nodejs": "npm",
        "node": "npm",
        "typescript": "npm",
        "ts": "npm",
        # Conda
        "conda": "conda",
        # Go
        "go": "Go",
        "golang": "Go",
        # Java
        "maven": "Maven",
        "java": "Maven",
        "gradle": "Maven",
        # Rust
        "cargo": "crates.io",
        "crates.io": "crates.io",
        "rust": "crates.io",
        # .NET
        "nuget": "NuGet",
        "dotnet": "NuGet",
        ".net": "NuGet",
        "csharp": "NuGet",
        # Ruby
        "rubygems": "RubyGems",
        "gem": "RubyGems",
        "ruby": "RubyGems",
        # PHP
        "packagist": "Packagist",
        "composer": "Packagist",
        "php": "Packagist",
        # Swift
        "cocoapods": "CocoaPods",
        "swift": "CocoaPods",
        "pods": "CocoaPods",
        # C/C++
        "conan": "Conan",
        "vcpkg": "Conan",
        "cpp": "Conan",
        "c": "Conan",
        "c++": "Conan",
        "cmake": "Conan",
    }
    if lower in ecosystem_normalize:
        return ecosystem_normalize[lower]
    
    # Resolve aliases first
    canonical = ALIAS_MAP.get(lower, lower)
    
    # Find in registry
    for entry in LANGUAGE_REGISTRY:
        if entry.language.lower() == canonical:
            return entry.ecosystem
    
    return "unknown"


def get_language_to_ecosystem_map() -> Dict[str, str]:
    """
    Get a dictionary mapping language names to ecosystem names.
    
    Returns:
        Dict like {"python": "PyPI", "javascript": "npm", ...}
    """
    mapping = {entry.language: entry.ecosystem for entry in LANGUAGE_REGISTRY}
    # Add aliases
    for alias, canonical in ALIAS_MAP.items():
        if canonical in mapping:
            mapping[alias] = mapping[canonical]
    return mapping


def get_cataloger_instances() -> List[object]:
    catalogers: List[object] = []
    for entry in LANGUAGE_REGISTRY:
        if not entry.cataloger:
            continue
        try:
            module_path, class_name = entry.cataloger.rsplit(".", 1)
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            catalogers.append(cls())
        except Exception as exc:
            logger.warning("Failed to load cataloger %s: %s", entry.cataloger, exc)
    return catalogers


def iter_manifest_patterns() -> Iterable[str]:
    for entry in LANGUAGE_REGISTRY:
        for name in entry.manifest_files:
            yield name
