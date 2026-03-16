"""
PHP/Composer Cataloger

Parses PHP Composer manifest files to extract package dependencies.
Supports:
  - composer.lock (preferred - exact versions)
  - composer.json (fallback - version constraints)

Lock-first approach: If composer.lock exists, use it for exact versions.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sbom.src.catalogers.base import BaseCataloger

logger = logging.getLogger(__name__)


class PHPCataloger(BaseCataloger):
    """Cataloger for PHP Composer packages."""

    LANGUAGE = "php"
    MANIFEST_FILES = ["composer.lock", "composer.json"]

    @property
    def language(self) -> str:
        """Return the language name this cataloger handles."""
        return "php"

    @property
    def ecosystem(self) -> str:
        """Return the ecosystem name for this language."""
        return "packagist"

    def detect(self, root: str) -> bool:
        """Check if this is a PHP/Composer project."""
        root_path = Path(root)
        return (root_path / "composer.json").exists() or \
               (root_path / "composer.lock").exists()

    def __init__(self):
        self.lock_packages: Dict[str, Dict[str, Any]] = {}
        self.direct_deps: Set[str] = set()

    def catalog(self, project_path: str, token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Catalog PHP dependencies from a project directory.

        Args:
            project_path: Path to the project root
            token: Optional API token (unused for PHP)
            nvd_api_key: Optional NVD API key (unused here, passed for interface compatibility)

        Returns:
            Dict with keys: packages, manifests, has_lock_file, language
        """
        project = Path(project_path)
        packages: List[Dict[str, Any]] = []
        manifests: List[str] = []
        has_lock_file = False

        # Reset state
        self.lock_packages = {}
        self.direct_deps = set()

        logger.info("Detected PHP project. Parsing manifests for dependencies...")

        # Step 1: Check for composer.lock (exact versions)
        lock_path = project / "composer.lock"
        if lock_path.exists():
            has_lock_file = True
            manifests.append(str(lock_path))
            print(f"   * Found LOCK file: {lock_path}")
            self._parse_composer_lock(lock_path)

        # Step 2: Parse composer.json for direct dependencies
        json_path = project / "composer.json"
        if json_path.exists():
            manifests.append(str(json_path))
            print(f"   * Found manifest: {json_path}")
            self._parse_composer_json(json_path)

        # Step 3: Build package list
        if has_lock_file:
            # Use lock file data (exact versions)
            packages = self._build_packages_from_lock()
            logger.info(f"Found {len(packages)} packages in composer.lock (exact versions)")
        else:
            # Fall back to composer.json (version constraints only)
            packages = self._build_packages_from_json(json_path if json_path.exists() else None)
            logger.info(f"Found {len(packages)} packages from composer.json")

        # Log statistics
        resolved = sum(1 for p in packages if p.get("version_resolved"))
        unresolved = len(packages) - resolved
        logger.info(f"Version resolution: {resolved} resolved, {unresolved} unresolved")

        # Build lock_data: {pkg_name: {version, hashes, dependencies}}
        lock_data_out: Dict[str, Dict[str, Any]] = {}
        if has_lock_file:
            for name_lower, pkg_data in self.lock_packages.items():
                version = pkg_data.get("version", "")
                if not version:
                    continue
                # Extract hashes from dist
                hashes = []
                dist = pkg_data.get("dist", {})
                shasum = dist.get("shasum", "") if isinstance(dist, dict) else ""
                if shasum:
                    hashes = [{"alg": "SHA-1", "content": shasum}]
                # Extract dependency names
                dep_names = []
                for dep_name in pkg_data.get("require", {}).keys():
                    if not dep_name.startswith("php") and not dep_name.startswith("ext-"):
                        dep_names.append(dep_name)
                lock_data_out[name_lower] = {
                    "version": version,
                    "hashes": hashes,
                    "dependencies": dep_names
                }
            if lock_data_out:
                print(f"[INFO] Collected {len(lock_data_out)} packages in lock_data for transitive resolution")

        return {
            "packages": packages,
            "manifests": manifests,
            "has_lock_file": has_lock_file,
            "language": self.LANGUAGE,
            "lock_data": lock_data_out,
        }

    def _parse_composer_lock(self, lock_path: Path) -> None:
        """Parse composer.lock file for exact package versions."""
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                lock_data = json.load(f)

            # Parse regular packages
            for pkg in lock_data.get("packages", []):
                name = pkg.get("name", "")
                if name:
                    version = pkg.get("version") or ""
                    # Remove 'v' prefix if present
                    if version and version.startswith("v"):
                        version = version[1:]
                    
                    self.lock_packages[name.lower()] = {
                        "name": name,
                        "version": version,
                        "source": pkg.get("source", {}),
                        "dist": pkg.get("dist", {}),
                        "require": pkg.get("require", {}),
                        "require-dev": pkg.get("require-dev", {}),
                        "license": pkg.get("license", []),
                        "description": pkg.get("description", ""),
                        "time": pkg.get("time", ""),
                        "type": pkg.get("type", "library"),
                        "authors": pkg.get("authors", []),
                        "homepage": pkg.get("homepage", ""),
                        "is_dev": False,
                    }
                    print(f"      [LOCK] {name} = {version}")

            # Parse dev packages
            for pkg in lock_data.get("packages-dev", []):
                name = pkg.get("name", "")
                if name:
                    version = pkg.get("version") or ""
                    if version and version.startswith("v"):
                        version = version[1:]
                    
                    self.lock_packages[name.lower()] = {
                        "name": name,
                        "version": version,
                        "source": pkg.get("source", {}),
                        "dist": pkg.get("dist", {}),
                        "require": pkg.get("require", {}),
                        "require-dev": pkg.get("require-dev", {}),
                        "license": pkg.get("license", []),
                        "description": pkg.get("description", ""),
                        "time": pkg.get("time", ""),
                        "type": pkg.get("type", "library"),
                        "authors": pkg.get("authors", []),
                        "homepage": pkg.get("homepage", ""),
                        "is_dev": True,
                    }
                    print(f"      [LOCK-DEV] {name} = {version}")

            count = len(lock_data.get("packages", [])) + len(lock_data.get("packages-dev", []))
            print(f"   Parsed {count} dependencies from composer.lock")

        except Exception as e:
            logger.warning(f"Error parsing composer.lock: {e}")

    def _parse_composer_json(self, json_path: Path) -> None:
        """Parse composer.json for direct dependencies."""
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Collect direct dependencies
            for name in data.get("require", {}).keys():
                if not name.startswith("php") and not name.startswith("ext-"):
                    self.direct_deps.add(name.lower())

            for name in data.get("require-dev", {}).keys():
                if not name.startswith("php") and not name.startswith("ext-"):
                    self.direct_deps.add(name.lower())

            print(f"   Parsed {len(self.direct_deps)} direct dependencies from composer.json")

        except Exception as e:
            logger.warning(f"Error parsing composer.json: {e}")

    def _build_packages_from_lock(self) -> List[Dict[str, Any]]:
        """Build package list from lock file data."""
        packages = []

        for name_lower, pkg_data in self.lock_packages.items():
            name = pkg_data["name"]
            version = pkg_data["version"]
            # If composer.json was absent, direct_deps is empty — treat all as direct
            is_direct = name_lower in self.direct_deps if self.direct_deps else True

            # Extract license
            licenses = pkg_data.get("license", [])
            license_str = licenses[0] if licenses else "NOASSERTION"

            # Extract authors
            authors = pkg_data.get("authors", [])
            supplier = ""
            if authors:
                author_names = [a.get("name", "") for a in authors if a.get("name")]
                supplier = ", ".join(author_names)

            # Build dependencies list
            deps = []
            for dep_name, dep_constraint in pkg_data.get("require", {}).items():
                if not dep_name.startswith("php") and not dep_name.startswith("ext-"):
                    deps.append({
                        "name": dep_name,
                        "version_constraint": dep_constraint,
                        "purl": f"pkg:composer/{dep_name}",
                    })

            # Get hash from dist
            dist = pkg_data.get("dist", {})
            shasum = dist.get("shasum", "")

            package = {
                "name": name,
                "version": version,
                "language": self.LANGUAGE,
                "purl": f"pkg:composer/{name}@{version}",
                "version_resolved": True,
                "version_source": "lock_file",
                "is_direct_dependency": is_direct,
                "is_dev_dependency": pkg_data.get("is_dev", False),
                "license": license_str,
                "description": pkg_data.get("description", ""),
                "homepage": pkg_data.get("homepage", ""),
                "supplier": supplier,
                "release_date": pkg_data.get("time", ""),
                "dependencies": deps,
                "package_type": pkg_data.get("type", "library"),
            }

            if shasum:
                package["hashes"] = [{"alg": "SHA-1", "content": shasum}]

            packages.append(package)

        return packages

    def _build_packages_from_json(self, json_path: Optional[Path]) -> List[Dict[str, Any]]:
        """Build package list from composer.json only (no lock file)."""
        packages = []

        if not json_path or not json_path.exists():
            return packages

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Process require
            for name, constraint in data.get("require", {}).items():
                if name.startswith("php") or name.startswith("ext-"):
                    continue

                version = self._parse_version_constraint(constraint)
                packages.append({
                    "name": name,
                    "version": version,
                    "version_constraint": constraint,
                    "language": self.LANGUAGE,
                    "purl": f"pkg:composer/{name}" + (f"@{version}" if version != "UNKNOWN" else ""),
                    "version_resolved": version != "UNKNOWN" and not any(c in version for c in "^~<>*|"),
                    "version_source": "manifest",
                    "is_direct_dependency": True,
                    "is_dev_dependency": False,
                })

            # Process require-dev
            for name, constraint in data.get("require-dev", {}).items():
                if name.startswith("php") or name.startswith("ext-"):
                    continue

                version = self._parse_version_constraint(constraint)
                packages.append({
                    "name": name,
                    "version": version,
                    "version_constraint": constraint,
                    "language": self.LANGUAGE,
                    "purl": f"pkg:composer/{name}" + (f"@{version}" if version != "UNKNOWN" else ""),
                    "version_resolved": version != "UNKNOWN" and not any(c in version for c in "^~<>*|"),
                    "version_source": "manifest",
                    "is_direct_dependency": True,
                    "is_dev_dependency": True,
                })

        except Exception as e:
            logger.warning(f"Error building packages from composer.json: {e}")

        return packages

    def _parse_version_constraint(self, constraint: str) -> str:
        """
        Parse version constraint and extract version if possible.
        
        Composer version constraints:
        - Exact: "1.2.3"
        - Range: ">=1.0 <2.0"
        - Caret: "^1.2.3" (>=1.2.3 <2.0.0)
        - Tilde: "~1.2.3" (>=1.2.3 <1.3.0)
        - Wildcard: "1.2.*"
        - Or: "1.0|2.0"
        """
        if not constraint:
            return "UNKNOWN"

        constraint = constraint.strip()

        # Exact version
        if re.match(r"^v?\d+\.\d+(\.\d+)?(-[\w.]+)?$", constraint):
            return constraint.lstrip("v")

        # Remove operators and return base version
        cleaned = re.sub(r"^[~^>=<!\s|]+", "", constraint)
        cleaned = re.sub(r"\s.*$", "", cleaned)  # Take first part if multiple
        cleaned = cleaned.replace("*", "0")
        cleaned = cleaned.lstrip("v")

        if re.match(r"^\d+(\.\d+)*(-[\w.]+)?$", cleaned):
            return cleaned

        return constraint  # Return original if can't parse

    def supports(self, project_path: str) -> bool:
        """Check if this cataloger supports the given project."""
        project = Path(project_path)
        for manifest in self.MANIFEST_FILES:
            if (project / manifest).exists():
                return True
        return False
