"""
Conda Package Cataloger

Catalogs conda packages from:
1. conda-meta/*.json (locally installed packages)
2. environment.yml (environment specifications)

NOTE: Enrichment (license, description, supplier) happens in /registry_enrich endpoint.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, Set

from sbom.src.catalogers.base import BaseCataloger

logger = logging.getLogger(__name__)


class CondaCataloger(BaseCataloger):
    """Cataloger for Conda/Anaconda packages."""

    def __init__(self):
        self._language = "conda"
        self._ecosystem = "conda"
    
    @property
    def language(self) -> str:
        """Return language name."""
        return self._language
    
    @property
    def ecosystem(self) -> str:
        """Return ecosystem name."""
        return self._ecosystem

    def detect(self, root: str) -> bool:
        """Detect if workspace contains conda files."""
        workspace_path = Path(root)

        # Check for conda-meta directory
        if (workspace_path / "conda-meta").exists():
            return True

        # Check for environment files
        conda_files = ["environment.yml", "environment.yaml"]
        for conda_file in conda_files:
            if (workspace_path / conda_file).exists():
                return True

        return False

    def catalog(self, repo_root: str, **kwargs) -> Dict[str, Any]:
        """Catalog conda packages."""
        workspace_path = Path(repo_root)
        packages: List[Dict[str, Any]] = []
        manifests = []

        # Step 1: Parse environment.yml first to know what is explicitly declared (= direct deps)
        env_names: Set[str] = set()
        env_packages: List[Dict[str, Any]] = []
        conda_meta_dir = workspace_path / "conda-meta"
        env_file = self._find_environment_file(workspace_path)
        if env_file:
            env_packages = self._parse_environment_yml(env_file)
            env_names = {p.get("name", "").lower() for p in env_packages if p.get("name")}
            manifests.append(str(env_file))

        # Step 2: Parse conda-meta (full installed environment — acts as lock file)
        if conda_meta_dir.exists():
            meta_packages = self._parse_conda_meta(conda_meta_dir)
            packages.extend(meta_packages)
            manifests.append(str(conda_meta_dir))

        # Step 3: Add env.yml packages not already covered by conda-meta (avoids duplicates)
        meta_names = {p.get("name", "").lower() for p in packages if p.get("name")}
        for ep in env_packages:
            if ep.get("name", "").lower() not in meta_names:
                packages.append(ep)

        # Step 4: Set fields; direct dep = explicitly listed in environment.yml
        for pkg in packages:
            name = pkg.get("name") or ""
            version = pkg.get("version", "UNKNOWN")

            # Direct dep: in environment.yml; or all direct when no env.yml exists
            pkg["is_direct_dependency"] = (name.lower() in env_names) if env_names else True
            pkg.setdefault("scope", "required")
            pkg.setdefault("type", "library")
            # Standard PURL for conda: pkg:conda/{name}@{version}
            pkg.setdefault(
                "purl",
                f"pkg:conda/{name}@{version}" if version != "UNKNOWN" else f"pkg:conda/{name}"
            )
            # Placeholders (will be filled by /registry_enrich)
            pkg.setdefault("component_name", name)
            pkg.setdefault("component_version", version)
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        direct_count = sum(1 for p in packages if p.get("is_direct_dependency"))
        print(f"[INFO] Found {len(packages)} conda dependencies ({direct_count} direct, {len(packages) - direct_count} transitive)")

        # conda-meta acts as lock file
        has_lock_file = conda_meta_dir.exists()
        lock_data: Dict[str, Dict[str, Any]] = {}
        if has_lock_file:
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version and version != "UNKNOWN":
                    key = name.lower()
                    if key not in lock_data:
                        lock_data[key] = {
                            "version": version,
                            "hashes": pkg.get("hashes", []),
                            "dependencies": pkg.get("dependencies", [])
                        }
            if lock_data:
                print(f"[INFO] Collected {len(lock_data)} packages in lock_data for transitive resolution")

        return {
            "packages": packages,
            "manifests": manifests,
            "has_lock_file": has_lock_file,
            "lock_data": lock_data,
        }

    def _parse_conda_meta(self, conda_meta_dir: Path) -> List[Dict[str, Any]]:
        """Parse conda-meta JSON files."""
        packages = []

        for json_file in conda_meta_dir.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                pkg = {
                    "name": data.get("name"),
                    "version": data.get("version"),
                    "language": "conda",
                    "ecosystem": "conda",
                    "channel": data.get("channel", "defaults"),
                    "license": data.get("license")
                }
                packages.append(pkg)
            except Exception as e:
                logger.warning(f"Failed to parse {json_file}: {e}")

        return packages

    def _find_environment_file(self, workspace_path: Path) -> Optional[Path]:
        """Find environment.yml file."""
        for filename in ["environment.yml", "environment.yaml"]:
            env_file = workspace_path / filename
            if env_file.exists():
                return env_file
        return None

    def _parse_environment_yml(self, env_file: Path) -> List[Dict[str, Any]]:
        """Parse environment.yml file."""
        packages = []

        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                env_data = yaml.safe_load(f)

            dependencies = env_data.get('dependencies', [])

            for dep in dependencies:
                if isinstance(dep, dict):
                    # pip sub-section: {"pip": ["tensorflow==2.0", "torch>=1.0"]}
                    for pip_dep in dep.get("pip", []):
                        if isinstance(pip_dep, str):
                            pkg_info = self._parse_pip_spec(pip_dep)
                            if pkg_info:
                                packages.append(pkg_info)
                    continue

                if isinstance(dep, str):
                    pkg_info = self._parse_conda_spec(dep)
                    if pkg_info:
                        packages.append(pkg_info)

        except Exception as e:
            logger.warning(f"Failed to parse {env_file}: {e}")

        return packages

    def _parse_conda_spec(self, spec: str) -> Optional[Dict[str, Any]]:
        """Parse conda package spec."""
        if spec.strip().startswith('#'):
            return None

        channel = "defaults"
        if '::' in spec:
            channel, spec = spec.split('::', 1)

        name = spec
        version = "UNKNOWN"

        for op in ['==', '>=', '<=', '>', '<', '=']:
            if op in spec:
                name, version = spec.split(op, 1)
                name = name.strip()
                version = version.strip()
                break

        if not name:
            return None

        return {
            "name": name,
            "version": version,
            "language": "conda",
            "ecosystem": "conda",
            "channel": channel
        }

    def _parse_pip_spec(self, spec: str) -> Optional[Dict[str, Any]]:
        """Parse a pip package spec string from the pip: sub-section of environment.yml."""
        spec = spec.strip()
        if not spec or spec.startswith('#') or spec.startswith('-'):
            return None
        name = spec
        version = "UNKNOWN"
        for op in ["==", ">=", "<=", "!=", "~=", ">", "<"]:
            if op in spec:
                parts = spec.split(op, 1)
                name = parts[0].strip()
                version = parts[1].strip()
                break
        if not name:
            return None
        return {
            "name": name,
            "version": version,
            "language": "conda",
            "ecosystem": "pypi",  # pip packages are from PyPI
            "channel": "pip",
        }
