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
from typing import List, Dict, Optional, Any

from src.catalogers.base import BaseCataloger

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

        # Check if in conda environment
        if os.environ.get("CONDA_DEFAULT_ENV"):
            return True

        return False

    def catalog(self, repo_root: str, **kwargs) -> Dict[str, Any]:
        """Catalog conda packages."""
        workspace_path = Path(repo_root)
        packages = []
        manifests = []

        # Parse conda-meta
        conda_meta_dir = workspace_path / "conda-meta"
        if conda_meta_dir.exists():
            meta_packages = self._parse_conda_meta(conda_meta_dir)
            packages.extend(meta_packages)
            manifests.append(str(conda_meta_dir))

        # Parse environment.yml
        env_file = self._find_environment_file(workspace_path)
        if env_file:
            env_packages = self._parse_environment_yml(env_file)
            packages.extend(env_packages)
            manifests.append(str(env_file))

        # Set basic fields for each package (NO enrichment - that happens in /registry_enrich)
        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version", "UNKNOWN")
            channel = pkg.get("channel", "conda-forge")
            
            pkg["is_direct_dependency"] = True
            pkg.setdefault("scope", "required")
            pkg.setdefault("type", "library")
            pkg.setdefault("purl", f"pkg:conda/{channel}/{name}@{version}")
            
            # Placeholders (will be filled by /registry_enrich)
            pkg.setdefault("component_name", name)
            pkg.setdefault("component_version", version)
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        print(f"[INFO] Found {len(packages)} DIRECT dependencies from conda manifests")

        return {
            "packages": packages,
            "manifests": manifests
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
