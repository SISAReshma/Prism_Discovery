"""
Swift/CocoaPods Cataloger

Parses Swift/iOS project manifest files to extract package dependencies.
Supports:
  - Podfile.lock (preferred - exact versions)
  - Podfile (fallback - version constraints)
  - Package.swift (Swift Package Manager)
  - Package.resolved (SPM lock file)

Lock-first approach: If lock files exist, use them for exact versions.
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


class SwiftCataloger(BaseCataloger):
    """Cataloger for Swift/CocoaPods/SPM packages."""

    LANGUAGE = "swift"
    MANIFEST_FILES = ["Podfile.lock", "Podfile", "Package.swift", "Package.resolved"]

    @property
    def language(self) -> str:
        """Return the language name this cataloger handles."""
        return "swift"

    @property
    def ecosystem(self) -> str:
        """Return the ecosystem name for this language."""
        return "cocoapods"

    def detect(self, root: str) -> bool:
        """Check if this is a Swift/CocoaPods/SPM project."""
        root_path = Path(root)
        return (root_path / "Podfile").exists() or \
               (root_path / "Podfile.lock").exists() or \
               (root_path / "Package.swift").exists() or \
               (root_path / "Package.resolved").exists()

    def __init__(self):
        self.lock_packages: Dict[str, Dict[str, Any]] = {}
        self.direct_deps: Set[str] = set()

    def catalog(self, project_path: str, **kwargs) -> Dict[str, Any]:
        """
        Catalog Swift dependencies from a project directory.

        Args:
            project_path: Path to the project root
            **kwargs: Additional arguments (nvd_api_key, etc.)

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

        logger.info("Detected Swift project. Parsing manifests for dependencies...")

        # Step 1: Check for Podfile.lock (CocoaPods exact versions)
        podfile_lock = project / "Podfile.lock"
        if podfile_lock.exists():
            has_lock_file = True
            manifests.append(str(podfile_lock))
            print(f"   * Found LOCK file: {podfile_lock}")
            self._parse_podfile_lock(podfile_lock)

        # Step 2: Check for Package.resolved (SPM lock file)
        package_resolved = project / "Package.resolved"
        if package_resolved.exists():
            has_lock_file = True
            manifests.append(str(package_resolved))
            print(f"   * Found LOCK file: {package_resolved}")
            self._parse_package_resolved(package_resolved)

        # Step 3: Parse Podfile for direct dependencies
        podfile = project / "Podfile"
        if podfile.exists():
            manifests.append(str(podfile))
            print(f"   * Found manifest: {podfile}")
            self._parse_podfile(podfile)

        # Step 4: Parse Package.swift for SPM dependencies
        package_swift = project / "Package.swift"
        if package_swift.exists():
            manifests.append(str(package_swift))
            print(f"   * Found manifest: {package_swift}")
            self._parse_package_swift(package_swift)

        # Step 5: Build package list from lock files
        for name, pkg_data in self.lock_packages.items():
            version = pkg_data.get("version", "UNKNOWN")
            source = pkg_data.get("source", "cocoapods")
            
            pkg = {
                "name": name,
                "version": version,
                "language": "swift",
                "purl": f"pkg:cocoapods/{name}@{version}" if source == "cocoapods" else f"pkg:swift/{name}@{version}",
                "version_resolved": True,
                "version_source": "lock_file",
                "is_direct_dependency": name in self.direct_deps,
                "is_dev_dependency": pkg_data.get("is_dev", False),
                "license": pkg_data.get("license"),
                "description": pkg_data.get("description"),
                "homepage": pkg_data.get("homepage"),
                "supplier": pkg_data.get("supplier"),
                "release_date": pkg_data.get("release_date"),
                "dependencies": pkg_data.get("dependencies", []),
                "package_type": "library",
                "source_type": source,  # cocoapods or swift-pm
            }
            packages.append(pkg)
            
            dep_type = "direct" if pkg["is_direct_dependency"] else "transitive"
            print(f"      [{source.upper()}] {name} = {version} ({dep_type})")

        print(f"   Parsed {len(packages)} dependencies")

        # Build lock_data: {pkg_name: {version, hashes, dependencies}}
        lock_data_out: Dict[str, Dict[str, Any]] = {}
        if has_lock_file:
            for name, pkg_data in self.lock_packages.items():
                version = pkg_data.get("version", "")
                if not version or version == "UNKNOWN":
                    continue
                key = name.lower()
                if key not in lock_data_out:
                    lock_data_out[key] = {
                        "version": version,
                        "hashes": pkg_data.get("hashes", []),
                        "dependencies": pkg_data.get("dependencies", [])
                    }
            if lock_data_out:
                print(f"[INFO] Collected {len(lock_data_out)} packages in lock_data for transitive resolution")

        return {
            "packages": packages,
            "manifests": manifests,
            "has_lock_file": has_lock_file,
            "language": "swift",
            "lock_data": lock_data_out,
        }

    def _parse_podfile_lock(self, lock_path: Path) -> None:
        """
        Parse Podfile.lock for exact versions.
        
        Format:
        PODS:
          - Alamofire (5.9.1)
          - Moya (15.0.0):
            - Alamofire (~> 5.0)
        
        DEPENDENCIES:
          - Alamofire (~> 5.0)
          - Moya (~> 15.0)
        """
        try:
            content = lock_path.read_text(encoding="utf-8")
            
            # Parse PODS section
            pods_match = re.search(r'PODS:\s*\n(.*?)(?:\n\n|\nDEPENDENCIES:|\nSPEC REPOS:|\Z)', 
                                   content, re.DOTALL)
            if pods_match:
                pods_section = pods_match.group(1)
                self._parse_pods_section(pods_section)
            
            # Parse DEPENDENCIES section for direct deps
            deps_match = re.search(r'DEPENDENCIES:\s*\n(.*?)(?:\n\n|\nSPEC REPOS:|\nSPEC CHECKSUMS:|\Z)', 
                                   content, re.DOTALL)
            if deps_match:
                deps_section = deps_match.group(1)
                self._parse_dependencies_section(deps_section)

            print(f"   Parsed {len(self.lock_packages)} dependencies from Podfile.lock")
            
        except Exception as e:
            logger.warning(f"Error parsing Podfile.lock: {e}")

    def _parse_pods_section(self, pods_section: str) -> None:
        """Parse the PODS section of Podfile.lock, including sub-dependencies."""
        lines = pods_section.splitlines()
        # Top-level pod pattern: "  - PodName (1.2.3)" or "  - PodName (1.2.3):"
        pod_pattern = re.compile(r'^\s{2}-\s+([^\s(/]+)\s+\(([^)]+)\)')
        # Sub-dependency pattern: "    - DepName (constraint)" (4-space indent)
        sub_dep_pattern = re.compile(r'^\s{4}-\s+([^\s(/]+)')
        
        current_pod = None
        current_deps: List[Dict[str, str]] = []
        
        for line in lines:
            pod_match = pod_pattern.match(line)
            if pod_match:
                # Save previous pod's dependencies
                if current_pod and current_pod in self.lock_packages:
                    self.lock_packages[current_pod]["dependencies"] = current_deps
                
                name = pod_match.group(1)
                version = pod_match.group(2)
                current_pod = name
                current_deps = []
                
                # Skip subspecs (Name/Subspec)
                if "/" in name:
                    current_pod = None
                    continue
                
                if name not in self.lock_packages:
                    self.lock_packages[name] = {
                        "version": version,
                        "source": "cocoapods",
                        "dependencies": [],
                    }
            elif current_pod:
                sub_match = sub_dep_pattern.match(line)
                if sub_match:
                    dep_name = sub_match.group(1)
                    # Skip subspecs in dependencies too
                    if "/" not in dep_name:
                        # Extract version constraint if present: "  - DepName (~> 5.0)"
                        constraint_match = re.search(r'\(([^)]+)\)', line)
                        dep_constraint = constraint_match.group(1) if constraint_match else ""
                        current_deps.append({
                            "name": dep_name,
                            "version_constraint": dep_constraint,
                            "purl": f"pkg:cocoapods/{dep_name}",
                        })
        
        # Don't forget last pod
        if current_pod and current_pod in self.lock_packages:
            self.lock_packages[current_pod]["dependencies"] = current_deps

    def _parse_dependencies_section(self, deps_section: str) -> None:
        """Parse the DEPENDENCIES section to identify direct dependencies."""
        # Match dependency entries: "  - PodName (~> 1.0)" or "  - PodName"
        dep_pattern = re.compile(r'^\s+-\s+([^\s(]+)', re.MULTILINE)
        
        for match in dep_pattern.finditer(deps_section):
            name = match.group(1)
            # Remove quotes if present
            name = name.strip('"\'')
            self.direct_deps.add(name)

    def _parse_package_resolved(self, resolved_path: Path) -> None:
        """
        Parse Package.resolved (SPM lock file).
        
        Format (v2):
        {
          "pins": [
            {
              "identity": "alamofire",
              "kind": "remoteSourceControl",
              "location": "https://github.com/Alamofire/Alamofire.git",
              "state": {
                "revision": "...",
                "version": "5.9.1"
              }
            }
          ]
        }
        """
        try:
            content = resolved_path.read_text(encoding="utf-8")
            data = json.loads(content)
            
            # Handle both v1 and v2 formats
            pins = data.get("pins") or data.get("object", {}).get("pins", [])
            
            for pin in pins:
                # v2 format
                identity = pin.get("identity") or pin.get("package", "").lower()
                name = pin.get("package") or identity
                
                state = pin.get("state", {})
                version = state.get("version") or state.get("revision", "")[:12]
                
                if name and version:
                    self.lock_packages[name] = {
                        "version": version,
                        "source": "swift-pm",
                        "homepage": pin.get("location") or pin.get("repositoryURL"),
                        "dependencies": [],
                    }
                    # Note: Package.resolved contains the FULL resolved graph (including transitives).
                    # Direct deps are determined only from Package.swift .package() declarations.

            print(f"   Parsed {len(pins)} dependencies from Package.resolved")
            
        except Exception as e:
            logger.warning(f"Error parsing Package.resolved: {e}")

    def _parse_podfile(self, podfile_path: Path) -> None:
        """
        Parse Podfile for direct dependencies and version constraints.
        
        Format:
        pod 'Alamofire', '~> 5.0'
        pod 'Moya'
        """
        try:
            content = podfile_path.read_text(encoding="utf-8")
            
            # Match pod declarations
            # pod 'Name', 'version'
            # pod 'Name', '~> version'
            # pod 'Name'
            pod_pattern = re.compile(
                r"pod\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
                re.IGNORECASE
            )
            
            count = 0
            for match in pod_pattern.finditer(content):
                name = match.group(1)
                constraint = match.group(2) if match.group(2) else "*"
                
                # Skip subspecs for direct dep tracking
                base_name = name.split("/")[0]
                self.direct_deps.add(base_name)
                
                # If not already in lock_packages, add with constraint
                if name not in self.lock_packages and "/" not in name:
                    self.lock_packages[name] = {
                        "version": self._parse_constraint(constraint),
                        "source": "cocoapods",
                        "version_constraint": constraint,
                        "dependencies": [],
                    }
                count += 1
            
            print(f"   Parsed {count} pod declarations from Podfile")
            
        except Exception as e:
            logger.warning(f"Error parsing Podfile: {e}")

    def _parse_package_swift(self, swift_path: Path) -> None:
        """
        Parse Package.swift for SPM dependencies.
        
        Format:
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.0.0")
        .package(url: "...", exact: "1.2.3")
        """
        try:
            content = swift_path.read_text(encoding="utf-8")
            
            # Match .package declarations
            package_pattern = re.compile(
                r'\.package\s*\(\s*url:\s*["\']([^"\']+)["\'].*?(?:from:|exact:|\.upToNextMajor|\.upToNextMinor|branch:)?\s*["\']?([^"\')\s,]+)?',
                re.IGNORECASE | re.DOTALL
            )
            
            count = 0
            for match in package_pattern.finditer(content):
                url = match.group(1)
                version = match.group(2) if match.group(2) else "latest"
                
                # Extract package name from URL
                # Note: rstrip(".git") strips individual chars, not the suffix — use explicit check
                _url_clean = url.rstrip("/")
                if _url_clean.endswith(".git"):
                    _url_clean = _url_clean[:-4]
                name = _url_clean.split("/")[-1]
                
                self.direct_deps.add(name)
                
                # If not already in lock_packages
                if name not in self.lock_packages:
                    self.lock_packages[name] = {
                        "version": version,
                        "source": "swift-pm",
                        "homepage": url,
                        "dependencies": [],
                    }
                count += 1
            
            print(f"   Parsed {count} package declarations from Package.swift")
            
        except Exception as e:
            logger.warning(f"Error parsing Package.swift: {e}")

    def _parse_constraint(self, constraint: str) -> str:
        """
        Parse version constraint and extract the base version.
        
        Examples:
            "~> 5.0" -> "5.0"
            ">= 1.0, < 2.0" -> "1.0"
            "5.9.1" -> "5.9.1"
        """
        if not constraint or constraint == "*":
            return "UNKNOWN"
        
        # Remove operators
        version = re.sub(r'^[~>=<\s]+', '', constraint)
        # Take first part if comma-separated
        version = version.split(",")[0].strip()
        return version or "UNKNOWN"
