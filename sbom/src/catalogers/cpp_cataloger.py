"""
C/C++ Package Cataloger

Parses C/C++ project manifest files to extract package dependencies.
Supports:
  - conanfile.txt (Conan package manager - text format)
  - conanfile.py  (Conan package manager - Python format)
  - vcpkg.json    (vcpkg manifest mode)
  - CMakeLists.txt (CMake FetchContent / find_package hints)

Lock-first approach: If conan.lock or vcpkg-configuration.json exists, use it for exact versions.

Note: deps.dev does NOT support C/C++ ecosystems. All enrichment comes from
Conan Center or vcpkg registry directly.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sbom.src.catalogers.base import BaseCataloger

logger = logging.getLogger(__name__)


class CppCataloger(BaseCataloger):
    """Cataloger for C/C++ projects using Conan or vcpkg."""

    LANGUAGE = "cpp"
    MANIFEST_FILES = [
        "conanfile.txt", "conanfile.py", "conan.lock",
        "vcpkg.json", "vcpkg-configuration.json",
        "CMakeLists.txt",
    ]

    @property
    def language(self) -> str:
        return "cpp"

    @property
    def ecosystem(self) -> str:
        return "conan"

    def __init__(self):
        self.lock_packages: Dict[str, Dict[str, Any]] = {}
        self.direct_deps: Set[str] = set()

    def detect(self, root: str) -> bool:
        """Check if this is a C/C++ project with Conan or vcpkg."""
        root_path = Path(root)
        if (root_path / "conanfile.txt").exists():
            return True
        if (root_path / "conanfile.py").exists():
            return True
        if (root_path / "conan.lock").exists():
            return True
        if (root_path / "vcpkg.json").exists():
            return True
        # Only detect CMakeLists.txt if it contains FetchContent or find_package
        cmake = root_path / "CMakeLists.txt"
        if cmake.exists():
            try:
                text = cmake.read_text(encoding="utf-8", errors="replace")[:4096]
                if "FetchContent" in text or "find_package" in text or "conan" in text.lower():
                    return True
            except Exception:
                pass
        return False

    def catalog(self, project_path: str, token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Catalog C/C++ dependencies from a project directory.

        Returns:
            Dict with keys: packages, manifests, has_lock_file, language, lock_data
        """
        project = Path(project_path)
        packages: List[Dict[str, Any]] = []
        manifests: List[str] = []
        has_lock_file = False

        # Reset state
        self.lock_packages = {}
        self.direct_deps = set()

        logger.info("Detected C/C++ project. Parsing manifests for dependencies...")

        # Step 1: Check for conan.lock (exact versions)
        conan_lock = project / "conan.lock"
        if conan_lock.exists():
            has_lock_file = True
            manifests.append(str(conan_lock))
            print(f"   * Found LOCK file: {conan_lock}")
            self._parse_conan_lock(conan_lock)

        # Step 2: Parse conanfile.txt
        conanfile_txt = project / "conanfile.txt"
        if conanfile_txt.exists():
            manifests.append(str(conanfile_txt))
            print(f"   * Found manifest: {conanfile_txt}")
            self._parse_conanfile_txt(conanfile_txt)

        # Step 3: Parse conanfile.py
        conanfile_py = project / "conanfile.py"
        if conanfile_py.exists():
            manifests.append(str(conanfile_py))
            print(f"   * Found manifest: {conanfile_py}")
            self._parse_conanfile_py(conanfile_py)

        # Step 4: Parse vcpkg.json
        vcpkg_json = project / "vcpkg.json"
        if vcpkg_json.exists():
            manifests.append(str(vcpkg_json))
            print(f"   * Found manifest: {vcpkg_json}")
            self._parse_vcpkg_json(vcpkg_json)

        # Step 5: Parse vcpkg-configuration.json for version pins
        vcpkg_config = project / "vcpkg-configuration.json"
        if vcpkg_config.exists():
            manifests.append(str(vcpkg_config))

        # Step 6: Parse CMakeLists.txt for FetchContent
        cmake_file = project / "CMakeLists.txt"
        if cmake_file.exists():
            manifests.append(str(cmake_file))
            print(f"   * Found manifest: {cmake_file}")
            self._parse_cmake(cmake_file)

        # Build package list from collected data
        seen: Set[str] = set()
        for name, pkg_data in self.lock_packages.items():
            if name in seen:
                continue
            seen.add(name)

            version = pkg_data.get("version", "UNKNOWN")
            source = pkg_data.get("source", "conan")  # "conan" or "vcpkg"
            is_direct = name in self.direct_deps

            if source == "conan":
                purl_ns = "conan"
            elif source == "vcpkg":
                purl_ns = "vcpkg"
            else:
                purl_ns = "github"  # cmake FetchContent packages are git-sourced
            pkg = {
                "name": name,
                "version": version,
                "language": "cpp",
                "purl": f"pkg:{purl_ns}/{name}@{version}" if version != "UNKNOWN" else f"pkg:{purl_ns}/{name}",
                "version_resolved": has_lock_file and version != "UNKNOWN",
                "version_source": "lock_file" if has_lock_file and version != "UNKNOWN" else "manifest",
                "is_direct_dependency": is_direct,
                "is_dev_dependency": pkg_data.get("is_dev", False),
                "dependencies": pkg_data.get("dependencies", []),
                "package_type": "library",
                "source_type": source,
                "type": "library",
            }
            packages.append(pkg)
            dep_type = "direct" if is_direct else "transitive"
            print(f"      [{source.upper()}] {name} = {version} ({dep_type})")

        # Set common fields
        for pkg in packages:
            pkg.setdefault("scope", "required")
            pkg.setdefault("component_name", pkg.get("name"))
            pkg.setdefault("component_version", pkg.get("version") or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        # Build lock_data
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
                            "dependencies": pkg.get("dependencies", []),
                        }
            if lock_data:
                print(f"[INFO] Collected {len(lock_data)} packages in lock_data for transitive resolution")

        resolved = sum(1 for p in packages if p.get("version_resolved"))
        unresolved = len(packages) - resolved
        print(f"[INFO] Found {len(packages)} C/C++ dependencies")
        print(f"[INFO] Version resolution: {resolved} resolved, {unresolved} unresolved")

        return {
            "packages": packages,
            "manifests": manifests,
            "has_lock_file": has_lock_file,
            "language": "cpp",
            "lock_data": lock_data,
        }

    # -------------------------
    # Conan Parsers
    # -------------------------

    def _parse_conan_lock(self, lock_path: Path) -> None:
        """
        Parse conan.lock for exact versions.

        Conan 2.x format (JSON):
        {
          "version": "0.5",
          "requires": ["zlib/1.3.1#...", "openssl/3.2.1#..."],
          "build_requires": [...],
          "python_requires": [...]
        }

        Conan 1.x format (JSON):
        {
          "graph_lock": {
            "nodes": {
              "0": {"ref": "mylib/1.0@user/channel", ...},
              "1": {"ref": "zlib/1.2.13", ...}
            }
          }
        }
        """
        try:
            content = lock_path.read_text(encoding="utf-8")
            data = json.loads(content)

            # Conan 2.x format
            # NOTE: conan.lock v2 "requires" is the FULL resolved graph (direct + transitive).
            # Direct deps are determined from conanfile.txt / conanfile.py, not the lock file.
            if "requires" in data:
                for req in data.get("requires", []):
                    self._add_conan_ref(req, is_direct=False)
                for req in data.get("build_requires", []):
                    self._add_conan_ref(req, is_direct=False)
                print(f"   Parsed {len(self.lock_packages)} dependencies from conan.lock (v2)")

            # Conan 1.x format — walk graph to build per-package dependency lists
            elif "graph_lock" in data:
                nodes = data.get("graph_lock", {}).get("nodes", {})
                # Root node "0" lists direct dep node IDs in its "requires" dict
                root_direct_ids: Set[str] = set(nodes.get("0", {}).get("requires", {}).keys())
                
                # First pass: build node_id -> package name mapping
                node_to_name: Dict[str, str] = {}
                for node_id, node_data in nodes.items():
                    if node_id == "0":
                        continue
                    ref = node_data.get("ref", "")
                    if ref:
                        # Parse ref to get name
                        clean_ref = ref.split("#")[0].split("@")[0]
                        parts = clean_ref.split("/")
                        if len(parts) >= 2:
                            node_to_name[node_id] = parts[0].strip().lower()
                
                # Second pass: add packages and resolve dependency references
                for node_id, node_data in nodes.items():
                    if node_id == "0":
                        continue
                    ref = node_data.get("ref", "")
                    if ref:
                        self._add_conan_ref(ref, is_direct=(node_id in root_direct_ids))
                        
                        # Walk this node's "requires" to build its dependency list
                        node_requires = node_data.get("requires", {})
                        if isinstance(node_requires, dict) and node_requires:
                            clean_ref = ref.split("#")[0].split("@")[0]
                            parts = clean_ref.split("/")
                            if len(parts) >= 2:
                                pkg_key = parts[0].strip().lower()
                                dep_list = []
                                for dep_node_id in node_requires.keys():
                                    dep_name = node_to_name.get(dep_node_id)
                                    if dep_name and dep_name in self.lock_packages:
                                        dep_ver = self.lock_packages[dep_name].get("version", "")
                                        dep_list.append({
                                            "name": dep_name,
                                            "version_constraint": dep_ver,
                                            "purl": f"pkg:conan/{dep_name}@{dep_ver}" if dep_ver else f"pkg:conan/{dep_name}",
                                        })
                                if dep_list and pkg_key in self.lock_packages:
                                    self.lock_packages[pkg_key]["dependencies"] = dep_list
                
                print(f"   Parsed {len(self.lock_packages)} dependencies from conan.lock (v1)")

        except Exception as e:
            logger.warning(f"Error parsing conan.lock: {e}")

    def _add_conan_ref(self, ref: str, is_direct: bool = True) -> None:
        """
        Parse a Conan reference string and add to lock_packages.

        Format: "name/version", "name/version@user/channel", "name/version#revision"
        """
        if not ref:
            return
        # Strip revision hash and user/channel
        ref = ref.split("#")[0]
        ref = ref.split("@")[0]
        parts = ref.split("/")
        if len(parts) >= 2:
            name = parts[0].strip()
            version = parts[1].strip()
            if name:
                key = name.lower()
                if key not in self.lock_packages:
                    self.lock_packages[key] = {
                        "version": version,
                        "source": "conan",
                        "dependencies": [],
                    }
                if is_direct:
                    self.direct_deps.add(key)

    def _parse_conanfile_txt(self, path: Path) -> None:
        """
        Parse conanfile.txt for dependencies.

        Format:
        [requires]
        zlib/1.3.1
        openssl/3.2.1

        [build_requires]
        cmake/3.28.1

        [tool_requires]
        cmake/3.28.1
        """
        try:
            content = path.read_text(encoding="utf-8")
            current_section = None

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Section headers
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1].lower()
                    continue

                if current_section in ("requires", "build_requires", "tool_requires"):
                    ref = line.split("#")[0].strip()  # Strip inline comments
                    if "/" in ref:
                        self._add_conan_ref(ref, is_direct=(current_section == "requires"))

            print(f"   Parsed {len(self.direct_deps)} direct dependencies from conanfile.txt")

        except Exception as e:
            logger.warning(f"Error parsing conanfile.txt: {e}")

    def _parse_conanfile_py(self, path: Path) -> None:
        """
        Parse conanfile.py for requires() calls.

        Extracts from patterns like:
            self.requires("zlib/1.3.1")
            self.tool_requires("cmake/3.28.1")
            requires = "zlib/1.3.1"
        """
        try:
            content = path.read_text(encoding="utf-8")

            # Pattern: self.requires("name/version")
            requires_pattern = re.compile(
                r'self\.(?:requires|tool_requires|build_requires)\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            for match in requires_pattern.finditer(content):
                ref = match.group(1)
                is_direct = "requires(" in match.group(0) and "tool_" not in match.group(0) and "build_" not in match.group(0)
                self._add_conan_ref(ref, is_direct=is_direct)

            # Pattern: requires = "name/version" (class attribute)
            attr_pattern = re.compile(r'requires\s*=\s*["\']([^"\']+)["\']')
            for match in attr_pattern.finditer(content):
                self._add_conan_ref(match.group(1), is_direct=True)

            print(f"   Parsed dependencies from conanfile.py")

        except Exception as e:
            logger.warning(f"Error parsing conanfile.py: {e}")

    # -------------------------
    # vcpkg Parser
    # -------------------------

    def _parse_vcpkg_json(self, path: Path) -> None:
        """
        Parse vcpkg.json manifest for dependencies.

        Format:
        {
          "name": "my-project",
          "version-semver": "1.0.0",
          "dependencies": [
            "zlib",
            {"name": "openssl", "version>=": "3.0.0"},
            {"name": "boost-asio", "features": ["ssl"]}
          ]
        }
        """
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)

            for dep in data.get("dependencies", []):
                if isinstance(dep, str):
                    # Simple dependency: "zlib"
                    name = dep.strip()
                    key = name.lower()
                    if key not in self.lock_packages:
                        self.lock_packages[key] = {
                            "version": "UNKNOWN",
                            "source": "vcpkg",
                            "dependencies": [],
                        }
                    self.direct_deps.add(key)

                elif isinstance(dep, dict):
                    # Complex dependency: {"name": "openssl", "version>=": "3.0.0"}
                    name = dep.get("name", "").strip()
                    if not name:
                        continue
                    key = name.lower()
                    version = dep.get("version>=", "") or dep.get("version", "") or "UNKNOWN"
                    if key not in self.lock_packages:
                        self.lock_packages[key] = {
                            "version": version,
                            "source": "vcpkg",
                            "version_constraint": dep.get("version>=", ""),
                            "features": dep.get("features", []),
                            "dependencies": [],
                        }
                    self.direct_deps.add(key)

            print(f"   Parsed {len(self.direct_deps)} dependencies from vcpkg.json")

        except Exception as e:
            logger.warning(f"Error parsing vcpkg.json: {e}")

    # -------------------------
    # CMake Parser (best-effort)
    # -------------------------

    def _parse_cmake(self, path: Path) -> None:
        """
        Parse CMakeLists.txt for FetchContent_Declare dependencies.

        Extracts from patterns like:
            FetchContent_Declare(
                googletest
                GIT_REPOSITORY https://github.com/google/googletest.git
                GIT_TAG v1.14.0
            )

            find_package(Boost 1.83 REQUIRED)
        """
        try:
            content = path.read_text(encoding="utf-8", errors="replace")

            # FetchContent_Declare
            fetch_pattern = re.compile(
                r'FetchContent_Declare\s*\(\s*(\w+)\s+.*?GIT_TAG\s+[v]?([^\s\)]+)',
                re.DOTALL | re.IGNORECASE,
            )
            for match in fetch_pattern.finditer(content):
                name = match.group(1).strip().lower()
                version = match.group(2).strip()
                if name and name not in self.lock_packages:
                    self.lock_packages[name] = {
                        "version": version,
                        "source": "cmake",
                        "dependencies": [],
                    }
                    self.direct_deps.add(name)

            # find_package(Name VERSION)
            find_pattern = re.compile(
                r'find_package\s*\(\s*(\w+)\s+(\d[\d.]*)',
                re.IGNORECASE,
            )
            for match in find_pattern.finditer(content):
                name = match.group(1).strip().lower()
                version = match.group(2).strip()
                if name and name not in self.lock_packages:
                    self.lock_packages[name] = {
                        "version": version,
                        "source": "cmake",
                        "version_constraint": f">={version}",
                        "dependencies": [],
                    }
                    self.direct_deps.add(name)

            print(f"   Parsed CMake dependencies from CMakeLists.txt")

        except Exception as e:
            logger.warning(f"Error parsing CMakeLists.txt: {e}")
