"""
src/catalogers/nuget_cataloger.py

NuGetCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Supported manifest/lock files:
- packages.lock.json (NuGet lock file - exact versions, prioritized)
- *.csproj, *.fsproj, *.vbproj (SDK-style project files)
- packages.config (legacy NuGet format)
- Directory.Packages.props (Central Package Management)

Each package dict contains:
{
  "name", "version", "purl", "language", "type", "sourcePath",
  "version_resolved", "version_source", "version_warning" (if applicable),
  "framework" (target framework)
}
"""

from __future__ import annotations
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional

from sbom.src.catalogers.base import BaseCataloger


class NuGetCataloger(BaseCataloger):
    """Cataloger for .NET/NuGet projects."""
    
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        return "dotnet"

    @property
    def ecosystem(self) -> str:
        return "NuGet"

    def detect(self, root: str) -> bool:
        rootp = Path(root)
        if list(rootp.rglob("*.csproj")) or list(rootp.rglob("*.fsproj")) or list(rootp.rglob("*.vbproj")):
            return True
        if list(rootp.rglob("packages.config")):
            return True
        if list(rootp.rglob("packages.lock.json")):
            return True
        if list(rootp.rglob("*.sln")):
            return True
        return False

    def catalog(self, repo_root: str, token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
        try:
            return self._catalog_internal(repo_root)
        except Exception as e:
            print(f"[ERROR] NuGet cataloger failed: {e}")
            import traceback
            traceback.print_exc()
            return {"packages": [], "manifests": [], "has_lock_file": False}

    def _catalog_internal(self, repo_root: str) -> Dict[str, Any]:
        root = Path(repo_root)
        print("[INFO] Detected .NET project. Parsing manifests for dependencies...")

        lock_files: List[Path] = []
        manifest_files: List[Path] = []

        for p in root.rglob("packages.lock.json"):
            if self._should_skip_path(p, root):
                continue
            lock_files.append(p)
            print(f"   * Found LOCK file: {p}")

        for pattern in ("*.csproj", "*.fsproj", "*.vbproj"):
            for p in root.rglob(pattern):
                if self._should_skip_path(p, root):
                    continue
                manifest_files.append(p)
                print(f"   * Found manifest: {p}")

        for p in root.rglob("packages.config"):
            if self._should_skip_path(p, root):
                continue
            manifest_files.append(p)
            print(f"   * Found manifest (legacy): {p}")

        for p in root.rglob("Directory.Packages.props"):
            if self._should_skip_path(p, root):
                continue
            manifest_files.append(p)
            print(f"   * Found CPM manifest: {p}")

        manifests = lock_files + manifest_files

        lock_versions: Dict[str, Dict[str, Any]] = {}
        lock_data: Dict[str, Dict[str, Any]] = {}
        for lf in lock_files:
            lock_pkgs = self._parse_packages_lock_json(lf)
            for pkg in lock_pkgs:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    key = name.lower()
                    if key not in lock_versions:
                        lock_versions[key] = {"version": version, "framework": pkg.get("framework", "")}
                    if key not in lock_data:
                        lock_data[key] = {
                            "version": version,
                            "hashes": pkg.get("hashes", []),
                            "dependencies": pkg.get("dependencies", [])
                        }

        has_lock_file = len(lock_versions) > 0
        if has_lock_file:
            print(f"[INFO] Found {len(lock_versions)} packages in lock files (exact versions)")

        packages: List[Dict[str, Any]] = []

        for m in manifests:
            nm = m.name.lower()
            if nm == "packages.lock.json":
                packages.extend(self._parse_packages_lock_json(m))
            elif nm.endswith((".csproj", ".fsproj", ".vbproj")):
                packages.extend(self._parse_project_file(m))
            elif nm == "packages.config":
                packages.extend(self._parse_packages_config(m))
            elif nm == "directory.packages.props":
                packages.extend(self._parse_directory_packages_props(m))

        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            name = p.get("name", "")
            if not name:
                continue
            key = name.lower()
            if key not in dedup or (p.get("version_source") == "lock_file" and dedup[key].get("version_source") != "lock_file"):
                dedup[key] = p
        packages = list(dedup.values())

        print(f"[INFO] Found {len(packages)} .NET dependencies")

        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                continue

            pkg["language"] = "dotnet"
            pkg["type"] = "library"
            pkg.setdefault("is_direct_dependency", True)
            pkg.setdefault("scope", "required")

            key = name.lower()
            version = pkg.get("version") or ""
            version_constraint = pkg.get("version_constraint", "")

            if key in lock_versions and pkg.get("version_source") != "lock_file":
                resolved_version = lock_versions[key]["version"]
                pkg["version"] = resolved_version
                pkg["version_resolved"] = True
                pkg["version_source"] = "lock_file"
                if version_constraint:
                    pkg["version_constraint"] = version_constraint
            elif not pkg.get("version_resolved"):
                if version and not self._is_version_range(version):
                    pkg["version_resolved"] = True
                    pkg["version_source"] = "manifest"
                elif version:
                    pkg["version_resolved"] = False
                    pkg["version_source"] = "manifest_constraint"
                    pkg["version_constraint"] = version
                    pkg["version_warning"] = f"Version range '{version}' detected. No lock file found."
                else:
                    pkg["version_resolved"] = False
                    pkg["version_source"] = "unknown"
                    pkg["version_warning"] = "Version not specified and no lock file found."

            version = pkg.get("version") or ""
            pkg["purl"] = self._build_nuget_purl(name, version)

            pkg.setdefault("component_name", name)
            pkg.setdefault("component_version", version or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        resolved_count = sum(1 for p in packages if p.get("version_resolved", False))
        unresolved_count = len(packages) - resolved_count
        print(f"[INFO] Version resolution: {resolved_count} resolved, {unresolved_count} unresolved")

        return {
            "packages": packages,
            "manifests": [str(m) for m in manifests],
            "has_lock_file": has_lock_file,
            "lock_data": lock_data,
        }

    def _parse_packages_lock_json(self, path: Path) -> List[Dict[str, Any]]:
        packages: List[Dict[str, Any]] = []
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        dependencies = data.get("dependencies", {})
        for framework, framework_deps in dependencies.items():
            if not isinstance(framework_deps, dict):
                continue
            for name, dep_info in framework_deps.items():
                if not isinstance(dep_info, dict):
                    continue
                version = dep_info.get("resolved", "")
                dep_type = dep_info.get("type", "").lower()
                content_hash = dep_info.get("contentHash", "")
                requested = dep_info.get("requested", "")
                is_direct = dep_type in ("direct", "")

                # Extract dependencies as structured dicts from lock file
                raw_deps = dep_info.get("dependencies", {})
                dep_list = [
                    {
                        "name": d,
                        "version_constraint": str(v),
                        "purl": f"pkg:nuget/{d}@{v}" if v else f"pkg:nuget/{d}",
                    }
                    for d, v in raw_deps.items()
                ] if isinstance(raw_deps, dict) else []

                pkg = {
                    "name": name,
                    "version": version,
                    "version_constraint": requested if requested != version else "",
                    "sourcePath": str(path),
                    "framework": framework,
                    "is_direct_dependency": is_direct,
                    "version_resolved": True,
                    "version_source": "lock_file",
                    "dependencies": dep_list,
                }
                if content_hash:
                    pkg["hashes"] = [{"alg": "SHA-512", "content": content_hash}]
                packages.append(pkg)
        return packages

    def _parse_project_file(self, path: Path) -> List[Dict[str, Any]]:
        packages: List[Dict[str, Any]] = []
        try:
            content = path.read_text(encoding="utf-8")
            content = re.sub(r'\sxmlns\s*=\s*"[^"]*"', '', content)
            root = ET.fromstring(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        for pkg_ref in root.iter("PackageReference"):
            name = pkg_ref.get("Include") or pkg_ref.get("Update") or ""
            version = pkg_ref.get("Version") or ""
            if not version:
                version_elem = pkg_ref.find("Version")
                if version_elem is not None and version_elem.text:
                    version = version_elem.text.strip()
            if not name:
                continue
            is_range = self._is_version_range(version)
            packages.append({
                "name": name,
                "version": version,
                "version_constraint": version if is_range else "",
                "sourcePath": str(path),
                "is_direct_dependency": True,
                "version_resolved": not is_range and bool(version),
                "version_source": "manifest" if not is_range else "manifest_constraint",
            })
        return packages

    def _parse_packages_config(self, path: Path) -> List[Dict[str, Any]]:
        packages: List[Dict[str, Any]] = []
        try:
            content = path.read_text(encoding="utf-8")
            root = ET.fromstring(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        for pkg_elem in root.iter("package"):
            name = pkg_elem.get("id", "")
            version = pkg_elem.get("version", "")
            framework = pkg_elem.get("targetFramework", "")
            if not name:
                continue
            packages.append({
                "name": name,
                "version": version,
                "sourcePath": str(path),
                "framework": framework,
                "is_direct_dependency": True,
                "version_resolved": bool(version),
                "version_source": "manifest",
            })
        return packages

    def _parse_directory_packages_props(self, path: Path) -> List[Dict[str, Any]]:
        packages: List[Dict[str, Any]] = []
        try:
            content = path.read_text(encoding="utf-8")
            content = re.sub(r'\sxmlns\s*=\s*"[^"]*"', '', content)
            root = ET.fromstring(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        for pkg_ver in root.iter("PackageVersion"):
            name = pkg_ver.get("Include") or ""
            version = pkg_ver.get("Version") or ""
            if not name:
                continue
            is_range = self._is_version_range(version)
            packages.append({
                "name": name,
                "version": version,
                "version_constraint": version if is_range else "",
                "sourcePath": str(path),
                "is_direct_dependency": True,
                "version_resolved": not is_range and bool(version),
                "version_source": "manifest" if not is_range else "manifest_constraint",
            })
        return packages

    def _is_version_range(self, version: str) -> bool:
        if not version:
            return True
        range_patterns = [r'^\[', r'^\(', r'\*', r',', r'^\$']
        for pattern in range_patterns:
            if re.search(pattern, version):
                return True
        return False

    def _build_nuget_purl(self, name: str, version: str) -> str:
        if not name:
            return ""
        if version:
            return f"pkg:nuget/{name}@{version}"
        return f"pkg:nuget/{name}"
