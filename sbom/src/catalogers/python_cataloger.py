"""
src/catalogers/python_cataloger.py

PythonCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Each package dict contains (best-effort):
{
  "name", "version", "purl", "language", "type", "sourcePath"
}

Notes:
- This cataloger ONLY parses manifests for direct dependencies.
- Metadata/vulnerability enrichment happens later in the pipeline.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

# tomllib compatibility for Python < 3.11
try:
    import tomllib  # type: ignore
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

from sbom.src.catalogers.base import BaseCataloger


class PythonCataloger(BaseCataloger):
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "python"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name."""
        return "pypi"

    # -------------------------
    def detect(self, root: str) -> bool:
        """Return True if common Python manifest files exist under root."""
        rootp = Path(root)
        names = ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "poetry.lock")
        for n in names:
            if any(rootp.rglob(n)):
                return True
        return False

    # -------------------------
    def catalog(
        self,
        repo_root: str,
        token: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Parse Python manifests and extract DIRECT dependencies only.
        """
        try:
            return self._catalog_internal(repo_root)
        except Exception as e:
            print(f"[ERROR] Python cataloger failed: {e}")
            import traceback
            traceback.print_exc()
            return {"packages": [], "manifests": []}

    def _catalog_internal(self, repo_root: str) -> Dict[str, Any]:
        root = Path(repo_root)
        print("[INFO] Detected Python project. Parsing manifests for DIRECT dependencies...")

        # Separate lock files from manifest files
        # Lock files have exact versions, manifest files have constraints
        lock_file_names = ["Pipfile.lock", "poetry.lock"]
        manifest_file_names = ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"]
        
        lock_files: List[Path] = []
        manifest_files: List[Path] = []
        
        for name in lock_file_names:
            for p in root.rglob(name):
                if self._should_skip_path(p, root):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                lock_files.append(p)
                print(f"   * Found LOCK file: {p}")
        
        for name in manifest_file_names:
            for p in root.rglob(name):
                if self._should_skip_path(p, root):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                manifest_files.append(p)
                print(f"   * Found manifest: {p}")
        
        manifests = lock_files + manifest_files
        
        # STEP 1: Extract essential data from lock files
        # Format: {pkg_name: {version, hashes, dependencies}}
        lock_data: Dict[str, Dict[str, Any]] = {}
        
        for lf in lock_files:
            lock_pkgs = self._parse_lock_or_pipfile(lf)
            for pkg in lock_pkgs:
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")
                if name and version and version != "UNKNOWN":
                    lock_data[name] = {
                        "version": version,
                        "hashes": pkg.get("hashes", []),
                        "dependencies": pkg.get("dependencies", [])
                    }
                    print(f"      [LOCK] {name} = {version}")
        
        # Build convenience lookup
        lock_versions: Dict[str, str] = {name: data["version"] for name, data in lock_data.items()}
        
        has_lock_file = len(lock_versions) > 0
        if has_lock_file:
            print(f"[INFO] Extracted {len(lock_versions)} packages from lock files (optimized)")
        else:
            print("[WARN] No lock files found - versions from requirements may be constraints, not actual")

        packages: List[Dict[str, Any]] = []

        # Track which packages appear in manifest files (= direct deps)
        # Lock-only packages will be marked transitive
        manifest_pkg_names: set = set()

        for m in manifests:
            nm = m.name.lower()
            if nm == "requirements.txt":
                pkgs = self._parse_requirements(m)
                for p in pkgs:
                    if p.get("name"):
                        manifest_pkg_names.add(p["name"].lower())
                packages.extend(pkgs)
            elif nm == "pyproject.toml":
                pkgs = self._parse_pyproject(m)
                for p in pkgs:
                    if p.get("name"):
                        manifest_pkg_names.add(p["name"].lower())
                packages.extend(pkgs)
            elif nm == "setup.py":
                pkgs = self._parse_setup_py(m)
                for p in pkgs:
                    if p.get("name"):
                        manifest_pkg_names.add(p["name"].lower())
                packages.extend(pkgs)
            elif nm == "pipfile":
                # Pipfile is a manifest — its deps are direct
                pkgs = self._parse_lock_or_pipfile(m)
                for p in pkgs:
                    if p.get("name"):
                        manifest_pkg_names.add(p["name"].lower())
                packages.extend(pkgs)
            elif nm in ("pipfile.lock", "poetry.lock"):
                # Lock files — packages here may be transitive
                packages.extend(self._parse_lock_or_pipfile(m))

        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            if not p.get("name"):
                continue
            dedup[p["name"].lower()] = p
        packages = list(dedup.values())

        print(f"[INFO] Found {len(packages)} DIRECT dependencies from manifests")

        # STEP 2: Resolve versions using lock file lookup
        for pkg in packages:
            name = pkg.get("name")
            if not name:
                continue

            pkg["language"] = "python"
            pkg["type"] = "library"
            name_lower = name.lower()
            # Direct if: no lock file present, OR no manifest packages found (lock-only project),
            # OR the package name explicitly appears in a manifest file
            if has_lock_file and manifest_pkg_names:
                pkg["is_direct_dependency"] = name_lower in manifest_pkg_names
            else:
                pkg["is_direct_dependency"] = True
            pkg.setdefault("scope", "required")
            original_version = pkg.get("version") or ""
            version_constraint = pkg.get("version_constraint", "")
            
            # Store the original constraint for tracking
            if version_constraint:
                pkg["version_original"] = version_constraint
            elif original_version and original_version != "UNKNOWN":
                pkg["version_original"] = original_version
            
            if name_lower in lock_versions:
                # Use exact version from lock file
                resolved_version = lock_versions[name_lower]
                pkg["version"] = resolved_version
                pkg["version_resolved"] = True
                pkg["version_source"] = "lock_file"
                if version_constraint:
                    pkg["version_constraint"] = version_constraint
            elif original_version and original_version != "UNKNOWN":
                # Check if constraint is exact version (==x.y.z)
                is_exact_version = version_constraint.startswith("==") if version_constraint else False
                
                if is_exact_version:
                    pkg["version_resolved"] = True
                    pkg["version_source"] = "manifest_exact"
                else:
                    pkg["version_resolved"] = False
                    pkg["version_source"] = "manifest_constraint"
                    pkg["version_warning"] = "No lock file found. Using minimum version from constraint. Actual installed version may differ. Vulnerability results may be inaccurate."
                
                if not version_constraint and original_version:
                    pkg["version_constraint"] = original_version
            else:
                # No version at all
                pkg["version"] = "UNKNOWN"
                pkg["version_resolved"] = False
                pkg["version_source"] = "unknown"
                pkg["version_warning"] = "Version not specified in manifest and no lock file found. Cannot accurately check vulnerabilities."

            version_final = pkg.get("version") or ""
            pkg["purl"] = pkg.get("purl") or f"pkg:pypi/{name}@{version_final}"

            pkg.setdefault("component_name", pkg.get("name"))
            pkg.setdefault("component_version", pkg.get("version") or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])
        
        # Log summary of version resolution
        resolved_count = sum(1 for p in packages if p.get("version_resolved", False))
        unresolved_count = len(packages) - resolved_count
        print(f"[INFO] Version resolution: {resolved_count} resolved (from lock), {unresolved_count} unresolved (from constraints)")

        # Return direct dependencies + lock data for transitive resolution
        return {
            "packages": packages,
            "manifests": [str(p) for p in manifests],
            "has_lock_file": has_lock_file,
            "lock_data": lock_data  # OPTIMIZED: {pkg_name: {version, hashes, dependencies}}
        }

    # -------------------------
    def _parse_requirements(self, path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        pattern = re.compile(r"^\s*([A-Za-z0-9_\-\.]+)(?:\s*([=<>!~]+)\s*(\S+))?")
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("-r ") or line.startswith("--requirement"):
                        continue

                    if line.startswith("-e ") or line.startswith("git+"):
                        if "#egg=" in line:
                            name = line.split("#egg=")[-1].strip()
                            out.append(self._mk_pkg(name, "UNKNOWN", path))
                        continue

                    if "#egg=" in line:
                        name = line.split("#egg=")[-1].strip()
                        out.append(self._mk_pkg(name, "UNKNOWN", path))
                        continue

                    if ";" in line:
                        line = line.split(";")[0].strip()

                    match = pattern.match(line)
                    if not match:
                        continue

                    name = match.group(1)
                    version = match.group(3) or ""
                    version = re.sub(r"^[=<>!~^]+", "", str(version)).strip()
                    out.append(self._mk_pkg(name, version, path))
        except Exception as e:
            print(f"   [WARN] Failed to parse requirements.txt {path}: {e}")
        return out

    def _parse_pyproject(self, path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            project = data.get("project", {}) if isinstance(data, dict) else {}
            deps = project.get("dependencies", []) if isinstance(project, dict) else []

            for dep in deps or []:
                if not isinstance(dep, str):
                    continue
                dep = dep.split(";")[0].strip()
                match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(.*)$", dep)
                if match:
                    name = match.group(1)
                    version = re.sub(r"^[=<>!~^]+", "", match.group(2).strip())
                    out.append(self._mk_pkg(name, version, path))

            tool = data.get("tool", {}) if isinstance(data, dict) else {}
            poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
            poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}

            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version = ""
                if isinstance(spec, str):
                    version = re.sub(r"^[=<>!~^]+", "", spec).strip()
                elif isinstance(spec, dict):
                    version = re.sub(r"^[=<>!~^]+", "", str(spec.get("version", ""))).strip()
                out.append(self._mk_pkg(name, version, path))
        except Exception as e:
            print(f"   [WARN] Failed to parse pyproject.toml {path}: {e}")
        return out

    def _parse_setup_py(self, path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, flags=re.DOTALL)
            if not match:
                return out
            body = match.group(1)
            for dep in re.findall(r"['\"]([^'\"]+)['\"]", body):
                dep = dep.split(";")[0].strip()
                dep_match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(.*)$", dep)
                if dep_match:
                    name = dep_match.group(1)
                    version = re.sub(r"^[=<>!~^]+", "", dep_match.group(2).strip())
                    out.append(self._mk_pkg(name, version, path))
        except Exception as e:
            print(f"   [WARN] Failed to parse setup.py {path}: {e}")
        return out

    def _parse_lock_or_pipfile(self, path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        name = path.name.lower()

        try:
            if name == "pipfile.lock":
                data = json.loads(path.read_text(encoding="utf-8"))
                for section in ("default", "develop"):
                    deps = data.get(section, {}) if isinstance(data, dict) else {}
                    for pkg_name, meta in deps.items():
                        version = ""
                        if isinstance(meta, dict):
                            version = meta.get("version", "")
                        version = re.sub(r"^[=<>!~^]+", "", str(version)).strip()
                        out.append(self._mk_pkg(pkg_name, version, path, scope="dev" if section == "develop" else "required"))
                return out

            if name == "pipfile":
                data = tomllib.loads(path.read_text(encoding="utf-8"))
                packages = data.get("packages", {}) if isinstance(data, dict) else {}
                dev_packages = data.get("dev-packages", {}) if isinstance(data, dict) else {}
                for pkg_name, spec in packages.items():
                    version = "" if isinstance(spec, dict) else str(spec)
                    version = re.sub(r"^[=<>!~^]+", "", version).strip()
                    out.append(self._mk_pkg(pkg_name, version, path, scope="required"))
                for pkg_name, spec in dev_packages.items():
                    version = "" if isinstance(spec, dict) else str(spec)
                    version = re.sub(r"^[=<>!~^]+", "", version).strip()
                    out.append(self._mk_pkg(pkg_name, version, path, scope="dev"))
                return out

            if name == "poetry.lock":
                text = path.read_text(encoding="utf-8", errors="ignore")
                current_name = None
                current_version = None
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("name = "):
                        current_name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("version = "):
                        current_version = line.split("=", 1)[1].strip().strip('"')
                        if current_name:
                            out.append(self._mk_pkg(current_name, current_version, path))
                            current_name = None
                            current_version = None
                return out

        except Exception as e:
            print(f"   [WARN] Failed to parse {path}: {e}")
        return out

    def _mk_pkg(self, name: str, version: str, path: Path, scope: str = "required") -> Dict[str, Any]:
        return {
            "name": name,
            "version": version or "UNKNOWN",
            "language": "python",
            "type": "library",
            "purl": f"pkg:pypi/{name}@{version or ''}",
            "sourcePath": str(path),
            "scope": scope,
            "is_direct_dependency": True,
        }
