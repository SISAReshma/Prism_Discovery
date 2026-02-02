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


class PythonCataloger:
    def __init__(self):
        self.language = "python"

    # -------------------------
    def _should_skip_path(self, path: Path) -> bool:
        """
        Skip manifest files in example/test/demo directories.
        These are not real dependencies per SBOM standards (SPDX, CycloneDX).
        Matches behavior of industry tools like Syft and Trivy.
        """
        excluded_dirs = {
            "example", "examples",
            "test", "tests", "testing",
            "demo", "demos",
            "sample", "samples",
            "tutorial", "tutorials",
            "doc", "docs", "documentation",
            "benchmark", "benchmarks",
            ".tox", ".venv", "venv", "env", "virtualenv",
            "node_modules", ".git", ".github",
        }

        parts_lower = [p.lower() for p in path.parts]
        return any(excluded in parts_lower for excluded in excluded_dirs)

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

        manifests: List[Path] = []
        for name in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "Pipfile.lock", "poetry.lock"):
            for p in root.rglob(name):
                if self._should_skip_path(p):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                manifests.append(p)
                print(f"   * Found manifest: {p}")

        packages: List[Dict[str, Any]] = []

        for m in manifests:
            nm = m.name.lower()
            if nm == "requirements.txt":
                packages.extend(self._parse_requirements(m))
            elif nm == "pyproject.toml":
                packages.extend(self._parse_pyproject(m))
            elif nm == "setup.py":
                packages.extend(self._parse_setup_py(m))
            elif nm in ("pipfile", "pipfile.lock", "poetry.lock"):
                packages.extend(self._parse_lock_or_pipfile(m))

        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            if not p.get("name"):
                continue
            dedup[p["name"].lower()] = p
        packages = list(dedup.values())

        print(f"[INFO] Found {len(packages)} DIRECT dependencies from manifests")

        for pkg in packages:
            name = pkg.get("name")
            if not name:
                continue

            pkg["language"] = "python"
            pkg["type"] = "library"
            pkg["is_direct_dependency"] = True
            pkg.setdefault("scope", "required")

            version_final = pkg.get("version") or ""
            pkg["purl"] = pkg.get("purl") or f"pkg:pypi/{name}@{version_final}"

            pkg.setdefault("component_name", pkg.get("name"))
            pkg.setdefault("component_version", pkg.get("version") or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        return {"packages": packages, "manifests": [str(p) for p in manifests]}

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
