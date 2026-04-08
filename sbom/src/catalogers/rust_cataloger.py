"""
src/catalogers/rust_cataloger.py

RustCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Supported manifest/lock files:
- Cargo.lock (lock file - exact versions, prioritized)
- Cargo.toml (manifest - may have version ranges)

Each package dict contains:
{
  "name", "version", "purl", "language", "type", "sourcePath",
  "version_resolved", "version_source", "version_warning" (if applicable),
  "checksum" (from Cargo.lock)
}

Notes:
- Cargo.lock is prioritized for exact versions and checksums.
- Cargo.toml can have version ranges like "^1.0", "~1.2", ">=1.0".
- Metadata/vulnerability enrichment happens later in the pipeline.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

# TOML parsing
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore

from sbom.src.catalogers.base import BaseCataloger


class RustCataloger(BaseCataloger):
    """Cataloger for Rust/Cargo projects."""
    
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "rust"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name for OSV."""
        return "crates.io"

    # -------------------------
    def detect(self, root: str) -> bool:
        """Return True if Rust/Cargo manifest files exist under root."""
        rootp = Path(root)
        if list(rootp.rglob("Cargo.toml")):
            return True
        if list(rootp.rglob("Cargo.lock")):
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
        Parse Rust manifests and extract dependencies.
        Priority: Cargo.lock first (exact versions), then Cargo.toml.
        """
        try:
            return self._catalog_internal(repo_root)
        except Exception as e:
            print(f"[ERROR] Rust cataloger failed: {e}")
            import traceback
            traceback.print_exc()
            return {"packages": [], "manifests": [], "has_lock_file": False}

    def _catalog_internal(self, repo_root: str) -> Dict[str, Any]:
        root = Path(repo_root)
        print("[INFO] Detected Rust project. Parsing manifests for dependencies...")

        lock_files: List[Path] = []
        manifest_files: List[Path] = []

        # Find Cargo.lock files (exact versions)
        for p in root.rglob("Cargo.lock"):
            if self._should_skip_path(p, root):
                print(f"   [SKIP] Skipping (example/test): {p}")
                continue
            lock_files.append(p)
            print(f"   * Found LOCK file: {p}")

        # Find Cargo.toml files
        for p in root.rglob("Cargo.toml"):
            if self._should_skip_path(p, root):
                print(f"   [SKIP] Skipping (example/test): {p}")
                continue
            manifest_files.append(p)
            print(f"   * Found manifest: {p}")

        manifests = lock_files + manifest_files

        # STEP 1: Build version lookup from lock files (exact versions)
        lock_versions: Dict[str, Dict[str, Any]] = {}  # key: package name, value: {version, checksum}
        for lf in lock_files:
            lock_pkgs = self._parse_cargo_lock(lf)
            for pkg in lock_pkgs:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                checksum = pkg.get("checksum", "")
                if name and version:
                    # For packages with multiple versions, keep track
                    key = name.lower()
                    if key not in lock_versions:
                        lock_versions[key] = {"version": version, "checksum": checksum}
                    print(f"      [LOCK] {name} = {version}")

        has_lock_file = len(lock_versions) > 0
        if has_lock_file:
            print(f"[INFO] Found {len(lock_versions)} packages in Cargo.lock (exact versions)")
        else:
            print("[WARN] No Cargo.lock found - versions from Cargo.toml may be ranges")

        packages: List[Dict[str, Any]] = []

        # STEP 2: Parse Cargo.toml for direct dependencies
        direct_deps: Dict[str, Dict[str, Any]] = {}
        for m in manifest_files:
            toml_pkgs = self._parse_cargo_toml(m)
            for pkg in toml_pkgs:
                name = pkg.get("name", "")
                if name:
                    key = name.lower()
                    if key not in direct_deps:
                        direct_deps[key] = pkg

        # STEP 3: Merge - prefer lock file versions
        if has_lock_file:
            # Use all packages from lock file
            for lf in lock_files:
                lock_pkgs = self._parse_cargo_lock(lf)
                for pkg in lock_pkgs:
                    name = pkg.get("name", "")
                    key = name.lower()
                    pkg["is_direct_dependency"] = key in direct_deps
                    pkg["version_resolved"] = True
                    pkg["version_source"] = "lock_file"
                    packages.append(pkg)
        else:
            # Use Cargo.toml dependencies only
            for pkg in direct_deps.values():
                packages.append(pkg)

        # Deduplicate by name (keep first/lock file version)
        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            name = p.get("name", "")
            if not name:
                continue
            key = name.lower()
            if key not in dedup:
                dedup[key] = p
        packages = list(dedup.values())

        print(f"[INFO] Found {len(packages)} Rust dependencies")

        # STEP 4: Set common fields
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                continue

            pkg["language"] = "rust"
            pkg["type"] = "library"
            pkg.setdefault("is_direct_dependency", True)
            pkg.setdefault("scope", "required")

            version = pkg.get("version") or ""
            version_constraint = pkg.get("version_constraint", "")

            # Build PURL
            pkg["purl"] = self._build_cargo_purl(name, version)

            # Ensure version resolution fields
            if not pkg.get("version_resolved"):
                if version and not self._is_version_range(version):
                    pkg["version_resolved"] = True
                    pkg["version_source"] = "manifest"
                elif version:
                    pkg["version_resolved"] = False
                    pkg["version_source"] = "manifest_constraint"
                    pkg["version_constraint"] = version
                    pkg["version_warning"] = f"Version range '{version}' detected. No Cargo.lock found. Actual version may differ."
                else:
                    pkg["version_resolved"] = False
                    pkg["version_source"] = "unknown"
                    pkg["version_warning"] = "Version not specified and no Cargo.lock found."

            # CERT-IN field placeholders
            pkg.setdefault("component_name", name)
            pkg.setdefault("component_version", version or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])
            
            # Add checksum as hash if available
            checksum = pkg.get("checksum", "")
            if checksum and not pkg.get("hashes"):
                pkg["hashes"] = [{"alg": "SHA-256", "content": checksum}]

        # Log summary
        resolved_count = sum(1 for p in packages if p.get("version_resolved", False))
        unresolved_count = len(packages) - resolved_count
        print(f"[INFO] Version resolution: {resolved_count} resolved, {unresolved_count} unresolved")

        # Build lock_data: {pkg_name: {version, hashes, dependencies}}
        lock_data: Dict[str, Dict[str, Any]] = {}
        if has_lock_file:
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    key = name.lower()
                    if key not in lock_data:
                        hashes = pkg.get("hashes", [])
                        if not hashes and pkg.get("checksum"):
                            hashes = [{"alg": "SHA-256", "content": pkg["checksum"]}]
                        lock_data[key] = {
                            "version": version,
                            "hashes": hashes,
                            "dependencies": pkg.get("dependencies", [])
                        }
            if lock_data:
                print(f"[INFO] Collected {len(lock_data)} packages in lock_data for transitive resolution")

        return {
            "packages": packages,
            "manifests": [str(m) for m in manifests],
            "has_lock_file": has_lock_file,
            "lock_data": lock_data
        }

    # -------------------------
    # Cargo.lock Parser
    # -------------------------
    def _parse_cargo_lock(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Cargo.lock file for dependencies.
        
        Format (TOML):
            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "abc123..."
            dependencies = [...]
        """
        packages: List[Dict[str, Any]] = []
        
        if tomllib is None:
            print(f"[WARN] TOML parser not available. Install tomli: pip install tomli")
            return self._parse_cargo_lock_regex(path)
        
        try:
            content = path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return self._parse_cargo_lock_regex(path)

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            source = pkg.get("source", "")
            checksum = pkg.get("checksum", "")
            
            # Skip the root package (no source)
            if not source and not checksum:
                continue
            
            # Only include crates.io packages
            if source and "crates.io" not in source and "registry" not in source:
                # Could be a git or path dependency
                pass
            
            # Extract dependencies as structured dicts (Cargo.lock lists them as "name version" strings)
            raw_deps = pkg.get("dependencies", [])
            dep_list = []
            for dep in raw_deps:
                if isinstance(dep, str):
                    parts = dep.split()
                    dep_name = parts[0]
                    dep_ver = parts[1] if len(parts) > 1 else ""
                    dep_list.append({
                        "name": dep_name,
                        "version_constraint": dep_ver,
                        "purl": f"pkg:cargo/{dep_name}@{dep_ver}" if dep_ver else f"pkg:cargo/{dep_name}",
                    })
            
            packages.append({
                "name": name,
                "version": version,
                "checksum": checksum,
                "source": source,
                "sourcePath": str(path),
                "dependencies": dep_list,
            })

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    def _parse_cargo_lock_regex(self, path: Path) -> List[Dict[str, Any]]:
        """Fallback regex parser for Cargo.lock when TOML parser unavailable."""
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        # Parse [[package]] blocks
        package_pattern = re.compile(
            r'\[\[package\]\]\s*\n'
            r'name\s*=\s*"([^"]+)"\s*\n'
            r'version\s*=\s*"([^"]+)"',
            re.MULTILINE
        )
        
        for match in package_pattern.finditer(content):
            name, version = match.groups()
            packages.append({
                "name": name,
                "version": version,
                "sourcePath": str(path),
                "dependencies": [],
            })

        print(f"   Parsed {len(packages)} dependencies from {path.name} (regex fallback)")
        return packages

    # -------------------------
    # Cargo.toml Parser
    # -------------------------
    def _parse_cargo_toml(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Cargo.toml file for dependencies.
        
        Format (TOML):
            [dependencies]
            serde = "1.0"
            serde_json = { version = "1.0", features = ["derive"] }
            
            [dev-dependencies]
            criterion = "0.5"
            
            [build-dependencies]
            cc = "1.0"
        """
        packages: List[Dict[str, Any]] = []
        
        if tomllib is None:
            print(f"[WARN] TOML parser not available for {path}")
            return packages
        
        try:
            content = path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        # Dependency sections to parse
        dep_sections = {
            "dependencies": "required",
            "dev-dependencies": "dev",
            "build-dependencies": "build",
        }

        for section, scope in dep_sections.items():
            deps = data.get(section, {})
            for name, spec in deps.items():
                version = ""
                features = []
                optional = False
                
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "")
                    features = spec.get("features", [])
                    optional = spec.get("optional", False)
                    # Skip path/git dependencies for now
                    if spec.get("path") or spec.get("git"):
                        continue
                
                is_range = self._is_version_range(version)
                
                packages.append({
                    "name": name,
                    "version": version,
                    "version_constraint": version if is_range else "",
                    "sourcePath": str(path),
                    "scope": scope,
                    "features": features,
                    "optional": optional,
                    "is_direct_dependency": True,
                    "version_resolved": not is_range and bool(version),
                    "version_source": "manifest" if not is_range else "manifest_constraint",
                })

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    # -------------------------
    # Helpers
    # -------------------------
    def _is_version_range(self, version: str) -> bool:
        """Check if version is a range (not exact)."""
        if not version:
            return True
        
        # Cargo version range indicators
        range_patterns = [
            r'^\^',      # Caret: ^1.0.0
            r'^~',       # Tilde: ~1.0.0
            r'^[<>=]',   # Comparison: >=1.0, <2.0
            r'\*',       # Wildcard: 1.*
            r',',        # Multiple requirements: >=1.0, <2.0
        ]
        
        for pattern in range_patterns:
            if re.search(pattern, version):
                return True
        
        # Check if it's a partial version (1.0 vs 1.0.0)
        # Cargo treats "1.0" as "^1.0.0"
        parts = version.split(".")
        if len(parts) < 3:
            return True
        
        return False

    def _build_cargo_purl(self, name: str, version: str) -> str:
        """
        Build Package URL for Cargo packages.
        
        Format: pkg:cargo/name@version
        """
        if not name:
            return ""
        
        if version:
            return f"pkg:cargo/{name}@{version}"
        return f"pkg:cargo/{name}"
