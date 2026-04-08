"""
src/catalogers/npm_cataloger.py

NpmCataloger:
- detect(root) -> bool
- catalog(root, token=None) -> dict {"packages": [...]}

Each package object:
{ name, version, purl, language, type, sourcePath, license, description, vulnerabilities, hashes }
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.catalogers.base import BaseCataloger


class NpmCataloger(BaseCataloger):
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "javascript"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name."""
        return "npm"

    def detect(self, root: Path) -> bool:
        """Check if this is a Node.js project."""
        # Check for package.json, package-lock.json, yarn.lock, or pnpm-lock.yaml
        return (
            (root / "package.json").exists() or 
            (root / "package-lock.json").exists() or
            (root / "yarn.lock").exists() or
            (root / "pnpm-lock.yaml").exists()
        )

    def catalog(self, repo_root: str, token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse npm/Node.js manifests and extract DIRECT dependencies only.
        
        This method ONLY parses manifest files (package.json, package-lock.json, etc.)
        to extract direct dependencies. NO enrichment or transitive resolution happens here.
        
        The flow is:
        - /discover_and_parse → Parse manifests (THIS METHOD) → Direct dependencies only
        - /fetch_depsdev → Enrich with metadata + Resolve transitive dependencies
        - /fetch_osv → Fetch vulnerabilities
        """
        root = Path(repo_root)
        print("[INFO] Detected Node.js project. Parsing manifests for DIRECT dependencies...")
        manifests: List[Path] = []
        for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            for p in root.rglob(name):
                manifests.append(p)
                print(f"   • Found manifest: {p}")

        packages: List[Dict[str, Any]] = []

        for m in manifests:
            if m.name == "package.json":
                packages.extend(self._parse_package_json(m))
            elif m.name == "package-lock.json":
                packages.extend(self._parse_package_lock(m))
            elif m.name == "yarn.lock":
                packages.extend(self._parse_yarn_lock(m))
            elif m.name == "pnpm-lock.yaml":
                packages.extend(self._parse_pnpm_lock(m))

        # dedupe
        seen: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            seen[p["name"].lower()] = p
        packages = list(seen.values())

        print(f"[INFO] Found {len(packages)} DIRECT dependencies from manifests")

        # Set basic fields for each package (NO enrichment - that happens in /fetch_depsdev)
        for pkg in packages:
            name = pkg.get("name")
            if not name:
                continue
            
            # Set language
            pkg["language"] = "javascript"
            pkg["type"] = "library"
            
            # Normalize purl
            ver = pkg.get("version") or ""
            pkg["purl"] = pkg.get("purl") or f"pkg:npm/{name}@{ver}"
            
            # Mark as direct dependency (from manifest/lock file)
            pkg["is_direct_dependency"] = True
            
            # Ensure scope field exists (default to "required")
            pkg.setdefault("scope", "required")
            
            # Add CERT-21 field placeholders (will be filled by /fetch_depsdev and /registry_enrich)
            pkg.setdefault("component_name", pkg.get("name"))
            pkg.setdefault("component_version", pkg.get("version") or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        # Return direct dependencies only - NO transitive, NO enrichment
        return {"packages": packages, "manifests": [str(p) for p in manifests]}
    
    # ---------- helpers ----------
    def _parse_package_json(self, path: Path) -> List[Dict[str, Any]]:
        out = []
        try:
            content = path.read_text(encoding="utf-8")
            j = json.loads(content)
            
            # NOTE: We intentionally DO NOT add the root package (project itself) to the SBOM.
            # The root package is the project being scanned, not a dependency.
            # Only the declared dependencies should be included in the SBOM.
            root_name = j.get("name")  # Save for reference if needed
            
            deps = j.get("dependencies", {}) or {}
            dev_deps = j.get("devDependencies", {}) or {}
            
            print(f"   Found {len(deps)} dependencies + {len(dev_deps)} devDependencies in {path}")
            
            # Parse production dependencies
            for name, ver in deps.items():
                version_constraint = ver if isinstance(ver, str) else ""
                clean_ver = ver
                if isinstance(ver, str):
                    clean_ver = re.sub(r"^[\\^~=<> ]+", "", ver)
                
                out.append({
                    "name": name,
                    "version": clean_ver,
                    "version_constraint": version_constraint,
                    "language": "javascript",
                    "type": "library",
                    "purl": f"pkg:npm/{name}@{clean_ver}",
                    "sourcePath": str(path),
                    "scope": "required"  # Production dependency
                })
            
            # Parse dev dependencies
            for name, ver in dev_deps.items():
                version_constraint = ver if isinstance(ver, str) else ""
                clean_ver = ver
                if isinstance(ver, str):
                    clean_ver = re.sub(r"^[\\^~=<> ]+", "", ver)
                
                out.append({
                    "name": name,
                    "version": clean_ver,
                    "version_constraint": version_constraint,
                    "language": "javascript",
                    "type": "library",
                    "purl": f"pkg:npm/{name}@{clean_ver}",
                    "sourcePath": str(path),
                    "scope": "dev"  # Development dependency
                })
        except Exception as e:
            print(f"   Failed to parse package.json {path}: {e}")
        return out

    def _parse_package_lock(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse package-lock.json supporting v1, v2, and v3 formats.
        Extracts exact versions and dependency relationships.
        """
        out = []
        try:
            j = json.loads(path.read_text(encoding="utf-8"))
            lockfile_version = j.get("lockfileVersion", 1)
            
            # v2/v3 format uses "packages" key
            if "packages" in j and lockfile_version >= 2:
                packages_data = j.get("packages", {})
                for pkg_path, pkg_info in packages_data.items():
                    # Skip root package (empty string key)
                    if not pkg_path:
                        continue
                    
                    # Extract package name from path (strip "node_modules/")
                    name = pkg_path.replace("node_modules/", "")
                    version = pkg_info.get("version", "UNKNOWN")
                    
                    # Extract dependencies
                    deps = list(pkg_info.get("dependencies", {}).keys())
                    
                    # Extract hashes from integrity field
                    hashes = []
                    integrity = pkg_info.get("integrity", "")
                    if integrity:
                        if integrity.startswith("sha512-"):
                            hashes.append({
                                "alg": "SHA-512",
                                "content": integrity[7:]  # Remove 'sha512-' prefix
                            })
                        elif integrity.startswith("sha1-"):
                            hashes.append({
                                "alg": "SHA-1",
                                "content": integrity[5:]  # Remove 'sha1-' prefix
                            })
                        elif integrity.startswith("sha256-"):
                            hashes.append({
                                "alg": "SHA-256",
                                "content": integrity[7:]  # Remove 'sha256-' prefix
                            })
                    
                    out.append({
                        "name": name,
                        "version": version,
                        "language": "javascript",
                        "type": "library",
                        "purl": f"pkg:npm/{name}@{version}",
                        "sourcePath": str(path),
                        "dependencies": deps,  # List of dependency names
                        "resolved": pkg_info.get("resolved", ""),
                        "hashes": hashes  # Properly formatted hashes
                    })
            
            # v1 format uses "dependencies" key with nested structure
            elif "dependencies" in j:
                def flatten_deps(deps_dict, parent_path=""):
                    for name, info in deps_dict.items():
                        ver = info.get("version", "UNKNOWN")
                        requires = list(info.get("requires", {}).keys())
                        
                        # Extract hashes from integrity field
                        hashes = []
                        integrity = info.get("integrity", "")
                        if integrity:
                            if integrity.startswith("sha512-"):
                                hashes.append({"alg": "SHA-512", "content": integrity[7:]})
                            elif integrity.startswith("sha1-"):
                                hashes.append({"alg": "SHA-1", "content": integrity[5:]})
                            elif integrity.startswith("sha256-"):
                                hashes.append({"alg": "SHA-256", "content": integrity[7:]})
                        
                        out.append({
                            "name": name,
                            "version": ver,
                            "language": "javascript",
                            "type": "library",
                            "purl": f"pkg:npm/{name}@{ver}",
                            "sourcePath": str(path),
                            "dependencies": requires,
                            "resolved": info.get("resolved", ""),
                            "hashes": hashes
                        })
                        
                        # Recursively flatten nested dependencies
                        if "dependencies" in info:
                            flatten_deps(info["dependencies"], f"{parent_path}/{name}")
                
                flatten_deps(j.get("dependencies", {}))
        
        except Exception as e:
            print(f"   [WARN] Failed to parse package-lock.json {path}: {e}")
        
        return out

    def _parse_yarn_lock(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse yarn.lock file (Yarn v1 format).
        
        Format example:
        ```
        package-name@^1.0.0:
          version "1.0.5"
          resolved "https://registry.yarnpkg.com/package-name/-/package-name-1.0.5.tgz#abc123"
          integrity sha512-...
          dependencies:
            dep1 "^2.0.0"
            dep2 "^3.1.0"
        ```
        """
        out = []
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"   [WARN] Failed to read yarn.lock {path}: {e}")
            return out
        
        # State machine for parsing
        current_pkg = {}
        current_deps = []
        in_dependencies = False
        
        for line in text.splitlines():
            # Package header (e.g., "package@^1.0.0:")
            if line and not line.startswith(" ") and line.endswith(":"):
                # Save previous package if exists
                if current_pkg.get("name"):
                    current_pkg["dependencies"] = current_deps
                    out.append(current_pkg)
                
                # Start new package
                # Extract name from "name@version:" or "name@version, name@version2:"
                pkg_spec = line.rstrip(":")
                # Handle multiple version specs: "pkg@^1.0.0, pkg@^2.0.0:"
                first_spec = pkg_spec.split(",")[0].strip()
                if "@" in first_spec:
                    # Split on last @ to handle scoped packages like @babel/core@^7.0.0
                    parts = first_spec.rsplit("@", 1)
                    pkg_name = parts[0].strip('"')
                    current_pkg = {
                        "name": pkg_name,
                        "version": "UNKNOWN",
                        "language": "javascript",
                        "type": "library",
                        "sourcePath": str(path),
                        "resolved": "",
                        "hashes": []
                    }
                    current_deps = []
                    in_dependencies = False
                continue
            
            # Indented properties (2 spaces)
            if line.startswith("  ") and not line.startswith("    "):
                line_stripped = line.strip()
                
                # version "1.0.5"
                if line_stripped.startswith('version "'):
                    version = line_stripped.split('"')[1]
                    current_pkg["version"] = version
                    current_pkg["purl"] = f"pkg:npm/{current_pkg['name']}@{version}"
                
                # resolved "https://..."
                elif line_stripped.startswith('resolved "'):
                    resolved = line_stripped.split('"')[1]
                    current_pkg["resolved"] = resolved
                
                # integrity sha512-...
                elif line_stripped.startswith('integrity sha'):
                    integrity = line_stripped.split(None, 1)[1].strip('"')
                    if integrity.startswith("sha512-"):
                        current_pkg["hashes"].append({
                            "alg": "SHA-512",
                            "content": integrity[7:]
                        })
                    elif integrity.startswith("sha1-"):
                        current_pkg["hashes"].append({
                            "alg": "SHA-1",
                            "content": integrity[5:]
                        })
                    elif integrity.startswith("sha256-"):
                        current_pkg["hashes"].append({
                            "alg": "SHA-256",
                            "content": integrity[7:]
                        })
                
                # dependencies:
                elif line_stripped == "dependencies:":
                    in_dependencies = True
                
                # optionalDependencies: or other section
                elif line_stripped.endswith(":") and not line_stripped.startswith('"'):
                    in_dependencies = False
            
            # Dependency entries (4 spaces indentation)
            elif line.startswith("    ") and in_dependencies:
                line_stripped = line.strip()
                if '"' in line_stripped:
                    # Format: "dep-name" "^1.0.0" or dep-name "^1.0.0"
                    # Extract first quoted string
                    parts = line_stripped.split('"')
                    if len(parts) >= 2:
                        dep_name = parts[1] if parts[0] == '' else parts[0]
                        if dep_name:
                            current_deps.append(dep_name)
        
        # Don't forget last package
        if current_pkg.get("name"):
            current_pkg["dependencies"] = current_deps
            out.append(current_pkg)
        
        return out

    def _parse_pnpm_lock(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse pnpm-lock.yaml supporting v5.x, v6.x, and v9.x formats.
        
        Format:
        v6.0+:
        ```yaml
        lockfileVersion: '6.0'
        packages:
          /express@4.18.2:
            resolution:
              integrity: sha512-...
            dependencies:
              accepts: 1.3.8
        ```
        
        v5.x:
        ```yaml
        lockfileVersion: 5.4
        packages:
          /express/4.18.2:
            resolution:
              integrity: sha512-...
        ```
        """
        out = []
        try:
            import yaml
            text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(text)
            
            if not data:
                print(f"   [WARN] Empty pnpm-lock.yaml {path}")
                return out
            
            # Get lockfile version
            lockfile_version = str(data.get("lockfileVersion", "5.0"))
            print(f"   Parsing pnpm-lock.yaml (version {lockfile_version})")
            
            # v6.0+ or v9.x format
            if lockfile_version.startswith("6") or lockfile_version.startswith("9"):
                out = self._parse_pnpm_v6(data, path)
            # v5.x format
            elif lockfile_version.startswith("5"):
                out = self._parse_pnpm_v5(data, path)
            else:
                print(f"   [WARN] Unknown pnpm lockfile version: {lockfile_version}")
                # Try v6 format as default
                out = self._parse_pnpm_v6(data, path)
            
            print(f"   Found {len(out)} packages in pnpm-lock.yaml")
            
        except ImportError:
            print(f"   [ERROR] PyYAML not installed. Cannot parse pnpm-lock.yaml")
            print(f"   Install with: pip install PyYAML")
        except Exception as e:
            print(f"   [WARN] Failed to parse pnpm-lock.yaml {path}: {e}")
        
        return out

    def _parse_pnpm_v6(self, data: dict, path: Path) -> List[Dict[str, Any]]:
        """
        Parse pnpm-lock.yaml v6.0+ format.
        
        Format:
        packages:
          /express@4.18.2:
            resolution: { integrity: sha512-... }
            dependencies:
              accepts: 1.3.8
          /@babel/core@7.23.0:
            resolution: { integrity: sha512-... }
        """
        out = []
        packages_data = data.get("packages", {})
        
        for pkg_key, pkg_info in packages_data.items():
            # Format: "/express@4.18.2" or "/@babel/core@7.23.0"
            # Strip leading "/"
            if not pkg_key.startswith("/"):
                continue
            
            pkg_key = pkg_key[1:]  # Remove leading "/"
            
            # Parse name and version
            # Handle scoped packages: @babel/core@7.23.0
            # Handle regular packages: express@4.18.2
            if pkg_key.startswith("@"):
                # Scoped package: @babel/core@7.23.0
                # Split on last @ to separate version
                parts = pkg_key.rsplit("@", 1)
                if len(parts) == 2:
                    name = parts[0]
                    version = parts[1]
                else:
                    continue
            else:
                # Regular package: express@4.18.2
                if "@" in pkg_key:
                    name, version = pkg_key.rsplit("@", 1)
                else:
                    continue
            
            # Extract dependencies
            deps = []
            if isinstance(pkg_info.get("dependencies"), dict):
                deps = list(pkg_info["dependencies"].keys())
            
            # Extract hashes from resolution.integrity
            hashes = []
            resolution = pkg_info.get("resolution", {})
            if isinstance(resolution, dict):
                integrity = resolution.get("integrity", "")
                if integrity:
                    hashes = self._parse_integrity(integrity)
            
            # Check if dev dependency
            is_dev = pkg_info.get("dev", False)
            
            out.append({
                "name": name,
                "version": version,
                "language": "javascript",
                "type": "library",
                "purl": f"pkg:npm/{name}@{version}",
                "sourcePath": str(path),
                "dependencies": deps,
                "hashes": hashes,
                "dev": is_dev
            })
        
        return out

    def _parse_pnpm_v5(self, data: dict, path: Path) -> List[Dict[str, Any]]:
        """
        Parse pnpm-lock.yaml v5.x format.
        
        Format:
        packages:
          /express/4.18.2:
            resolution: { integrity: sha512-... }
          /@babel/core/7.23.0:
            resolution: { integrity: sha512-... }
        """
        out = []
        packages_data = data.get("packages", {})
        
        for pkg_path, pkg_info in packages_data.items():
            # Format: "/express/4.18.2" or "/@babel/core/7.23.0"
            if not pkg_path.startswith("/"):
                continue
            
            parts = pkg_path[1:].split("/")  # Remove leading "/" and split
            
            # Parse name and version
            if len(parts) >= 2:
                if parts[0].startswith("@"):
                    # Scoped package: ["@babel", "core", "7.23.0"]
                    if len(parts) >= 3:
                        name = f"{parts[0]}/{parts[1]}"
                        version = parts[2]
                    else:
                        continue
                else:
                    # Regular package: ["express", "4.18.2"]
                    name = parts[0]
                    version = parts[1]
            else:
                continue
            
            # Extract dependencies
            deps = []
            if isinstance(pkg_info.get("dependencies"), dict):
                deps = list(pkg_info["dependencies"].keys())
            
            # Extract hashes
            hashes = []
            resolution = pkg_info.get("resolution", {})
            if isinstance(resolution, dict):
                integrity = resolution.get("integrity", "")
                if integrity:
                    hashes = self._parse_integrity(integrity)
            
            # Check if dev dependency
            is_dev = pkg_info.get("dev", False)
            
            out.append({
                "name": name,
                "version": version,
                "language": "javascript",
                "type": "library",
                "purl": f"pkg:npm/{name}@{version}",
                "sourcePath": str(path),
                "dependencies": deps,
                "hashes": hashes,
                "dev": is_dev
            })
        
        return out

    def _parse_integrity(self, integrity: str) -> List[Dict[str, str]]:
        """
        Parse integrity field from lock files.
        Supports SHA-512, SHA-256, and SHA-1.
        
        Examples:
        - sha512-abc123...
        - sha256-def456...
        - sha1-ghi789...
        """
        hashes = []
        
        if not integrity:
            return hashes
        
        if integrity.startswith("sha512-"):
            hashes.append({
                "alg": "SHA-512",
                "content": integrity[7:]  # Remove 'sha512-' prefix
            })
        elif integrity.startswith("sha256-"):
            hashes.append({
                "alg": "SHA-256",
                "content": integrity[7:]  # Remove 'sha256-' prefix
            })
        elif integrity.startswith("sha1-"):
            hashes.append({
                "alg": "SHA-1",
                "content": integrity[5:]  # Remove 'sha1-' prefix
            })
        
        return hashes
