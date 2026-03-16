"""
src/catalogers/go_cataloger.py

GoCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Supported manifest files:
- go.mod (Go modules - modern, primary)
- go.sum (checksums for go.mod dependencies)
- Gopkg.toml / Gopkg.lock (dep tool - legacy)
- vendor/modules.txt (vendored dependencies)

Each package dict contains (best-effort):
{
  "name", "version", "purl", "language", "type", "sourcePath"
}

Notes:
- This cataloger ONLY parses manifests for direct dependencies.
- Metadata/vulnerability enrichment happens later in the pipeline.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# tomllib compatibility for Python < 3.11 (for Gopkg.toml)
try:
    import tomllib  # type: ignore
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore

from sbom.src.catalogers.base import BaseCataloger


class GoCataloger(BaseCataloger):
    """Cataloger for Go projects supporting modern go.mod and legacy dep tool."""
    
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "go"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name."""
        return "Go"

    # -------------------------
    def detect(self, root: str) -> bool:
        """Return True if Go manifest files exist under root."""
        rootp = Path(root)
        # Check for modern go.mod first (most common)
        if list(rootp.rglob("go.mod")):
            return True
        # Check for legacy dep tool
        if list(rootp.rglob("Gopkg.toml")) or list(rootp.rglob("Gopkg.lock")):
            return True
        # Check for vendored modules
        if list(rootp.rglob("vendor/modules.txt")):
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
        Parse Go manifests and extract dependencies.
        """
        try:
            return self._catalog_internal(repo_root)
        except Exception as e:
            print(f"[ERROR] Go cataloger failed: {e}")
            import traceback
            traceback.print_exc()
            return {"packages": [], "manifests": []}

    def _catalog_internal(self, repo_root: str) -> Dict[str, Any]:
        root = Path(repo_root)
        print("[INFO] Detected Go project. Parsing manifests for dependencies...")

        manifests: List[Path] = []
        packages: List[Dict[str, Any]] = []
        
        # Collect all manifest files
        manifest_names = ["go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock"]
        for name in manifest_names:
            for p in root.rglob(name):
                if self._should_skip_path(p, root):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                manifests.append(p)
                print(f"   * Found manifest: {p}")
        
        # Check for vendor/modules.txt
        for p in root.rglob("vendor/modules.txt"):
            if self._should_skip_path(p, root):
                continue
            manifests.append(p)
            print(f"   * Found manifest: {p}")

        # Track go.sum hashes for enrichment
        go_sum_hashes: Dict[str, str] = {}

        # Parse manifests in priority order
        for m in manifests:
            nm = m.name.lower()
            if nm == "go.mod":
                packages.extend(self._parse_go_mod(m))
            elif nm == "go.sum":
                # Parse go.sum for hashes, associate with packages later
                go_sum_hashes.update(self._parse_go_sum(m))
            elif nm == "gopkg.toml":
                packages.extend(self._parse_gopkg_toml(m))
            elif nm == "gopkg.lock":
                packages.extend(self._parse_gopkg_lock(m))
            elif nm == "modules.txt":
                packages.extend(self._parse_vendor_modules(m))

        # Deduplicate by module name (keep first occurrence with version)
        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            name = p.get("name")
            if not name:
                continue
            key = name.lower()
            if key not in dedup or (not dedup[key].get("version") and p.get("version")):
                dedup[key] = p
        packages = list(dedup.values())

        # Enrich packages with hashes from go.sum
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            hash_key = f"{name}@{version}"
            if hash_key in go_sum_hashes:
                pkg["hashes"] = [{"alg": "SHA-256", "content": go_sum_hashes[hash_key]}]

        print(f"[INFO] Found {len(packages)} Go dependencies from manifests")

        # Determine if we have go.sum (acts as lock file with hashes)
        has_lock_file = len(go_sum_hashes) > 0
        if has_lock_file:
            print(f"[INFO] Found {len(go_sum_hashes)} entries in go.sum (checksums)")

        # Build lock_data: {pkg_name: {version, hashes, dependencies}}
        lock_data: Dict[str, Dict[str, Any]] = {}
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and pkg.get("hashes"):
                key = name.lower()
                if key not in lock_data:
                    lock_data[key] = {
                        "version": version,
                        "hashes": pkg.get("hashes", []),
                        "dependencies": pkg.get("dependencies", [])
                    }
        if lock_data:
            print(f"[INFO] Collected {len(lock_data)} packages in lock_data for transitive resolution")

        # Set common fields
        for pkg in packages:
            name = pkg.get("name")
            if not name:
                continue

            pkg["language"] = "go"
            pkg["type"] = "library"
            pkg["is_direct_dependency"] = pkg.get("is_direct_dependency", True)
            pkg.setdefault("scope", "required")

            version = pkg.get("version") or ""
            
            # Version resolution fields
            # go.mod always has exact versions (no ranges in Go)
            if version:
                pkg["version_resolved"] = True
                pkg["version_source"] = "manifest"  # go.mod has exact versions
            else:
                pkg["version_resolved"] = False
                pkg["version_source"] = "unknown"
                pkg["version_warning"] = "Version not found in go.mod"
            
            # If we have hash from go.sum, mark as verified
            if pkg.get("hashes"):
                pkg["version_source"] = "lock_file"  # go.sum provides verification
            
            # Go PURLs use golang type and encode the module path
            pkg["purl"] = pkg.get("purl") or self._build_go_purl(name, version)

            # Extract short package name from full module path
            # e.g., "github.com/gin-gonic/gin" -> "gin"
            # e.g., "go.uber.org/zap" -> "zap"
            short_name = self._extract_short_name(name)
            pkg.setdefault("component_name", short_name)
            pkg["module_path"] = name  # Keep full path for reference
            pkg.setdefault("component_version", version or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])

        return {
            "packages": packages,
            "manifests": [str(m) for m in manifests],
            "has_lock_file": has_lock_file,
            "lock_data": lock_data
        }

    # -------------------------
    # go.mod Parser
    # -------------------------
    def _parse_go_mod(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse go.mod file for dependencies.
        
        Format:
            module github.com/user/myapp
            
            go 1.21
            
            require (
                github.com/gin-gonic/gin v1.9.1
                golang.org/x/text v0.14.0
            )
            
            require github.com/single/dep v1.0.0 // indirect
            
            replace github.com/old/pkg => github.com/new/pkg v2.0.0
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        # Track replacements
        replacements: Dict[str, Tuple[str, str]] = {}
        
        # Parse replace directives first
        # Single-line: replace old => new v1.0.0
        # Block: replace ( ... )
        replace_single = re.findall(
            r'replace\s+([\w./-]+)(?:\s+[\w./-]+)?\s+=>\s+([\w./-]+)\s+(v[\w.\-+]+)?',
            content
        )
        for old, new, ver in replace_single:
            replacements[old] = (new, ver or "")

        # Parse replace blocks
        replace_block = re.search(r'replace\s*\((.*?)\)', content, re.DOTALL)
        if replace_block:
            for line in replace_block.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                match = re.match(r'([\w./-]+)(?:\s+[\w./-]+)?\s+=>\s+([\w./-]+)\s+(v[\w.\-+]+)?', line)
                if match:
                    old, new, ver = match.groups()
                    replacements[old] = (new, ver or "")

        # Parse require directives
        # Single-line: require module/path v1.0.0
        require_single = re.findall(
            r'^require\s+([\w./-]+)\s+(v[\w.\-+]+)(?:\s*//\s*(indirect))?',
            content,
            re.MULTILINE
        )
        for mod, ver, indirect in require_single:
            is_direct = indirect != "indirect"
            # Apply replacement if exists
            if mod in replacements:
                new_mod, new_ver = replacements[mod]
                mod = new_mod
                if new_ver:
                    ver = new_ver
            
            packages.append({
                "name": mod,
                "version": self._clean_version(ver),
                "sourcePath": str(path),
                "is_direct_dependency": is_direct,
                "dependencies": [],
            })

        # Parse require blocks (use findall to catch ALL require blocks — direct + indirect)
        require_blocks = re.findall(r'require\s*\((.*?)\)', content, re.DOTALL)
        for block_content in require_blocks:
            for line in block_content.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                # Match: module/path v1.0.0 // indirect
                match = re.match(r'([\w./-]+)\s+(v[\w.\-+]+)(?:\s*//\s*(indirect))?', line)
                if match:
                    mod, ver, indirect = match.groups()
                    is_direct = indirect != "indirect"
                    # Apply replacement if exists
                    if mod in replacements:
                        new_mod, new_ver = replacements[mod]
                        mod = new_mod
                        if new_ver:
                            ver = new_ver
                    
                    packages.append({
                        "name": mod,
                        "version": self._clean_version(ver),
                        "sourcePath": str(path),
                        "is_direct_dependency": is_direct,
                        "dependencies": [],
                    })

        return packages

    # -------------------------
    # go.sum Parser
    # -------------------------
    def _parse_go_sum(self, path: Path) -> Dict[str, str]:
        """
        Parse go.sum file for checksums.
        
        Format:
            github.com/gin-gonic/gin v1.9.1 h1:abc123...
            github.com/gin-gonic/gin v1.9.1/go.mod h1:xyz789...
        
        Returns:
            Dict mapping "module@version" -> hash
        """
        hashes: Dict[str, str] = {}
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return hashes

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            
            # Match: module version hash
            # We prefer the non-/go.mod entry
            parts = line.split()
            if len(parts) >= 3:
                mod = parts[0]
                ver = parts[1]
                hash_val = parts[2]
                
                # Skip /go.mod entries, prefer source hash
                if "/go.mod" in ver:
                    ver = ver.replace("/go.mod", "")
                    # Only use go.mod hash if we don't have source hash
                    key = f"{mod}@{self._clean_version(ver)}"
                    if key not in hashes:
                        # Extract just the hash part after h1:
                        if hash_val.startswith("h1:"):
                            hashes[key] = hash_val[3:]
                else:
                    key = f"{mod}@{self._clean_version(ver)}"
                    if hash_val.startswith("h1:"):
                        hashes[key] = hash_val[3:]

        return hashes

    # -------------------------
    # Gopkg.toml Parser (legacy dep tool)
    # -------------------------
    def _parse_gopkg_toml(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Gopkg.toml (dep tool) for dependencies.
        
        Format (TOML):
            [[constraint]]
            name = "github.com/user/pkg"
            version = "1.0.0"
            
            [[override]]
            name = "github.com/other/pkg"
            revision = "abc123"
        """
        packages: List[Dict[str, Any]] = []
        
        if tomllib is None:
            print(f"[WARN] tomllib/tomli not available, skipping {path}")
            return packages
        
        try:
            content = path.read_bytes()
            data = tomllib.loads(content.decode("utf-8"))
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        # Parse [[constraint]] sections
        for constraint in data.get("constraint", []):
            name = constraint.get("name", "")
            if not name:
                continue
            
            version = constraint.get("version", "") or constraint.get("branch", "") or constraint.get("revision", "")
            
            packages.append({
                "name": name,
                "version": self._clean_version(version),
                "sourcePath": str(path),
                "is_direct_dependency": True,
                "dependencies": [],
            })

        # Parse [[override]] sections (still dependencies, just overridden versions)
        for override in data.get("override", []):
            name = override.get("name", "")
            if not name:
                continue
            
            version = override.get("version", "") or override.get("branch", "") or override.get("revision", "")
            
            packages.append({
                "name": name,
                "version": self._clean_version(version),
                "sourcePath": str(path),
                "is_direct_dependency": True,
                "is_override": True,
                "dependencies": [],
            })

        return packages

    # -------------------------
    # Gopkg.lock Parser (legacy dep tool)
    # -------------------------
    def _parse_gopkg_lock(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Gopkg.lock (dep tool) for resolved dependencies.
        
        Format (TOML):
            [[projects]]
            name = "github.com/user/pkg"
            version = "v1.0.0"
            revision = "abc123def456"
        """
        packages: List[Dict[str, Any]] = []
        
        if tomllib is None:
            print(f"[WARN] tomllib/tomli not available, skipping {path}")
            return packages
        
        try:
            content = path.read_bytes()
            data = tomllib.loads(content.decode("utf-8"))
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        # Parse [[projects]] sections
        for project in data.get("projects", []):
            name = project.get("name", "")
            if not name:
                continue
            
            # Prefer version over revision
            version = project.get("version", "") or project.get("revision", "")
            
            packages.append({
                "name": name,
                "version": self._clean_version(version),
                "sourcePath": str(path),
                "is_direct_dependency": False,  # Lock file contains all deps
                "revision": project.get("revision", ""),
                "dependencies": [],
            })

        return packages

    # -------------------------
    # vendor/modules.txt Parser
    # -------------------------
    def _parse_vendor_modules(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse vendor/modules.txt for vendored dependencies.
        
        Format:
            # github.com/gin-gonic/gin v1.9.1
            ## explicit; go 1.18
            github.com/gin-gonic/gin
            github.com/gin-gonic/gin/binding
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        current_module = None
        current_version = None
        is_explicit = False

        for line in content.splitlines():
            line = line.strip()
            
            # Module header: # module/path version
            if line.startswith("# "):
                parts = line[2:].split()
                if len(parts) >= 2:
                    current_module = parts[0]
                    current_version = parts[1]
                    is_explicit = False
                elif len(parts) == 1:
                    current_module = parts[0]
                    current_version = ""
                    is_explicit = False
            # Explicit marker
            elif line.startswith("## explicit"):
                is_explicit = True
                if current_module:
                    packages.append({
                        "name": current_module,
                        "version": self._clean_version(current_version or ""),
                        "sourcePath": str(path),
                        "is_direct_dependency": is_explicit,
                        "vendored": True,
                        "dependencies": [],
                    })
                    current_module = None
                    current_version = None
            # Skip package lines (subpackages)
            elif line and not line.startswith("#"):
                continue

        return packages

    # -------------------------
    # Utility Methods
    # -------------------------
    def _clean_version(self, version: str) -> str:
        """
        Clean version string.
        
        Examples:
            "v1.2.3" -> "1.2.3"
            "v1.2.3+incompatible" -> "1.2.3"
            "v0.0.0-20210101000000-abcdef123456" -> "0.0.0-20210101000000-abcdef123456"
        """
        if not version:
            return ""
        
        version = version.strip()
        
        # Remove leading 'v'
        if version.startswith("v"):
            version = version[1:]
        
        # Remove +incompatible suffix
        if "+incompatible" in version:
            version = version.replace("+incompatible", "")
        
        return version

    def _build_go_purl(self, module: str, version: str) -> str:
        """
        Build a PURL for a Go module.
        
        Go PURLs use type 'golang' and URL-encode the module path.
        
        Examples:
            github.com/gin-gonic/gin @ 1.9.1
            -> pkg:golang/github.com/gin-gonic/gin@1.9.1
        """
        import urllib.parse
        
        # URL-encode the module path (but preserve slashes for readability in some tools)
        # PURL spec says namespace/name should be encoded
        encoded_module = urllib.parse.quote(module, safe="")
        
        if version:
            return f"pkg:golang/{encoded_module}@{version}"
        else:
            return f"pkg:golang/{encoded_module}"

    def _extract_short_name(self, module_path: str) -> str:
        """
        Extract short package name from full Go module path.
        
        Examples:
            github.com/gin-gonic/gin -> gin
            go.uber.org/zap -> zap
            github.com/go-redis/redis/v8 -> redis
            github.com/jackc/pgx/v5 -> pgx
            golang.org/x/text -> text
        """
        if not module_path:
            return module_path
        
        # Split by /
        parts = module_path.split("/")
        
        # Get the last meaningful part
        short_name = parts[-1]
        
        # If last part is a version indicator like v8, v5, use second-to-last
        if re.match(r'^v\d+$', short_name) and len(parts) > 1:
            short_name = parts[-2]
        
        return short_name
