"""
src/catalogers/ruby_cataloger.py

RubyCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Supported manifest/lock files:
- Gemfile.lock (lock file - exact versions, prioritized)
- Gemfile (manifest - may have version constraints)
- *.gemspec (gem specification files)

Each package dict contains:
{
  "name", "version", "purl", "language", "type", "sourcePath",
  "version_resolved", "version_source", "version_warning" (if applicable),
  "is_direct_dependency"
}

Notes:
- Gemfile.lock is prioritized for exact versions.
- Gemfile can have version constraints like "~> 2.0", ">= 1.0".
- Metadata/vulnerability enrichment happens later in the pipeline.
- deps.dev ecosystem: RUBYGEMS
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from sbom.src.catalogers.base import BaseCataloger


class RubyCataloger(BaseCataloger):
    """Cataloger for Ruby/RubyGems projects."""
    
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "ruby"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name for OSV."""
        return "RubyGems"

    # -------------------------
    def detect(self, root: str) -> bool:
        """Return True if Ruby/RubyGems manifest files exist under root."""
        rootp = Path(root)
        
        # Check for Gemfile or Gemfile.lock
        if (rootp / "Gemfile").exists() or (rootp / "Gemfile.lock").exists():
            return True
        
        # Check for *.gemspec files
        if any(rootp.glob("*.gemspec")):
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
        Parse Ruby manifests and extract dependencies.
        
        Priority: Gemfile.lock (exact versions) > Gemfile (constraints) > *.gemspec
        """
        root = Path(repo_root)
        print("[INFO] Detected Ruby project. Parsing manifests for dependencies...")
        
        # Track all found manifests
        manifests: List[str] = []
        lock_versions: Dict[str, Dict[str, Any]] = {}  # name -> {version, source, checksum, ...}
        has_lock_file = False
        
        # Step 1: Parse Gemfile.lock first (exact versions)
        lock_file = root / "Gemfile.lock"
        if lock_file.exists() and not self._should_skip_path(lock_file, root):
            print(f"   * Found LOCK file: {lock_file}")
            manifests.append(str(lock_file))
            has_lock_file = True
            lock_versions = self._parse_gemfile_lock(lock_file)
            print(f"   Parsed {len(lock_versions)} dependencies from Gemfile.lock")
            for name, info in list(lock_versions.items())[:15]:
                print(f"      [LOCK] {name} = {info.get('version', 'N/A')}")
            if len(lock_versions) > 15:
                print(f"      ... and {len(lock_versions) - 15} more")
            print(f"[INFO] Found {len(lock_versions)} packages in Gemfile.lock (exact versions)")
        
        # Step 2: Parse Gemfile for direct dependencies
        gemfile = root / "Gemfile"
        direct_deps: Set[str] = set()
        gemfile_deps: Dict[str, str] = {}  # name -> constraint
        
        if gemfile.exists() and not self._should_skip_path(gemfile, root):
            print(f"   * Found manifest: {gemfile}")
            manifests.append(str(gemfile))
            gemfile_deps, direct_deps = self._parse_gemfile(gemfile)
            print(f"   Parsed {len(gemfile_deps)} dependencies from Gemfile")

        # Fallback: if Gemfile is absent, extract direct deps from lock file DEPENDENCIES section
        if has_lock_file and not direct_deps:
            direct_deps = self._get_lock_direct_deps(lock_file)
            if direct_deps:
                print(f"   [INFO] {len(direct_deps)} direct deps found in Gemfile.lock DEPENDENCIES section")

        # Step 3: Parse *.gemspec files
        for gemspec in root.glob("*.gemspec"):
            if self._should_skip_path(gemspec, root):
                continue
            print(f"   * Found manifest: {gemspec}")
            manifests.append(str(gemspec))
            gemspec_deps = self._parse_gemspec(gemspec)
            print(f"   Parsed {len(gemspec_deps)} dependencies from {gemspec.name}")
            # Gemspec dependencies are direct
            for name in gemspec_deps:
                direct_deps.add(name)
                if name not in gemfile_deps:
                    gemfile_deps[name] = gemspec_deps[name]
        
        # Step 4: Build final package list
        packages: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        
        # If we have a lock file, use it as the source of truth
        if has_lock_file:
            for name, lock_info in lock_versions.items():
                if name in seen:
                    continue
                seen.add(name)
                
                version = lock_info.get("version", "UNKNOWN")
                is_direct = name in direct_deps
                
                # Build structured dependency list from lock file's SPECS tree
                raw_deps = lock_info.get("dependencies", [])
                deps = []
                for dep_name in raw_deps:
                    dep_ver = lock_versions.get(dep_name, {}).get("version", "")
                    deps.append({
                        "name": dep_name,
                        "version_constraint": dep_ver or "",
                        "purl": f"pkg:gem/{dep_name}@{dep_ver}" if dep_ver else f"pkg:gem/{dep_name}",
                    })

                pkg = {
                    "name": name,
                    "version": version,
                    "purl": f"pkg:gem/{name}@{version}" if version != "UNKNOWN" else f"pkg:gem/{name}",
                    "language": "ruby",
                    "type": "library",
                    "sourcePath": str(lock_file),
                    "version_resolved": True,
                    "version_source": "lock_file",
                    "is_direct_dependency": is_direct,
                    "dependencies": deps,
                }
                
                # Add source info if available
                if lock_info.get("source"):
                    pkg["source"] = lock_info["source"]
                
                packages.append(pkg)
        else:
            # No lock file - use Gemfile/gemspec with warnings
            print("[WARN] No Gemfile.lock found - versions from manifests may be constraints")
            for name, constraint in gemfile_deps.items():
                if name in seen:
                    continue
                seen.add(name)
                
                # Try to extract version from constraint
                version, is_exact = self._extract_version_from_constraint(constraint)
                
                pkg = {
                    "name": name,
                    "version": version,
                    "purl": f"pkg:gem/{name}@{version}" if version != "UNKNOWN" else f"pkg:gem/{name}",
                    "language": "ruby",
                    "type": "library",
                    "sourcePath": str(gemfile) if gemfile.exists() else str(root),
                    "version_resolved": is_exact,
                    "version_source": "manifest" if is_exact else "manifest_constraint",
                    "is_direct_dependency": True,
                }
                
                if not is_exact and constraint:
                    pkg["version_constraint"] = constraint
                    pkg["version_warning"] = f"Version constraint '{constraint}' - actual version may differ. Generate Gemfile.lock for exact versions."
                
                packages.append(pkg)
        
        # Summary
        resolved = sum(1 for p in packages if p.get("version_resolved", False))
        unresolved = len(packages) - resolved
        print(f"[INFO] Found {len(packages)} Ruby dependencies")
        print(f"[INFO] Version resolution: {resolved} resolved, {unresolved} unresolved")

        # Build lock_data: {pkg_name: {version, hashes, dependencies}}
        lock_data_out: Dict[str, Dict[str, Any]] = {}
        if has_lock_file:
            for name, info in lock_versions.items():
                key = name.lower()
                if key not in lock_data_out:
                    lock_data_out[key] = {
                        "version": info.get("version", ""),
                        "hashes": info.get("hashes", []),
                        "dependencies": info.get("dependencies", [])
                    }
            if lock_data_out:
                print(f"[INFO] Collected {len(lock_data_out)} packages in lock_data for transitive resolution")
        
        return {
            "packages": packages,
            "manifests": manifests,
            "has_lock_file": has_lock_file,
            "language": "ruby",
            "ecosystem": "RubyGems",
            "lock_data": lock_data_out,
        }

    # -------------------------
    def _parse_gemfile_lock(self, lock_path: Path) -> Dict[str, Dict[str, Any]]:
        """
        Parse Gemfile.lock for exact versions.
        
        Format:
        GEM
          remote: https://rubygems.org/
          specs:
            rails (7.0.4)
              actioncable (= 7.0.4)
              actionmailbox (= 7.0.4)
            actioncable (7.0.4)
              actionpack (= 7.0.4)
        
        Returns:
            Dict mapping gem name -> {version, source, dependencies}
        """
        packages: Dict[str, Dict[str, Any]] = {}
        
        try:
            content = lock_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[WARN] Failed to read {lock_path}: {e}")
            return packages
        
        current_source = None
        in_specs = False
        current_gem = None
        
        # Regex to match gem lines: "    gem_name (version)"
        gem_pattern = re.compile(r'^    ([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)$')
        # Regex to match dependency lines: "      dep_name (constraint)"
        dep_pattern = re.compile(r'^      ([a-zA-Z0-9_\-]+)\s*(?:\(.*\))?$')
        
        for line in content.splitlines():
            # Track source
            if line.startswith("GEM"):
                current_source = "rubygems"
                continue
            elif line.startswith("GIT"):
                current_source = "git"
                continue
            elif line.startswith("PATH"):
                current_source = "path"
                continue
            elif line.strip().startswith("remote:"):
                # Could extract specific remote URL
                continue
            elif line.strip() == "specs:":
                in_specs = True
                continue
            elif line and not line.startswith(" "):
                # New section
                in_specs = False
                current_gem = None
                continue
            
            if not in_specs:
                continue
            
            # Try to match a gem line
            gem_match = gem_pattern.match(line)
            if gem_match:
                name = gem_match.group(1)
                version = gem_match.group(2)
                current_gem = name
                
                packages[name] = {
                    "version": version,
                    "source": current_source or "rubygems",
                    "dependencies": [],
                }
                continue
            
            # Try to match a dependency line
            if current_gem:
                dep_match = dep_pattern.match(line)
                if dep_match:
                    dep_name = dep_match.group(1)
                    packages[current_gem]["dependencies"].append(dep_name)
        
        return packages

    # -------------------------
    def _parse_gemfile(self, gemfile_path: Path) -> tuple[Dict[str, str], Set[str]]:
        """
        Parse Gemfile for dependencies.
        
        Format:
        gem 'rails', '~> 7.0'
        gem 'pg', '>= 1.0'
        gem 'puma', '~> 5.0'
        
        Returns:
            Tuple of (deps dict, direct deps set)
        """
        deps: Dict[str, str] = {}
        direct: Set[str] = set()
        
        try:
            content = gemfile_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[WARN] Failed to read {gemfile_path}: {e}")
            return deps, direct
        
        # Regex to match gem declarations
        # gem 'name', 'version'
        # gem "name", "~> 1.0"
        # gem 'name', '~> 1.0', group: :development
        gem_pattern = re.compile(
            r'''gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?''',
            re.IGNORECASE
        )
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments
            if line.startswith("#"):
                continue
            
            match = gem_pattern.search(line)
            if match:
                name = match.group(1)
                constraint = match.group(2) or ""
                deps[name] = constraint.strip()
                direct.add(name)
        
        return deps, direct

    # -------------------------
    def _parse_gemspec(self, gemspec_path: Path) -> Dict[str, str]:
        """
        Parse *.gemspec for dependencies.
        
        Format:
        spec.add_dependency 'rails', '~> 7.0'
        spec.add_runtime_dependency 'pg'
        spec.add_development_dependency 'rspec', '~> 3.0'
        
        Returns:
            Dict mapping gem name -> constraint
        """
        deps: Dict[str, str] = {}
        
        try:
            content = gemspec_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[WARN] Failed to read {gemspec_path}: {e}")
            return deps
        
        # Regex patterns for dependency declarations
        patterns = [
            # add_dependency, add_runtime_dependency
            re.compile(r'''\.add(?:_runtime)?_dependency\s*\(?\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?\)?'''),
            # add_development_dependency (still include for completeness)
            re.compile(r'''\.add_development_dependency\s*\(?\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?\)?'''),
        ]
        
        for pattern in patterns:
            for match in pattern.finditer(content):
                name = match.group(1)
                constraint = match.group(2) or ""
                deps[name] = constraint.strip()
        
        return deps

    # -------------------------
    def _extract_version_from_constraint(self, constraint: str) -> tuple[str, bool]:
        """
        Extract version from a Ruby version constraint.
        
        Args:
            constraint: Version constraint like "~> 2.0", ">= 1.0", "2.0.0"
            
        Returns:
            Tuple of (version, is_exact)
        """
        if not constraint:
            return "UNKNOWN", False
        
        constraint = constraint.strip()
        
        # Check if it's an exact version (no operator)
        if re.match(r'^[\d.]+$', constraint):
            return constraint, True
        
        # Check for equality operator
        eq_match = re.match(r'^=\s*([\d.]+)$', constraint)
        if eq_match:
            return eq_match.group(1), True
        
        # For pessimistic (~>) or comparison operators, extract the base version
        op_match = re.match(r'^[~>=<!\s]+\s*([\d.]+)', constraint)
        if op_match:
            return op_match.group(1), False
        
        return "UNKNOWN", False
    def _get_lock_direct_deps(self, lock_path: Path) -> Set[str]:
        """
        Extract direct dependency names from Gemfile.lock DEPENDENCIES section.
        Used as fallback when Gemfile is absent.

        Gemfile.lock DEPENDENCIES format:
            DEPENDENCIES
              rails (~> 7.0.0)
              pg (>= 0.18)
              puma
        """
        direct: Set[str] = set()
        try:
            content = lock_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return direct

        in_deps = False
        for line in content.splitlines():
            if line.startswith("DEPENDENCIES"):
                in_deps = True
                continue
            if in_deps:
                # Any line that doesn't start with whitespace = new top-level section
                if line and not line.startswith(" "):
                    break
                # Match: "  gemname (constraint)" or "  gemname"
                m = re.match(r'^  ([a-zA-Z0-9_\-\.]+)', line)
                if m:
                    direct.add(m.group(1))
        return direct