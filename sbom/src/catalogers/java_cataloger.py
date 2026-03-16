"""
src/catalogers/java_cataloger.py

JavaCataloger responsibilities:
- detect(root) -> bool
- catalog(root, token=None, nvd_api_key=None)
  -> Dict with key "packages": list[package_dict]

Supported manifest/lock files:
- gradle.lockfile (Gradle lock file - exact versions)
- buildscript-gradle.lockfile (Gradle buildscript lock)
- pom.xml (Maven - usually exact versions)
- build.gradle (Gradle Groovy DSL)
- build.gradle.kts (Gradle Kotlin DSL)

Each package dict contains:
{
  "name", "version", "purl", "language", "type", "sourcePath",
  "version_resolved", "version_source", "version_warning" (if applicable),
  "groupId", "artifactId"
}

Notes:
- Lock files (gradle.lockfile) are prioritized for exact versions.
- Maven pom.xml usually has exact versions (but can use properties/ranges).
- Gradle build files can use dynamic versions - flagged with warnings.
- Metadata/vulnerability enrichment happens later in the pipeline.
"""

from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from sbom.src.catalogers.base import BaseCataloger


class JavaCataloger(BaseCataloger):
    """Cataloger for Java projects supporting Maven and Gradle."""
    
    def __init__(self):
        pass

    @property
    def language(self) -> str:
        """Return language name."""
        return "java"

    @property
    def ecosystem(self) -> str:
        """Return ecosystem name for OSV."""
        return "Maven"

    # -------------------------
    def detect(self, root: str) -> bool:
        """Return True if Java/Maven/Gradle manifest files exist under root."""
        rootp = Path(root)
        # Check for Maven
        if list(rootp.rglob("pom.xml")):
            return True
        # Check for Gradle
        if list(rootp.rglob("build.gradle")) or list(rootp.rglob("build.gradle.kts")):
            return True
        # Check for Gradle lock files
        if list(rootp.rglob("gradle.lockfile")):
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
        Parse Java manifests and extract dependencies.
        Priority: Lock files first (exact versions), then manifests.
        """
        try:
            return self._catalog_internal(repo_root)
        except Exception as e:
            print(f"[ERROR] Java cataloger failed: {e}")
            import traceback
            traceback.print_exc()
            return {"packages": [], "manifests": [], "has_lock_file": False}

    def _catalog_internal(self, repo_root: str) -> Dict[str, Any]:
        root = Path(repo_root)
        print("[INFO] Detected Java project. Parsing manifests for dependencies...")

        # Separate lock files from manifest files
        lock_files: List[Path] = []
        manifest_files: List[Path] = []

        # Find Gradle lock files (exact versions)
        for name in ("gradle.lockfile", "buildscript-gradle.lockfile"):
            for p in root.rglob(name):
                if self._should_skip_path(p, root):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                lock_files.append(p)
                print(f"   * Found LOCK file: {p}")

        # Find manifest files
        for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            for p in root.rglob(name):
                if self._should_skip_path(p, root):
                    print(f"   [SKIP] Skipping (example/test): {p}")
                    continue
                manifest_files.append(p)
                print(f"   * Found manifest: {p}")

        manifests = lock_files + manifest_files

        # STEP 1: Build version lookup from lock files (exact versions)
        lock_versions: Dict[str, str] = {}  # key: "groupId:artifactId", value: version
        lock_data: Dict[str, Dict[str, Any]] = {}  # OPTIMIZED: {pkg_key: {version, hashes, dependencies}}
        for lf in lock_files:
            lock_pkgs = self._parse_gradle_lockfile(lf)
            for pkg in lock_pkgs:
                group_id = pkg.get("groupId", "")
                artifact_id = pkg.get("artifactId", "")
                version = pkg.get("version", "")
                if group_id and artifact_id and version and version != "UNKNOWN":
                    key = f"{group_id}:{artifact_id}"
                    lock_versions[key] = version
                    if key.lower() not in lock_data:
                        lock_data[key.lower()] = {
                            "version": version,
                            "hashes": pkg.get("hashes", []),
                            "dependencies": pkg.get("dependencies", [])
                        }
                    print(f"      [LOCK] {key} = {version}")

        has_lock_file = len(lock_versions) > 0
        if has_lock_file:
            print(f"[INFO] Found {len(lock_versions)} packages in lock files (exact versions)")
        else:
            print("[WARN] No Gradle lock files found - versions from manifests may be dynamic")

        packages: List[Dict[str, Any]] = []

        # STEP 2: Parse all manifests — collect direct dep names from pom/gradle
        manifest_deps: set = set()  # Tracks deps declared in pom.xml / build.gradle (direct)
        for m in manifests:
            nm = m.name.lower()
            if nm == "pom.xml":
                parsed = self._parse_pom_xml(m)
                for p in parsed:
                    gid = p.get("groupId", "")
                    aid = p.get("artifactId", "")
                    if aid:
                        manifest_deps.add(f"{gid}:{aid}".lower())
                packages.extend(parsed)
            elif nm == "build.gradle":
                parsed = self._parse_build_gradle(m)
                for p in parsed:
                    gid = p.get("groupId", "")
                    aid = p.get("artifactId", "")
                    if aid:
                        manifest_deps.add(f"{gid}:{aid}".lower())
                packages.extend(parsed)
            elif nm == "build.gradle.kts":
                parsed = self._parse_build_gradle_kts(m)
                for p in parsed:
                    gid = p.get("groupId", "")
                    aid = p.get("artifactId", "")
                    if aid:
                        manifest_deps.add(f"{gid}:{aid}".lower())
                packages.extend(parsed)
            elif nm == "gradle.lockfile" or nm == "buildscript-gradle.lockfile":
                packages.extend(self._parse_gradle_lockfile(m))

        # Deduplicate by groupId:artifactId (prefer lock file versions)
        dedup: Dict[str, Dict[str, Any]] = {}
        for p in packages:
            group_id = p.get("groupId", "")
            artifact_id = p.get("artifactId", "")
            if not artifact_id:
                continue
            key = f"{group_id}:{artifact_id}".lower()
            if key not in dedup or (not dedup[key].get("version_resolved") and p.get("version_resolved")):
                dedup[key] = p
        packages = list(dedup.values())

        print(f"[INFO] Found {len(packages)} Java dependencies from manifests")

        # STEP 3: Resolve versions using lock file lookup
        for pkg in packages:
            group_id = pkg.get("groupId", "")
            artifact_id = pkg.get("artifactId", "")
            if not artifact_id:
                continue

            pkg["language"] = "java"
            pkg["type"] = "library"

            # Build lookup key FIRST — needed by is_direct_dependency check below
            lookup_key = f"{group_id}:{artifact_id}"

            # Classify direct vs transitive using manifest declarations
            if manifest_deps and has_lock_file:
                pkg["is_direct_dependency"] = lookup_key.lower() in manifest_deps
            else:
                pkg["is_direct_dependency"] = pkg.get("is_direct_dependency", True)
            pkg.setdefault("scope", "required")
            original_version = pkg.get("version") or ""
            version_constraint = pkg.get("version_constraint", "")

            if lookup_key in lock_versions:
                # Use exact version from lock file
                resolved_version = lock_versions[lookup_key]
                pkg["version"] = resolved_version
                pkg["version_resolved"] = True
                pkg["version_source"] = "lock_file"
                if version_constraint:
                    pkg["version_constraint"] = version_constraint
            elif original_version and not self._is_dynamic_version(original_version):
                # Version looks exact (not a range or property)
                pkg["version_resolved"] = True
                pkg["version_source"] = "manifest"
            elif original_version:
                # Dynamic version or property reference
                pkg["version_resolved"] = False
                pkg["version_source"] = "manifest_constraint"
                pkg["version_warning"] = f"Dynamic version '{original_version}' detected. No lock file found. Actual resolved version may differ. Vulnerability results may be inaccurate."
            else:
                # No version at all
                pkg["version"] = "UNKNOWN"
                pkg["version_resolved"] = False
                pkg["version_source"] = "unknown"
                pkg["version_warning"] = "Version not specified in manifest and no lock file found. Cannot accurately check vulnerabilities."

            # Build name and PURL
            if group_id:
                pkg["name"] = f"{group_id}:{artifact_id}"
            else:
                pkg["name"] = artifact_id

            version = pkg.get("version") or ""
            pkg["purl"] = self._build_maven_purl(group_id, artifact_id, version)

            # CERT-IN field placeholders
            # Use artifact_id as short component name (not group_id:artifact_id)
            pkg.setdefault("component_name", artifact_id)
            pkg["group_id"] = group_id  # Keep full group_id for reference
            pkg.setdefault("component_version", version or "")
            pkg.setdefault("component_license", "NOASSERTION")
            pkg.setdefault("hashes", [])
            pkg.setdefault("dependencies", [])

        # Log summary of version resolution
        resolved_count = sum(1 for p in packages if p.get("version_resolved", False))
        unresolved_count = len(packages) - resolved_count
        print(f"[INFO] Version resolution: {resolved_count} resolved, {unresolved_count} unresolved (dynamic/missing)")

        return {
            "packages": packages,
            "manifests": [str(m) for m in manifests],
            "has_lock_file": has_lock_file,
            "lock_data": lock_data
        }

    # -------------------------
    # Gradle Lock File Parser
    # -------------------------
    def _parse_gradle_lockfile(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Gradle lock file (gradle.lockfile).
        
        Format:
            # This is a Gradle generated file for dependency locking.
            # Manual edits can break the build and are not advised.
            # This file is expected to be part of source control.
            com.google.code.gson:gson:2.10.1=compileClasspath,runtimeClasspath
            org.apache.commons:commons-lang3:3.14.0=compileClasspath
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        for line in content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # Skip the empty= line at the end
            if line.startswith("empty="):
                continue
            
            # Format: groupId:artifactId:version=configurations
            match = re.match(r'^([\w.\-]+):([\w.\-]+):([\w.\-+]+)(?:=.*)?$', line)
            if match:
                group_id, artifact_id, version = match.groups()
                packages.append({
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "name": f"{group_id}:{artifact_id}",
                    "version": version,
                    "sourcePath": str(path),
                    "version_resolved": True,
                    "version_source": "lock_file",
                    "is_direct_dependency": True,  # Lock file doesn't distinguish
                    "dependencies": [],
                })

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    # -------------------------
    # Maven pom.xml Parser
    # -------------------------
    def _parse_pom_xml(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Maven pom.xml for dependencies.
        
        Handles:
        - <dependencies> section
        - <dependencyManagement> section
        - Property references like ${version.property}
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
            # Remove XML namespace to simplify parsing
            content = re.sub(r'\sxmlns\s*=\s*"[^"]*"', '', content, count=1)
            root = ET.fromstring(content)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return packages

        # Extract properties for version resolution
        properties: Dict[str, str] = {}
        props_elem = root.find("properties")
        if props_elem is not None:
            for prop in props_elem:
                tag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
                properties[tag] = prop.text or ""

        # Also check parent for version
        parent = root.find("parent")
        if parent is not None:
            parent_version = parent.find("version")
            if parent_version is not None and parent_version.text:
                properties["project.parent.version"] = parent_version.text
                properties["parent.version"] = parent_version.text

        # Project version
        project_version = root.find("version")
        if project_version is not None and project_version.text:
            properties["project.version"] = project_version.text
            properties["version"] = project_version.text

        def resolve_property(value: str) -> Tuple[str, bool]:
            """Resolve ${property} references. Returns (value, is_resolved)."""
            if not value:
                return "", False
            
            original = value
            # Handle ${property} syntax
            prop_pattern = re.compile(r'\$\{([^}]+)\}')
            matches = prop_pattern.findall(value)
            
            for prop_name in matches:
                if prop_name in properties:
                    value = value.replace(f"${{{prop_name}}}", properties[prop_name])
                else:
                    # Unresolved property
                    return original, False
            
            # Check if all properties were resolved
            if "${" in value:
                return original, False
            return value, True

        def parse_dependencies(deps_elem, is_managed: bool = False):
            """Parse <dependency> elements."""
            if deps_elem is None:
                return
            
            for dep in deps_elem.findall("dependency"):
                group_id_elem = dep.find("groupId")
                artifact_id_elem = dep.find("artifactId")
                version_elem = dep.find("version")
                scope_elem = dep.find("scope")
                optional_elem = dep.find("optional")

                group_id = group_id_elem.text if group_id_elem is not None else ""
                artifact_id = artifact_id_elem.text if artifact_id_elem is not None else ""
                version_raw = version_elem.text if version_elem is not None else ""
                scope = scope_elem.text if scope_elem is not None else "compile"
                is_optional = optional_elem is not None and optional_elem.text == "true"

                if not artifact_id:
                    continue

                # Resolve version property
                version, is_resolved = resolve_property(version_raw)

                # Skip test/provided scope for SBOM (optional)
                sbom_scope = "required"
                if scope in ("test", "provided"):
                    sbom_scope = "optional"
                elif is_optional:
                    sbom_scope = "optional"

                packages.append({
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "name": f"{group_id}:{artifact_id}" if group_id else artifact_id,
                    "version": version,
                    "version_constraint": version_raw if version_raw != version else "",
                    "sourcePath": str(path),
                    "scope": sbom_scope,
                    "maven_scope": scope,
                    "is_direct_dependency": True,
                    "version_resolved": is_resolved and bool(version),
                    "version_source": "manifest" if is_resolved else "manifest_constraint",
                })

        # Parse main dependencies
        parse_dependencies(root.find("dependencies"))
        
        # Parse dependencyManagement (for version info)
        dep_mgmt = root.find("dependencyManagement")
        if dep_mgmt is not None:
            parse_dependencies(dep_mgmt.find("dependencies"), is_managed=True)

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    # -------------------------
    # Gradle build.gradle Parser (Groovy DSL)
    # -------------------------
    def _parse_build_gradle(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Gradle build.gradle (Groovy DSL) for dependencies.
        
        Formats supported:
        - implementation 'group:artifact:version'
        - implementation "group:artifact:version"
        - implementation("group:artifact:version")   (parenthesized — common in modern Gradle)
        - implementation group: 'com.example', name: 'lib', version: '1.0'
        - compile 'group:artifact:version'  (legacy)
        - testImplementation 'group:artifact:version'
        - Variable interpolation: ${varName} resolved from def/val declarations
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        # ---- Extract Gradle variables for interpolation ----
        # Matches: def jacksonVersion = "2.18.0"  /  def junitVersion = '5.11.1'
        #          val jacksonVersion = "2.18.0"
        #          ext.jacksonVersion = "2.18.0"
        gradle_vars: Dict[str, str] = {}
        var_pattern = re.compile(
            r"""(?:def|val|final\s+\w+)\s+(\w+)\s*=\s*['"](.*?)['"]""",
            re.MULTILINE
        )
        for m in var_pattern.finditer(content):
            gradle_vars[m.group(1)] = m.group(2)
        
        # Also: ext.varName = "value"  /  ext { varName = "value" }
        ext_pattern = re.compile(
            r"""ext\.(\w+)\s*=\s*['"](.*?)['"]""",
            re.MULTILINE
        )
        for m in ext_pattern.finditer(content):
            gradle_vars[m.group(1)] = m.group(2)
        
        # Also pick up simple: varName = "value" at top-level (before dependencies block)
        simple_var_pattern = re.compile(
            r"""^(\w+)\s*=\s*['"]([\d][\w.\-]*?)['"]""",
            re.MULTILINE
        )
        for m in simple_var_pattern.finditer(content):
            name = m.group(1)
            # Only add if looks like a version variable
            if "version" in name.lower() or "ver" in name.lower() or re.match(r'^\d', m.group(2)):
                gradle_vars[name] = m.group(2)
        
        if gradle_vars:
            print(f"      [GRADLE] Extracted {len(gradle_vars)} variables: {list(gradle_vars.keys())}")

        def _resolve_gradle_string(s: str) -> Tuple[str, bool]:
            """Resolve ${varName} and $varName in a Gradle string. Returns (resolved, fully_resolved)."""
            if not s:
                return s, False
            original = s
            # Handle ${varName}
            for var_name, var_val in gradle_vars.items():
                s = s.replace(f"${{{var_name}}}", var_val)
                s = s.replace(f"${var_name}", var_val)
            fully_resolved = "$" not in s
            return s, fully_resolved

        # Configuration names (scope mapping)
        config_scopes = {
            "implementation": "required",
            "api": "required",
            "compile": "required",  # legacy
            "runtime": "required",
            "runtimeOnly": "required",
            "compileOnly": "optional",
            "testImplementation": "dev",
            "testCompile": "dev",  # legacy
            "testRuntimeOnly": "dev",
            "androidTestImplementation": "dev",
            "debugImplementation": "optional",
            "releaseImplementation": "required",
        }

        seen_deps: set = set()  # Avoid duplicates across patterns

        def _add_dep(config: str, group_id: str, artifact_id: str, version_raw: str):
            """Add a dependency if not already seen."""
            key = f"{group_id}:{artifact_id}".lower()
            if key in seen_deps:
                return
            seen_deps.add(key)
            
            # Resolve variable interpolation in version
            version, was_resolved = _resolve_gradle_string(version_raw)
            is_dynamic = self._is_dynamic_version(version)
            resolved = was_resolved and not is_dynamic and bool(version)
            
            pkg = {
                "groupId": group_id,
                "artifactId": artifact_id,
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "sourcePath": str(path),
                "scope": config_scopes.get(config, "required"),
                "gradle_config": config,
                "is_direct_dependency": True,
                "version_resolved": resolved,
                "version_source": "manifest" if resolved else "manifest_constraint",
            }
            if not resolved and version_raw and "$" in version_raw:
                pkg["version_warning"] = f"Variable '{version_raw}' could not be fully resolved."
            packages.append(pkg)

        # Pattern 1: configuration("group:artifact:version") — parenthesized (modern Gradle)
        # Matches: implementation("com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}")
        pattern_paren = re.compile(
            r"""(\w+)\s*\(\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-${}]+)['"]\s*\)""",
            re.MULTILINE
        )
        for match in pattern_paren.finditer(content):
            config, group_id, artifact_id, version = match.groups()
            if config in config_scopes:
                _add_dep(config, group_id, artifact_id, version)

        # Pattern 2: configuration 'group:artifact:version' — space-separated (classic Gradle)
        # Matches: implementation 'com.google.code.gson:gson:2.10.1'
        pattern_space = re.compile(
            r"""(\w+)\s+['"]([\w.\-]+):([\w.\-]+):([\w.\-${}]+)['"]""",
            re.MULTILINE
        )
        for match in pattern_space.finditer(content):
            config, group_id, artifact_id, version = match.groups()
            if config in config_scopes:
                _add_dep(config, group_id, artifact_id, version)

        # Pattern 3: configuration group: 'x', name: 'y', version: 'z'
        pattern_named = re.compile(
            r"(\w+)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]",
            re.MULTILINE
        )
        for match in pattern_named.finditer(content):
            config, group_id, artifact_id, version = match.groups()
            if config in config_scopes:
                _add_dep(config, group_id, artifact_id, version)

        # Pattern 4: Dependencies without version (from BOM/platform)
        # implementation 'com.google.code.gson:gson'  OR  implementation("com.google.code.gson:gson")
        pattern_nover = re.compile(
            r"""(\w+)\s*[\s(]['"]([\w.\-]+):([\w.\-]+)['"]\s*\)?""",
            re.MULTILINE
        )
        for match in pattern_nover.finditer(content):
            config, group_id, artifact_id = match.groups()
            if config not in config_scopes:
                continue
            key = f"{group_id}:{artifact_id}".lower()
            if key in seen_deps:
                continue
            seen_deps.add(key)
            packages.append({
                "groupId": group_id,
                "artifactId": artifact_id,
                "name": f"{group_id}:{artifact_id}",
                "version": "",
                "sourcePath": str(path),
                "scope": config_scopes.get(config, "required"),
                "gradle_config": config,
                "is_direct_dependency": True,
                "version_resolved": False,
                "version_source": "manifest_constraint",
                "version_warning": "Version managed by BOM/platform. Actual version unknown without lock file.",
            })

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    # -------------------------
    # Gradle build.gradle.kts Parser (Kotlin DSL)
    # -------------------------
    def _parse_build_gradle_kts(self, path: Path) -> List[Dict[str, Any]]:
        """
        Parse Gradle build.gradle.kts (Kotlin DSL) for dependencies.
        
        Formats supported:
        - implementation("group:artifact:version")
        - implementation("group:artifact:version") { ... }
        - testImplementation("group:artifact:version")
        - Variable interpolation: $varName / ${varName}
        """
        packages: List[Dict[str, Any]] = []
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to read {path}: {e}")
            return packages

        # ---- Extract Kotlin variables for interpolation ----
        gradle_vars: Dict[str, str] = {}
        var_pattern = re.compile(
            r"""(?:val|var|const\s+val)\s+(\w+)\s*=\s*"(.*?)\"""",
            re.MULTILINE
        )
        for m in var_pattern.finditer(content):
            gradle_vars[m.group(1)] = m.group(2)
        
        if gradle_vars:
            print(f"      [GRADLE KTS] Extracted {len(gradle_vars)} variables: {list(gradle_vars.keys())}")

        def _resolve_kts_string(s: str) -> Tuple[str, bool]:
            if not s:
                return s, False
            for var_name, var_val in gradle_vars.items():
                s = s.replace(f"${{{var_name}}}", var_val)
                s = s.replace(f"${var_name}", var_val)
            return s, "$" not in s

        # Configuration names (scope mapping)
        config_scopes = {
            "implementation": "required",
            "api": "required",
            "compile": "required",
            "runtime": "required",
            "runtimeOnly": "required",
            "compileOnly": "optional",
            "testImplementation": "dev",
            "testCompile": "dev",
            "testRuntimeOnly": "dev",
            "androidTestImplementation": "dev",
            "debugImplementation": "optional",
            "releaseImplementation": "required",
        }

        seen_deps: set = set()

        # Pattern: configuration("group:artifact:version")
        pattern = re.compile(
            r'(\w+)\s*\(\s*"([\w.\-]+):([\w.\-]+):([\w.\-${}]+)"\s*\)',
            re.MULTILINE
        )
        
        for match in pattern.finditer(content):
            config, group_id, artifact_id, version_raw = match.groups()
            if config not in config_scopes:
                continue
            
            key = f"{group_id}:{artifact_id}".lower()
            if key in seen_deps:
                continue
            seen_deps.add(key)
            
            version, was_resolved = _resolve_kts_string(version_raw)
            is_dynamic = self._is_dynamic_version(version)
            resolved = was_resolved and not is_dynamic and bool(version)
            
            packages.append({
                "groupId": group_id,
                "artifactId": artifact_id,
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "sourcePath": str(path),
                "scope": config_scopes.get(config, "required"),
                "gradle_config": config,
                "is_direct_dependency": True,
                "version_resolved": resolved,
                "version_source": "manifest" if resolved else "manifest_constraint",
            })

        # Pattern: configuration("group:artifact") - no version (from BOM)
        pattern_no_ver = re.compile(
            r'(\w+)\s*\(\s*"([\w.\-]+):([\w.\-]+)"\s*\)',
            re.MULTILINE
        )
        
        for match in pattern_no_ver.finditer(content):
            config, group_id, artifact_id = match.groups()
            if config not in config_scopes:
                continue
            key = f"{group_id}:{artifact_id}".lower()
            if key in seen_deps:
                continue
            seen_deps.add(key)
            
            packages.append({
                "groupId": group_id,
                "artifactId": artifact_id,
                "name": f"{group_id}:{artifact_id}",
                "version": "",
                "sourcePath": str(path),
                "scope": config_scopes.get(config, "required"),
                "gradle_config": config,
                "is_direct_dependency": True,
                "version_resolved": False,
                "version_source": "manifest_constraint",
                "version_warning": "Version managed by BOM/platform. Actual version unknown without lock file.",
            })

        print(f"   Parsed {len(packages)} dependencies from {path.name}")
        return packages

    # -------------------------
    # Helpers
    # -------------------------
    def _is_dynamic_version(self, version: str) -> bool:
        """Check if version is dynamic (range, property, latest, etc.)."""
        if not version:
            return True
        
        dynamic_patterns = [
            r'^\$',          # Property reference $version or ${version}
            r'^\[',          # Version range [1.0,2.0)
            r'^\(',          # Version range (1.0,2.0]
            r'\+$',          # Latest: 1.0.+ or +
            r'^latest',      # latest.release, latest.integration
            r'^LATEST',
            r'^RELEASE',
            r'^\*',          # Wildcard
            r'^dynamic',
        ]
        
        for pattern in dynamic_patterns:
            if re.search(pattern, version, re.IGNORECASE):
                return True
        return False

    def _build_maven_purl(self, group_id: str, artifact_id: str, version: str) -> str:
        """
        Build Package URL for Maven packages.
        
        Format: pkg:maven/groupId/artifactId@version
        """
        if not artifact_id:
            return ""
        
        if group_id:
            # URL encode the group ID (replace . with /)
            namespace = group_id
            return f"pkg:maven/{namespace}/{artifact_id}@{version}" if version else f"pkg:maven/{namespace}/{artifact_id}"
        else:
            return f"pkg:maven/{artifact_id}@{version}" if version else f"pkg:maven/{artifact_id}"
