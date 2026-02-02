"""
Prepare a workspace and scan it for SBOM artifacts.

Exposes:
  - prepare_workspace(scan_id, temp_base, repo_url, local_path, zip_path, token, username)
  - scan_workspace(workspace, scan_id, temp_base, include_transitives=True, enable_license_lookup=True)

Notes:
 - This module intentionally does lazy imports for catalogers to reduce circular import issues.
 - It prints progress lines so the CLI user knows which files are being parsed.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any, Set
import shutil
import uuid
import os
import subprocess
import json
from datetime import datetime, timezone

# Utility functions assumed implemented in repo
from src.utils.file_utils import ensure_dir, extract_zip, cleanup_workspace
from src.utils.git_utils import git_clone, probe_repo_access  # git_clone should accept token/username optional
from src.core import vulnerability_provider
from src.registry.language_registry import iter_manifest_patterns, get_purl_type, get_cataloger_instances, get_language_for_manifest
from src.config.ecosystems import get_ecosystem
# sbom generator is called later in pipeline (main.py) — scan returns catalog for them


def _clean_version(version: str) -> str:
    """
    Clean version string by removing operators and normalizing format.
    
    Examples:
        "==1.2.3" -> "1.2.3"
        ">=2.0.0" -> "2.0.0"
        "^1.5" -> "1.5"
        "~1.2.3" -> "1.2.3"
    """
    import re
    if not version or version == "UNKNOWN":
        return "UNKNOWN"
    
    # Remove leading operators
    cleaned = re.sub(r'^[=<>!~^]+\s*', '', str(version)).strip()
    
    # Remove trailing operators or wildcards
    cleaned = re.sub(r'[*+]$', '', cleaned).strip()
    
    return cleaned if cleaned else "UNKNOWN"


def _normalize_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize package data:
    - Clean version strings
    - Ensure PURL exists
    - Standardize fields
    
    Returns normalized package dict.
    """
    # Clean version early
    if "version" in pkg:
        pkg["version"] = _clean_version(pkg["version"])
    
    # Ensure name exists
    name = pkg.get("name", "")
    if not name:
        return pkg
    
    # Ensure language/ecosystem
    lang = pkg.get("language", "unknown").lower()
    pkg["language"] = lang
    
    # Generate or normalize PURL
    version = pkg.get("version", "")
    ecosystem = get_purl_type(lang)
    
    # Generate PURL if missing or incorrect
    if not pkg.get("purl") or "@" not in pkg.get("purl", ""):
        if version and version != "UNKNOWN":
            pkg["purl"] = f"pkg:{ecosystem}/{name}@{version}"
        else:
            pkg["purl"] = f"pkg:{ecosystem}/{name}"
    
    return pkg

def prepare_workspace(scan_id: str,
                      temp_base: Path,
                      repo_url: Optional[str] = None,
                      local_path: Optional[str] = None,
                      zip_path: Optional[str] = None,
                      token: Optional[str] = None,
                      username: Optional[str] = None) -> Path:
    """
    Create workspace directory under temp_base/scan_id and populate it from repo/local/zip.
    Returns Path to workspace.
    """
    workspace = (temp_base / scan_id).resolve()
    ensure_dir(workspace)
    print(f"[INFO] Preparing workspace: {workspace}")
    if repo_url:
        print(f"-> Cloning {repo_url} into {workspace} ...")
        # git_clone should raise on error
        git_clone(repo_url, workspace, token=token, username=username)
    elif local_path:
        src = Path(local_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Local path not found: {src}")
        print(f"-> Copying local path {src} -> {workspace}")
        for item in src.iterdir():
            dest = workspace / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
    elif zip_path:
        zp = Path(zip_path).resolve()
        if not zp.exists():
            raise FileNotFoundError(f"Zip path not found: {zp}")
        print(f"-> Extracting zip {zp} -> {workspace}")
        extract_zip(zp, workspace)
    else:
        raise ValueError("One of repo_url, local_path or zip_path must be provided.")
    return workspace


def _discover_manifests(workspace: Path) -> List[str]:
    """
    Walk the workspace and return list of notable manifest file paths (pyproject, requirements, package.json, setup.py, Pipfile, poetry.lock).
    Also prints each manifest found.
    
    Fixed: Proper path component checking instead of string matching.
    """
    manifests = []
    patterns = set(iter_manifest_patterns())
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", ".cache", "build", "dist"}
    
    for root, dirs, files in os.walk(workspace):
        # Proper path checking: check if any part of the path is a skip directory
        root_path = Path(root)
        if any(skip_dir in root_path.parts for skip_dir in skip_dirs):
            dirs[:] = []  # Don't recurse into this directory
            continue
            
        for f in files:
            if f in patterns:
                full = root_path / f
                manifests.append(str(full))
                print(f"   * Found manifest: {full}")
    return manifests





def _run_catalogers(workspace: Path,
                    nvd_api_key: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    """
    Run language-specific catalogers with automatic enrichment.
    
    Catalogers now handle enrichment internally:
    - Metadata: deps.dev (primary) → PyPI (fallback)
    - Vulnerabilities: OSV (primary) → NVD (fallback if API key provided)
    - Dependencies: Always from deps.dev
    
    No manual flags needed - everything is automatic!
    
    Args:
        workspace: Path to workspace to scan
        nvd_api_key: Optional NVD API key for vulnerability fallback
    
    Returns:
        Tuple of (packages list, manifests list, raw cataloger outputs)
    """
    packages: List[Dict[str, Any]] = []
    manifests: List[str] = []
    raw_outputs: List[Dict[str, Any]] = []  # Store raw cataloger outputs for audit

    catalogers = get_cataloger_instances()

    for cataloger in catalogers:
        try:
            if not cataloger.detect(workspace):
                continue

            catres = cataloger.catalog(str(workspace), nvd_api_key=nvd_api_key)

            if isinstance(catres, dict) and "packages" in catres:
                cat_packages = catres["packages"]

                for p in cat_packages:
                    normalized = _normalize_package(p)
                    packages.append(normalized)

                cataloger_name = getattr(cataloger, "language", None)
                if not isinstance(cataloger_name, str):
                    cataloger_name = cataloger.__class__.__name__.replace("Cataloger", "").lower()

                raw_outputs.append({
                    "cataloger": cataloger_name,
                    "package_count": len(cat_packages),
                    "manifests": catres.get("manifests", [])
                })

                for m_path in catres.get("manifests", []):
                    if m_path not in manifests:
                        manifests.append(m_path)

                print(f"   {cataloger_name}: Found {len(cat_packages)} packages")
            else:
                print(f"[WARNING] {cataloger.__class__.__name__} returned unexpected format: {type(catres)}")

        except Exception as e:
            print(f"[ERROR] {cataloger.__class__.__name__} failed: {e}")
            import traceback
            traceback.print_exc()

    # Deduplicate packages by PURL (now that all packages have normalized PURLs)
    deduped = {}
    for p in packages:
        purl = p.get("purl")
        if not purl:
            # Fallback key if PURL somehow missing
            key = f"{p.get('name', 'unknown')}@{p.get('version', 'unknown')}"
        else:
            key = purl
        
        # Keep first occurrence (cataloger order matters)
        if key not in deduped:
            deduped[key] = p
    
    packages_out = list(deduped.values())
    
    print(f"[INFO] Cataloging complete: {len(packages)} packages found, {len(packages_out)} unique packages after deduplication")
    
    return packages_out, manifests, raw_outputs


# Replace the existing scan_workspace with this function (complete).
def scan_workspace(workspace: Path,
                   scan_id: Optional[str] = None,
                   temp_base: Optional[Path] = None,
                   nvd_api_key: Optional[str] = None,
                   project_name: str = "UNKNOWN",
                   verify_mode: str = "selective",
                   verify_packages: List[str] = None,
                   max_workers: int = 10,
                   recent_publish_days: int = 7) -> Tuple[Dict[str, Any], List[str]]:
    """
    Single-pass scanner that discovers packages and enriches them automatically.
    
    Data Source Priority:
    1. Package Metadata: deps.dev (primary) → PyPI (fallback)
    2. Vulnerabilities: OSV (primary) → NVD (fallback if API key provided)
    3. Dependencies: Always from deps.dev (includes transitives)
    
    All CERT-IN mandatory fields are ALWAYS fetched automatically.
    No manual flags needed - the system is smart enough to fetch everything.
    
    Args:
        workspace: Path to the workspace to scan
        scan_id: Unique scan identifier
        temp_base: Base directory for temporary files
        nvd_api_key: Optional NVD API key for vulnerability fallback
        project_name: Name of the project being scanned
        verify_mode: Package verification mode
        verify_packages: List of packages to verify
        max_workers: Maximum number of worker threads
        recent_publish_days: Days to consider a package "recently published"
    
    Returns:
        Tuple of (catalog dict, notices list)
    """
    notices: List[str] = []
    scan_id = scan_id or uuid.uuid4().hex[:12]
    workspace = Path(workspace).resolve()
    print(f"[INFO] Scanning workspace: {workspace}")

    # --- 1) Discover manifests (single pass)
    print("[INFO] Discovering project manifests...")
    discovered_manifests = _discover_manifests(workspace)

    # --- 2) Run catalogers just once (Python/Node/Maven/Conan/etc)
    # Note: Catalogers now handle enrichment internally (deps.dev primary, PyPI fallback)
    print("[INFO] Running catalogers with automatic enrichment...")
    packages, catalog_manifests, raw_outputs = _run_catalogers(
        workspace,
        nvd_api_key=nvd_api_key  # Pass only nvd_api_key for optional fallback
    )
    
    # Merge discovered and cataloger-reported manifests
    all_manifests = list(set(discovered_manifests + catalog_manifests))

    # --- 3) Save raw cataloger output for audit trail
    if scan_id and temp_base:
        raw_report_path = temp_base / scan_id / "raw_cataloger_output.json"
        try:
            raw_report_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create structured summary
            summary = {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "workspace": str(workspace),
                "catalogers": raw_outputs,
                "total_packages": len(packages),
                "total_manifests": len(all_manifests)
            }
            
            raw_report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(f"[INFO] Raw cataloger output saved to {raw_report_path}")
        except Exception as e:
            print(f"[WARNING] Failed to save raw cataloger output: {e}")

    # Check if root package was found (by name matching project_name)
    if project_name != "UNKNOWN":
        found_root = any(p.get("name", "").lower() == project_name.lower() for p in packages)
        if not found_root:
            # Infer language/type from manifests
            root_lang = "unknown"
            root_purl_type = "unknown"

            for m in all_manifests:
                lang = get_language_for_manifest(Path(m).name)
                if lang:
                    root_lang = lang
                    root_purl_type = get_purl_type(lang)
                    break

            if root_lang == "unknown":
                root_lang = "python"
                root_purl_type = "pypi"

            # Don't include root project as a component - only list dependencies
            # (Commenting out to exclude root project from SBOM)
            # packages.append({
            #     "name": project_name,
            #     "version": "UNKNOWN",
            #     "language": root_lang,
            #     "type": "library",
            #     "purl": f"pkg:{root_purl_type}/{project_name}",
            #     "license": "NOASSERTION",
            #     "description": f"Root project: {project_name}",
            #     "dependencies": []
            # })

    # --- 4) Vulnerability Detection Already Handled by Catalogers
    # Note: Catalogers now handle vulnerability detection internally (OSV primary, NVD fallback)
    # This section is kept for backward compatibility but doesn't re-enrich
    try:
        print(f"[INFO] Vulnerability detection completed by catalogers (OSV primary)")
        
        # Optional: Hybrid verification for packages that need it
        if verify_mode != "none":
            print(f"[INFO] Starting package verification (mode: {verify_mode})...")
            
            # Import hybrid detection modules
            from src.clients import depsdev_client
            
            # Prepare package data for concurrent processing
            package_data = []
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")  # Already cleaned by _normalize_package
                lang = (pkg.get("language") or "").lower()
                
                if not name or not version or version == "UNKNOWN":
                    pkg.setdefault("vulnerabilities", [])
                    continue
                
                # Map language to deps.dev ecosystem
                ecosystem = get_purl_type(lang)
                
                # Version is already cleaned by _normalize_package, no need to clean again
                
                # Get deps.dev client instance
                client = depsdev_client.get_client()
                
                # ============================================================
                # METADATA ONLY from deps.dev (NOT vulnerabilities)
                # Vulnerabilities will come from CVE/OSV only
                # ============================================================
                
                # Initialize variables
                dep_graph = None
                metadata = {}
                
                # Fetch dependency graph from deps.dev
                # Version is already cleaned by _normalize_package
                dep_graph = client.get_dependency_graph(ecosystem, name, version)
                
                # Fetch metadata (license, release_date, homepage) from deps.dev
                metadata = client.get_metadata(ecosystem, name, version)
                
                # Enrich package with deps.dev metadata
                # Don't overwrite if already set by cataloger (e.g., from repo files for dev versions)
                if not pkg.get("component_license") or pkg.get("component_license") == "NOASSERTION":
                    pkg["component_license"] = metadata.get("license", "NOASSERTION")
                if not pkg.get("release_date"):
                    pkg["release_date"] = metadata.get("published_at", "")
                if not pkg.get("homepage"):
                    pkg["homepage"] = metadata.get("homepage", "")
                
                # Add dependencies from graph (only if not already set by cataloger)
                if dep_graph and dep_graph.get("direct") and not pkg.get("component_dependencies"):
                    # Convert to PURL format, avoiding double prefixing
                    deps_list = []
                    for dep in dep_graph["direct"]:
                        dep_name = dep['name']
                        # Check if already in PURL format
                        if dep_name.startswith("pkg:"):
                            deps_list.append(dep_name)
                        else:
                            deps_list.append(f"pkg:{ecosystem}/{dep_name}")
                    pkg["component_dependencies"] = deps_list
                
                # Derive component_origin from license
                license_str = pkg.get("component_license", "")
                if license_str and license_str != "NOASSERTION":
                    if any(lic in license_str.upper() for lic in ["MIT", "BSD", "APACHE", "ISC"]):
                        pkg["component_origin"] = "Open Source"
                    elif any(lic in license_str.upper() for lic in ["GPL", "LGPL", "AGPL"]):
                        pkg["component_origin"] = "Restrictive"
                    else:
                        pkg["component_origin"] = "Unknown"
                else:
                    pkg["component_origin"] = "Unknown"
                
                # ============================================================
                # VULNERABILITY DETECTION: Use OSV/CVE directly (NOT deps.dev)
                # ============================================================
                
                # Query OSV database for vulnerabilities
                from src.core import vulnerability_provider
                
                # Map ecosystem for OSV
                osv_ecosystem = get_ecosystem(ecosystem)
                
                # Version is already cleaned by _normalize_package
                osv_vulns = vulnerability_provider.query_osv_package(osv_ecosystem, name, version) or []
                
                # Normalize OSV vulnerabilities
                normalized_vulns = vulnerability_provider.normalize_osv_entries(osv_vulns)
                
                pkg["vulnerabilities"] = normalized_vulns
                print(f"[INFO] Found {len(normalized_vulns)} vulnerabilities for {name} from OSV")
                
                # ============================================================
                # CERT-IN 21 FIELDS ENRICHMENT
                # ============================================================
                
                # Import all new utilities
                from src.utils.eol_utils import get_eol_for_package
                from src.utils.file_analysis import (
                    detect_executable_property,
                    detect_archive_property,
                    detect_structured_property,
                    calculate_criticality
                )
                from src.utils.license_utils import determine_usage_restrictions
                from src.utils.patch_utils import determine_patch_status
                
                # 1. EOL Date (Field 11)
                pkg["eol_date"] = get_eol_for_package(ecosystem, name, version)
                
                # 2. Patch Status (Field 9)
                pkg["patch_status"] = determine_patch_status(version, normalized_vulns)
                
                # 3. Criticality (Field 12) - must be after EOL and vulnerabilities
                pkg["criticality"] = calculate_criticality(pkg)
                
                # 4. Usage Restrictions (Field 13)
                pkg["usage_restrictions"] = determine_usage_restrictions(license_str)
                
                # 5. Executable Property (Field 18)
                pkg["executable"] = detect_executable_property(pkg, workspace)
                
                # 6. Archive Property (Field 19)
                pkg["archive"] = detect_archive_property(pkg)
                
                # 7. Structured Property (Field 20)
                pkg["structured_properties"] = detect_structured_property(pkg, workspace)
                
                # 8. Component Supplier (Field 4) - Extract from metadata
                # Try to get supplier from deps.dev package info
                try:
                    pkg_info = client.get_package_info(ecosystem, name, version)
                    projects = pkg_info.get("projects", [])
                    if projects:
                        project_key = projects[0].get("projectKey", {})
                        system = project_key.get("system", "")
                        proj_id = project_key.get("id", "")
                        if system and proj_id:
                            pkg["component_supplier"] = f"{system}:{proj_id}"
                        else:
                            pkg["component_supplier"] = ""
                    else:
                        pkg["component_supplier"] = ""
                except Exception as e:
                    pkg["component_supplier"] = ""
                
                # 9. Comments (Field 15) - Generate from metadata
                comments = []
                if pkg.get("description"):
                    desc = pkg["description"][:150]
                    comments.append(f"Purpose: {desc}")
                
                vuln_count = len(normalized_vulns)
                if vuln_count > 0:
                    critical = sum(1 for v in normalized_vulns if "CRITICAL" in str(v.get("severity_string", "")).upper())
                    high = sum(1 for v in normalized_vulns if "HIGH" in str(v.get("severity_string", "")).upper())
                    if critical or high:
                        comments.append(f"Security: {critical} critical, {high} high vulnerabilities")
                
                deps_count = len(pkg.get("component_dependencies", []))
                if deps_count > 0:
                    comments.append(f"Dependencies: {deps_count} direct")
                
                pkg["comments"] = " | ".join(comments) if comments else ""
                
                # 10. Hashes/Checksums (Field 14) - Will be implemented later during file scanning
                # For now, set as empty to indicate field is available
                pkg.setdefault("hashes", [])
                
                # Add to batch (no longer includes depsdev_vulns)
                package_data.append({
                    "ecosystem": ecosystem,
                    "name": name,
                    "version": version,  # Already cleaned
                    "publish_date": pkg.get("release_date"),
                    "dependency_graph": dep_graph,
                    "pkg_ref": pkg  # Keep reference to original package object
                })
            
            # Vulnerabilities are already set from OSV - no need for verification manager processing
            
            print(f"[OK] Vulnerability detection complete (OSV/CVE).")
            print(f"     - Packages scanned: {len(packages)}")
            print(f"     - Vulnerabilities found: {sum(len(p.get('vulnerabilities', [])) for p in packages)}")

        else:
            print("[INFO] Vulnerability enrichment skipped.")
            for p in packages:
                p.setdefault("vulnerabilities", [])
    except Exception as e:
        notices.append(f"Hybrid vulnerability detection failed: {e}")
        print(f"[WARN] Hybrid vulnerability detection failed: {e}")
        import traceback
        traceback.print_exc()
        for p in packages:
            p.setdefault("vulnerabilities", [])

    # --- Clean up package fields to use only CERT-IN 21 standard field names ---
    for pkg in packages:
        # Remove component_* prefix fields (use standard names instead)
        # CERT-IN 21 fields use: name, version, description, supplier, license, etc.
        
        # Keep only these standard CERT-IN fields:
        cert_in_fields = {
            # Field 1: Component Name
            "name": pkg.get("component_name") or pkg.get("name"),
            # Field 2: Component Version  
            "version": pkg.get("component_version") or pkg.get("version"),
            # Field 3: Component Description
            "description": pkg.get("component_description") or pkg.get("description", ""),
            # Field 4: Component Supplier
            "supplier": pkg.get("component_supplier") or pkg.get("supplier", ""),
            # Field 5: Component License
            "license": pkg.get("component_license") or pkg.get("license", "NOASSERTION"),
            # Field 6: Component Origin
            "origin": pkg.get("component_origin") or pkg.get("origin", "Unknown"),
            # Field 7: Component Dependencies
            "dependencies": pkg.get("component_dependencies") or pkg.get("dependencies", []),
            # Field 8: Vulnerabilities
            "vulnerabilities": pkg.get("vulnerabilities", []),
            # Field 9: Patch Status
            "patch_status": pkg.get("patch_status", "none"),
            # Field 10: Release Date
            "release_date": pkg.get("release_date", ""),
            # Field 11: EOL Date
            "eol_date": pkg.get("eol_date", ""),
            # Field 12: Criticality
            "criticality": pkg.get("criticality", "Low"),
            # Field 13: Usage Restrictions
            "usage_restrictions": pkg.get("usage_restrictions", "Unknown"),
            # Field 14: Hashes/Checksums
            "hashes": pkg.get("hashes", []),
            # Field 15: Comments/Notes
            "comments": pkg.get("comments", ""),
            # Field 16: Author of SBOM Data
            "author_of_sbom_data": pkg.get("author_of_sbom_data", "Tool: stacksqscanner"),
            # Field 17: Timestamp
            "timestamp": pkg.get("timestamp", datetime.now(timezone.utc).isoformat()),
            # Field 18: Executable Property
            "executable": pkg.get("executable", "No"),
            # Field 19: Archive Property
            "archive": pkg.get("archive", "No"),
            # Field 20: Structured Properties
            "structured_properties": pkg.get("structured_properties", "No"),
            # Field 21: Unique Identifier (PURL)
            "purl": pkg.get("unique_identifier") or pkg.get("purl"),
            
            # Additional useful fields (not part of CERT-IN 21)
            "language": pkg.get("language"),
            "type": pkg.get("type"),
            "sourcePath": pkg.get("sourcePath"),
        }
        
        # Clear package and add only clean fields
        pkg.clear()
        pkg.update(cert_in_fields)

    # --- 5) Build catalog
    catalog: Dict[str, Any] = {
        "packages": packages,
        "discovered_manifests": all_manifests,
        "workspace": str(workspace),
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Final summary printed exactly once
    print("[INFO] Scan summary:")
    print(f" - Manifests discovered: {len(all_manifests)}")
    print(f" - Unique packages found: {len(packages)}")
    # Always show vulnerabilities (they're always checked now)
    vuln_count = sum(len(p.get("vulnerabilities", [])) for p in packages)
    print(f" - Total vulnerabilities: {vuln_count}")

    return catalog, notices

