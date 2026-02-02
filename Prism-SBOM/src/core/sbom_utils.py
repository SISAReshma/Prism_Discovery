
from __future__ import annotations
from typing import Dict, Any, List
import urllib.parse
from src.utils.hash_utils import hashes_for_files
from src.utils.package_metadata_utils import (
    fetch_pypi_meta,
    extract_license_from_pypi_meta,
    extract_hashes_from_pypi_meta,
    fetch_npm_meta,
    extract_license_from_npm_meta,
    extract_hashes_from_npm_meta,
    infer_license_type,
)
from src.core import vulnerability_provider
from src.utils.license_utils import determine_usage_restrictions


def enrich_python_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a python package entry with:
      - PyPI metadata (description, author, release_date, license)
      - OSV vulnerability data
      - SHA256 file hashes
      - CERT fields fallback defaults
    """
    name = pkg.get("name")
    ver = pkg.get("version") or "UNKNOWN"

    # PRESERVE scanner enrichments (deps.dev data takes precedence over PyPI)
    scanner_enrichments = {
        "component_dependencies": pkg.get("component_dependencies"),
        "component_license": pkg.get("component_license"),
        "component_origin": pkg.get("component_origin"),
        "release_date": pkg.get("release_date"),
        "homepage": pkg.get("homepage"),
    }

    out = dict(pkg)  # copy

    # -----------------------------
    # 1) Ensure canonical PURL
    # -----------------------------
    if ver != "UNKNOWN":
        purl = f"pkg:pypi/{name}@{ver}"
    else:
        purl = f"pkg:pypi/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # -----------------------------
    # 2) PyPI metadata enrichment
    # -----------------------------
    try:
        pypi = fetch_pypi_meta(name, None if ver == "UNKNOWN" else ver)
        if pypi:
            info = pypi.get("info", {})

            # description
            desc = info.get("summary") or info.get("description") or ""
            out.setdefault("component_description", desc)

            # supplier/author
            author = info.get("author") or info.get("maintainer") or ""
            out.setdefault("component_supplier", author)

            # license - Overwrite if empty or NOASSERTION
            current_license = out.get("component_license") or out.get("license") or ""
            if not current_license or current_license.upper() == "NOASSERTION":
                lic = extract_license_from_pypi_meta(pypi)
                if lic and lic.upper() != "NOASSERTION":
                    out["component_license"] = lic
                    out["license"] = lic
            elif out.get("license") and not out.get("component_license"):
                # Cataloger set "license", copy to "component_license"
                out["component_license"] = out["license"]
            
            # hashes (SHA-256)
            from src.utils.package_metadata_utils import extract_hashes_from_pypi_meta, extract_release_date_from_pypi
            hashes = extract_hashes_from_pypi_meta(pypi, ver if ver != "UNKNOWN" else None)
            if hashes:
                out["hashes"] = hashes

            # release date - Don't overwrite if already set from cataloger (e.g., from git for dev versions)
            if not out.get("release_date"):
                release_date = extract_release_date_from_pypi(pypi, ver if ver != "UNKNOWN" else None)
                if release_date:
                    out["release_date"] = release_date

    except Exception:
        pass  # best-effort

    # -----------------------------
    # 3) Resolve dependencies list with version constraints
    # -----------------------------
    # Only process dependencies if not already enriched by deps.dev
    if not scanner_enrichments.get("component_dependencies"):
        import urllib.parse as urlparse
        raw_deps = pkg.get("dependencies", [])
        dep_purls = []
        for dep in raw_deps:
            if isinstance(dep, str):
                # Simple string dependency name - check if already PURL format
                if dep.startswith("pkg:"):
                    dep_purls.append(dep)
                else:
                    dep_purls.append(f"pkg:pypi/{dep}")
            elif isinstance(dep, dict):
                # Dict with name and optional version_constraint
                dep_name = dep.get("name")
                dep_constraint = dep.get("version_constraint", "")
                
                if dep.get("purl"):
                    # If PURL already exists, use it
                    dep_purls.append(dep.get("purl"))
                elif dep_name:
                    # Build PURL with optional version constraint
                    if dep_constraint and dep_constraint != "UNKNOWN" and dep_constraint.strip():
                        # Add version constraint as PURL qualifier
                        encoded_constraint = urlparse.quote(dep_constraint)
                        dep_purls.append(f"pkg:pypi/{dep_name}?version_constraint={encoded_constraint}")
                    else:
                        dep_purls.append(f"pkg:pypi/{dep_name}")
        out["component_dependencies"] = dep_purls
    else:
        # Preserve deps.dev enriched dependencies
        out["component_dependencies"] = scanner_enrichments["component_dependencies"]

    # -----------------------------
    # 4) Hash files for evidence (only if not already from PyPI)
    # -----------------------------
    if not out.get("hashes"):  # Only compute if hashes don't exist from PyPI
        locations = pkg.get("locations", [])
        file_paths = [loc.get("path") for loc in locations if loc.get("path")]
        try:
            if file_paths:  # Only if we have file paths
                out["hashes"] = hashes_for_files(file_paths)
            else:
                out.setdefault("hashes", [])
        except Exception:
            out.setdefault("hashes", [])

    # -----------------------------
    # 5) Vulnerability enrichment
    # -----------------------------
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("PyPI", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # patch status
    if out["vulnerabilities"]:
        has_fix = any(
            ("fixed" in (v.get("references") or {}))
            or v.get("fixed_versions")
            for v in out["vulnerabilities"]
        )
        out["patch_status"] = "fix_available" if has_fix else "unknown"
    else:
        out["patch_status"] = "none"

    # -----------------------------
    # 6) Fill CERT default fields
    # -----------------------------
    
    # ✅ Use centralized license_utils instead of hardcoded logic
    license_str = out.get("component_license", "")
    out.setdefault("usage_restrictions", determine_usage_restrictions(license_str))
    
    # Infer component origin from license using centralized function
    if not out.get("component_origin"):
        license_str = out.get("component_license", "")
        out["component_origin"] = infer_license_type(license_str)

    out.setdefault("eol_date", "Unknown") # PyPI does not provide EOL dates
    out.setdefault("criticality", "Medium") # Default criticality
    
    defaults = [
        "comments",
        "author_of_sbom_data",
        "timestamp",
        "executable",
        "archive",
        "structured_properties",
    ]
    for f in defaults:
        out.setdefault(f, "")

    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    # -----------------------------
    # 7) RESTORE scanner enrichments (deps.dev data takes precedence)
    # -----------------------------
    for key, value in scanner_enrichments.items():
        if value:  # Only restore if scanner provided a value
            out[key] = value

    return out


def enrich_npm_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an NPM package entry with:
      - NPM registry metadata (description, author, license)
      - SHA-512/SHA-1 hashes
      - OSV vulnerability data
      - CERT fields fallback defaults
    """
    name = pkg.get("name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)  # copy

    # -----------------------------
    # 1) Ensure canonical PURL
    # -----------------------------
    if ver != "UNKNOWN":
        purl = f"pkg:npm/{name}@{ver}"
    else:
        purl = f"pkg:npm/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # -----------------------------
    # 2) NPM metadata enrichment
    # -----------------------------
    try:
        # Fetch package-level metadata (for time field with all versions)
        npm_meta = fetch_npm_meta(name, None)  # Always fetch without version to get 'time' field
        if npm_meta:
            # description
            desc = npm_meta.get("description", "")
            out.setdefault("component_description", desc)

            # supplier/author
            author = npm_meta.get("author", "")
            if isinstance(author, dict):
                author = author.get("name", "")
            out.setdefault("component_supplier", str(author) if author else "")

            # license - check latest version or dist-tags
            if ver != "UNKNOWN":
                # Try to get license from specific version
                versions_data = npm_meta.get("versions", {})
                version_info = versions_data.get(ver, {})
                lic = version_info.get("license", "")
                if not lic:
                    # Fallback to package-level license
                    lic = npm_meta.get("license", "NOASSERTION")
            else:
                lic = npm_meta.get("license", "NOASSERTION")
            
            # Normalize license
            if isinstance(lic, dict):
                lic = lic.get("type", "NOASSERTION")
            out["component_license"] = lic or out.get("component_license", "NOASSERTION")
            
            # hashes (SHA-512/SHA-1) - from specific version
            if ver != "UNKNOWN":
                versions_data = npm_meta.get("versions", {})
                version_info = versions_data.get(ver, {})
                dist = version_info.get("dist", {})
                hashes = []
                if dist.get("integrity"):
                    integrity = dist["integrity"]
                    if integrity.startswith("sha512-"):
                        hashes.append({
                            "alg": "SHA-512",
                            "content": integrity.replace("sha512-", "")
                        })
                elif dist.get("shasum"):
                    hashes.append({
                        "alg": "SHA-1",
                        "content": dist["shasum"]
                    })
                if hashes:
                    out["hashes"] = hashes
            
            # release date from 'time' field
            from src.utils.package_metadata_utils import extract_release_date_from_npm
            release_date = extract_release_date_from_npm(npm_meta, ver if ver != "UNKNOWN" else None)
            if release_date:
                out["release_date"] = release_date

    except Exception:
        pass  # best-effort

    # -----------------------------
    # 3) Resolve dependencies list with version constraints
    # -----------------------------
    raw_deps = pkg.get("dependencies", [])
    dep_purls = []
    for dep in raw_deps:
        if isinstance(dep, str):
            # Simple string dependency name
            dep_purls.append(f"pkg:npm/{dep}")
        elif isinstance(dep, dict):
            # Dict with name and optional version_constraint
            dep_name = dep.get("name")
            dep_constraint = dep.get("version_constraint", "")
            
            if dep.get("purl"):
                # If PURL already exists, use it
                dep_purls.append(dep.get("purl"))
            elif dep_name:
                # Build PURL with optional version constraint
                if dep_constraint and dep_constraint != "UNKNOWN" and dep_constraint.strip():
                    # Add version constraint as PURL qualifier
                    encoded_constraint = urllib.parse.quote(dep_constraint)
                    dep_purls.append(f"pkg:npm/{dep_name}?version_constraint={encoded_constraint}")
                else:
                    dep_purls.append(f"pkg:npm/{dep_name}")
    out["component_dependencies"] = dep_purls

    # -----------------------------
    # 4) Vulnerability enrichment
    # -----------------------------
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("npm", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # patch status
    if out["vulnerabilities"]:
        has_fix = any(
            ("fixed" in (v.get("references") or {}))
            or v.get("fixed_versions")
            for v in out["vulnerabilities"]
        )
        out["patch_status"] = "fix_available" if has_fix else "unknown"
    else:
        out["patch_status"] = "none"

    # -----------------------------
    # 5) Fill CERT default fields
    # -----------------------------
    
    # ✅ Use centralized license_utils instead of hardcoded logic
    license_str = out.get("component_license", "")
    out.setdefault("usage_restrictions", determine_usage_restrictions(license_str))
    
    # Infer component origin from license using centralized function
    if not out.get("component_origin"):
        license_str = out.get("component_license", "")
        out["component_origin"] = infer_license_type(license_str)

    out.setdefault("eol_date", "Unknown") # NPM doesn't provide EOL dates
    out.setdefault("criticality", "Medium") # Default criticality
    
    defaults = [
        "comments",
        "author_of_sbom_data",
        "timestamp",
        "executable",
        "archive",
        "structured_properties",
    ]
    for f in defaults:
        out.setdefault(f, "")

    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out
