
from __future__ import annotations
from typing import Dict, Any, List
import urllib.parse
from sbom.src.utils.hash_utils import hashes_for_files
from sbom.src.clients.pypi_client import (
    fetch_pypi_meta,
    extract_license_from_pypi_meta,
    extract_hashes_from_pypi_meta,
    extract_release_date_from_pypi,
)
from sbom.src.clients.npm_client import (
    fetch_npm_meta,
    extract_license_from_npm_meta,
    extract_hashes_from_npm_meta,
    extract_release_date_from_npm,
    infer_license_type,
)
from sbom.src.clients.nuget_client import (
    fetch_nuget_meta,
    extract_license_from_nuget_meta,
    extract_release_date_from_nuget,
)
from sbom.src.clients.rubygems_client import (
    fetch_rubygems_meta,
    extract_license_from_rubygems_meta,
    extract_release_date_from_rubygems,
    extract_sha256_from_rubygems,
)
from sbom.src.clients.packagist_client import (
    fetch_packagist_meta,
    extract_license_from_packagist_meta,
    extract_release_date_from_packagist,
    extract_sha256_from_packagist,
    extract_authors_from_packagist,
)
from sbom.src.clients.cargo_client import (
    fetch_cargo_meta,
    extract_license_from_cargo_meta,
    extract_release_date_from_cargo,
    extract_checksum_from_cargo,
)
from sbom.src.clients.maven_client import (
    fetch_maven_meta,
    extract_license_from_maven_meta,
    extract_release_date_from_maven,
)
from sbom.src.clients.go_client import fetch_go_meta
from sbom.src.core import vulnerability_provider
from sbom.src.utils.license_utils import determine_usage_restrictions


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
    # Skip if registry_enrich already fetched this package's data.
    # _registry_enriched is set by orchestrator._apply_registry_info().
    # Without this guard generate-sbom would call PyPI a 2nd (and 3rd) time
    # for every Python package, exhausting the rate limit.
    if not pkg.get("_registry_enriched"):
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
                from sbom.src.clients.pypi_client import extract_hashes_from_pypi_meta, extract_release_date_from_pypi
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
    # Skip if registry_enrich already fetched this package's data.
    if not pkg.get("_registry_enriched"):
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
                from sbom.src.clients.npm_client import extract_release_date_from_npm
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


def enrich_dotnet_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a .NET/NuGet package entry with:
      - deps.dev metadata (primary)
      - deps.dev dependency graph (for transitive deps)
      - NuGet.org metadata (fallback)
      - OSV vulnerability data
      
    Fallback Strategy:
      1. deps.dev API (common fields + dependencies)
      2. NuGet API (for fields deps.dev doesn't have)
      3. Cache (if APIs fail)
    """
    name = pkg.get("name") or pkg.get("component_name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)

    # Build PURL
    if ver != "UNKNOWN":
        purl = f"pkg:nuget/{name}@{ver}"
    else:
        purl = f"pkg:nuget/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try deps.dev first
    try:
        from sbom.src.clients.depsdev_client import DepsDevClient
        depsdev = DepsDevClient()
        depsdev_meta = depsdev.get_package_info("nuget", name, ver) if ver != "UNKNOWN" else None
        
        if depsdev_meta:
            if not out.get("component_license"):
                licenses = depsdev_meta.get("licenses", [])
                if licenses:
                    out["component_license"] = licenses[0] if len(licenses) == 1 else ", ".join(licenses)
            
            if not out.get("component_description"):
                out["component_description"] = depsdev_meta.get("description", "")
                
            if not out.get("homepage"):
                links = depsdev_meta.get("links", [])
                homepage = ""
                for link in links:
                    if isinstance(link, dict):
                        label = link.get("label", "")
                        if label in ["HOMEPAGE", "SOURCE_REPO"]:
                            homepage = link.get("url", "")
                            break
                out["homepage"] = homepage or f"https://www.nuget.org/packages/{name}"
        
        # Fetch dependency graph from deps.dev
        if ver != "UNKNOWN" and not out.get("component_dependencies"):
            dep_graph = depsdev.get_dependency_graph("nuget", name, ver)
            if dep_graph:
                direct_deps = dep_graph.get("direct", [])
                if direct_deps:
                    formatted_deps = []
                    for dep in direct_deps:
                        dep_name = dep.get("name", "")
                        dep_version = dep.get("version", "unknown")
                        if dep_name:
                            formatted_deps.append({
                                "name": dep_name,
                                "version": dep_version,
                                "purl": f"pkg:nuget/{dep_name}@{dep_version}",
                                "relationship": "direct"
                            })
                    out["component_dependencies"] = formatted_deps
                    out["metadata_source"] = "deps.dev"
    except Exception as e:
        print(f"[WARN] deps.dev enrichment failed for NuGet {name}@{ver}: {e}")

    # Fallback to NuGet API
    if not out.get("component_license") or not out.get("release_date"):
        try:
            nuget_meta = fetch_nuget_meta(name, None if ver == "UNKNOWN" else ver)
            if nuget_meta:
                if not out.get("component_license"):
                    lic = extract_license_from_nuget_meta(nuget_meta)
                    if lic:
                        out["component_license"] = lic
                
                if not out.get("release_date"):
                    release_date = extract_release_date_from_nuget(nuget_meta)
                    if release_date:
                        out["release_date"] = release_date
                        
                if not out.get("component_description"):
                    out["component_description"] = nuget_meta.get("description", "")
                    
                if not out.get("component_supplier"):
                    authors = nuget_meta.get("authors", "")
                    if authors:
                        out["component_supplier"] = authors
        except Exception:
            pass

    # Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("NuGet", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://www.nuget.org/packages/{name}")
    out.setdefault("release_date", "Unknown")
    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Ruby (RubyGems) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_ruby_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Ruby gem package entry with:
      - RubyGems metadata (description, author, release_date, license)
      - OSV vulnerability data
      - SHA256 file hashes
      - CERT fields fallback defaults
    """
    name = pkg.get("name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)  # copy

    # 1) Ensure canonical PURL
    if ver != "UNKNOWN":
        purl = f"pkg:gem/{name}@{ver}"
    else:
        purl = f"pkg:gem/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # 2) RubyGems metadata enrichment
    try:
        rubygems_meta = fetch_rubygems_meta(name, None if ver == "UNKNOWN" else ver)
        if rubygems_meta:
            desc = rubygems_meta.get("info") or rubygems_meta.get("summary") or ""
            out.setdefault("component_description", desc)

            authors = rubygems_meta.get("authors") or ""
            out.setdefault("component_supplier", authors)

            current_license = out.get("component_license") or out.get("license") or ""
            if not current_license or current_license.upper() == "NOASSERTION":
                lic = extract_license_from_rubygems_meta(rubygems_meta)
                if lic and lic.upper() != "NOASSERTION":
                    out["component_license"] = lic
                    out["license"] = lic
            elif out.get("license") and not out.get("component_license"):
                out["component_license"] = out["license"]

            sha256 = extract_sha256_from_rubygems(rubygems_meta)
            if sha256:
                out["hashes"] = [{"alg": "SHA-256", "content": sha256}]

            if not out.get("release_date"):
                release_date = extract_release_date_from_rubygems(rubygems_meta)
                if release_date:
                    out["release_date"] = release_date

            homepage = rubygems_meta.get("homepage_uri") or rubygems_meta.get("project_uri") or ""
            if homepage:
                out.setdefault("homepage", homepage)

    except Exception:
        pass

    # 3) Resolve dependencies list
    raw_deps = pkg.get("dependencies") or []
    dep_purls = []
    for dep in raw_deps:
        if isinstance(dep, str):
            dep_purls.append(f"pkg:gem/{dep}")
        elif isinstance(dep, dict):
            dep_name = dep.get("name")
            dep_constraint = dep.get("version_constraint", "")
            if dep.get("purl"):
                dep_purls.append(dep.get("purl"))
            elif dep_name:
                if dep_constraint and dep_constraint != "UNKNOWN" and dep_constraint.strip():
                    encoded_constraint = urllib.parse.quote(dep_constraint)
                    dep_purls.append(f"pkg:gem/{dep_name}?version_constraint={encoded_constraint}")
                else:
                    dep_purls.append(f"pkg:gem/{dep_name}")
    out["component_dependencies"] = dep_purls

    # 4) Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("RubyGems", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    if out["vulnerabilities"]:
        has_fix = any(
            ("fixed" in (v.get("references") or {}))
            or v.get("fixed_versions")
            for v in out["vulnerabilities"]
        )
        out["patch_status"] = "fix_available" if has_fix else "unknown"
    else:
        out["patch_status"] = "none"

    # 5) Fill CERT default fields
    if not out.get("component_origin"):
        license_str = out.get("component_license", "")
        out["component_origin"] = infer_license_type(license_str)

    out.setdefault("eol_date", "Unknown")
    out.setdefault("criticality", "Medium")

    defaults = ["comments", "author_of_sbom_data", "timestamp", "executable", "archive", "structured_properties"]
    for f in defaults:
        out.setdefault(f, "")

    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  PHP (Packagist/Composer) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_php_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a PHP/Composer package entry with:
      - Packagist metadata (description, author, release_date, license)
      - OSV vulnerability data
      - SHA hashes
      - CERT fields fallback defaults
    """
    name = pkg.get("name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)

    if ver != "UNKNOWN":
        purl = f"pkg:composer/{name}@{ver}"
    else:
        purl = f"pkg:composer/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    try:
        packagist_meta = fetch_packagist_meta(name, None if ver == "UNKNOWN" else ver)
        if packagist_meta:
            desc = packagist_meta.get("description") or ""
            out.setdefault("component_description", desc)

            authors = extract_authors_from_packagist(packagist_meta)
            out.setdefault("component_supplier", authors)

            current_license = out.get("component_license") or out.get("license") or ""
            if not current_license or current_license.upper() == "NOASSERTION":
                lic = extract_license_from_packagist_meta(packagist_meta)
                if lic and lic.upper() != "NOASSERTION":
                    out["component_license"] = lic
                    out["license"] = lic
            elif out.get("license") and not out.get("component_license"):
                out["component_license"] = out["license"]

            sha = extract_sha256_from_packagist(packagist_meta)
            if sha:
                out["hashes"] = [{"alg": "SHA-1", "content": sha}]

            if not out.get("release_date"):
                release_date = extract_release_date_from_packagist(packagist_meta)
                if release_date:
                    out["release_date"] = release_date

            homepage = packagist_meta.get("homepage") or ""
            if homepage:
                out.setdefault("homepage", homepage)

    except Exception:
        pass

    raw_deps = pkg.get("dependencies") or []
    dep_purls = []
    for dep in raw_deps:
        if isinstance(dep, str):
            dep_purls.append(f"pkg:composer/{dep}")
        elif isinstance(dep, dict):
            dep_name = dep.get("name")
            dep_constraint = dep.get("version_constraint", "")
            if dep.get("purl"):
                dep_purls.append(dep.get("purl"))
            elif dep_name:
                if dep_constraint and dep_constraint != "UNKNOWN" and dep_constraint.strip():
                    encoded_constraint = urllib.parse.quote(dep_constraint)
                    dep_purls.append(f"pkg:composer/{dep_name}?version_constraint={encoded_constraint}")
                else:
                    dep_purls.append(f"pkg:composer/{dep_name}")
    out["component_dependencies"] = dep_purls

    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("Packagist", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    if out["vulnerabilities"]:
        has_fix = any(
            ("fixed" in (v.get("references") or {}))
            or v.get("fixed_versions")
            for v in out["vulnerabilities"]
        )
        out["patch_status"] = "fix_available" if has_fix else "unknown"
    else:
        out["patch_status"] = "none"

    if not out.get("component_origin"):
        license_str = out.get("component_license", "")
        out["component_origin"] = infer_license_type(license_str)

    out.setdefault("eol_date", "Unknown")
    out.setdefault("criticality", "Medium")

    defaults = ["comments", "author_of_sbom_data", "timestamp", "executable", "archive", "structured_properties"]
    for f in defaults:
        out.setdefault(f, "")

    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Go (golang) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_go_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Go package entry with:
      - deps.dev metadata (primary)
      - Go proxy metadata (fallback)
      - OSV vulnerability data
    """
    name = pkg.get("name") or pkg.get("module_path")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)

    if ver != "UNKNOWN":
        purl = f"pkg:golang/{urllib.parse.quote(name, safe='')}@{ver}"
    else:
        purl = f"pkg:golang/{urllib.parse.quote(name, safe='')}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try deps.dev first
    try:
        from sbom.src.clients.depsdev_client import DepsDevClient
        depsdev = DepsDevClient()
        depsdev_meta = depsdev.get_package_info("go", name, ver) if ver != "UNKNOWN" else None

        if depsdev_meta:
            if not out.get("component_license"):
                licenses = depsdev_meta.get("licenses", [])
                if licenses:
                    out["component_license"] = licenses[0] if len(licenses) == 1 else ", ".join(licenses)

            if not out.get("component_description"):
                out["component_description"] = depsdev_meta.get("description", "")

            if not out.get("homepage"):
                links = depsdev_meta.get("links", {})
                out["homepage"] = links.get("homepage") or links.get("repo") or f"https://pkg.go.dev/{name}"
    except Exception:
        pass

    # Fallback to Go proxy API
    if not out.get("component_description") or not out.get("release_date"):
        try:
            go_meta = fetch_go_meta(name, None if ver == "UNKNOWN" else ver)
            if go_meta:
                if not out.get("release_date"):
                    out["release_date"] = go_meta.get("time", "Unknown")
        except Exception:
            pass

    # Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("Go", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://pkg.go.dev/{name}")
    out.setdefault("release_date", "Unknown")
    out.setdefault("component_name", pkg.get("component_name") or name.split("/")[-1])
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Java (Maven) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_java_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Java/Maven package entry with:
      - deps.dev metadata (primary)
      - Maven Central metadata (fallback)
      - OSV vulnerability data
    """
    name = pkg.get("name") or ""
    ver = pkg.get("version") or "UNKNOWN"

    group_id = pkg.get("group_id", "")
    artifact_id = pkg.get("artifact_id", "")
    if not group_id and ":" in name:
        parts = name.split(":")
        group_id = parts[0]
        artifact_id = parts[1] if len(parts) > 1 else ""
    elif not artifact_id:
        artifact_id = name

    out = dict(pkg)

    if group_id and artifact_id:
        if ver != "UNKNOWN":
            purl = f"pkg:maven/{group_id}/{artifact_id}@{ver}"
        else:
            purl = f"pkg:maven/{group_id}/{artifact_id}"
    else:
        purl = f"pkg:maven/{name}@{ver}" if ver != "UNKNOWN" else f"pkg:maven/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try deps.dev first
    try:
        from sbom.src.clients.depsdev_client import DepsDevClient
        depsdev = DepsDevClient()
        pkg_name = f"{group_id}:{artifact_id}" if group_id else name
        depsdev_meta = depsdev.get_package_info("maven", pkg_name, ver) if ver != "UNKNOWN" else None

        if depsdev_meta:
            if not out.get("component_license"):
                licenses = depsdev_meta.get("licenses", [])
                if licenses:
                    out["component_license"] = licenses[0] if len(licenses) == 1 else ", ".join(licenses)

            if not out.get("component_description"):
                out["component_description"] = depsdev_meta.get("description", "")

            if not out.get("homepage"):
                links = depsdev_meta.get("links", {})
                out["homepage"] = links.get("homepage") or links.get("repo") or ""
    except Exception:
        pass

    # Fallback to Maven Central API
    if not out.get("component_license") or not out.get("release_date"):
        try:
            maven_meta = fetch_maven_meta(group_id, artifact_id, None if ver == "UNKNOWN" else ver)
            if maven_meta:
                if not out.get("component_license"):
                    lic = extract_license_from_maven_meta(maven_meta)
                    if lic:
                        out["component_license"] = lic

                if not out.get("release_date"):
                    release_date = extract_release_date_from_maven(maven_meta)
                    if release_date:
                        out["release_date"] = release_date

                if not out.get("component_description"):
                    out["component_description"] = maven_meta.get("description", "")

                if not out.get("homepage"):
                    out["homepage"] = maven_meta.get("homepage") or maven_meta.get("url") or ""
        except Exception:
            pass

    # Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv_name = f"{group_id}:{artifact_id}" if group_id else name
            osv = vulnerability_provider.query_osv_package("Maven", osv_name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}" if group_id else "N/A")
    out.setdefault("release_date", "Unknown")
    out.setdefault("component_name", pkg.get("component_name") or artifact_id or name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Rust (Cargo/crates.io) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_rust_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Rust/Cargo package entry with:
      - deps.dev metadata (primary)
      - crates.io metadata (fallback)
      - OSV vulnerability data
    """
    name = pkg.get("name") or pkg.get("component_name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)

    if ver != "UNKNOWN":
        purl = f"pkg:cargo/{name}@{ver}"
    else:
        purl = f"pkg:cargo/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try deps.dev first
    try:
        from sbom.src.clients.depsdev_client import DepsDevClient
        depsdev = DepsDevClient()
        depsdev_meta = depsdev.get_package_info("cargo", name, ver) if ver != "UNKNOWN" else None

        if depsdev_meta:
            if not out.get("component_license"):
                licenses = depsdev_meta.get("licenses", [])
                if licenses:
                    out["component_license"] = licenses[0] if len(licenses) == 1 else ", ".join(licenses)

            if not out.get("component_description"):
                out["component_description"] = depsdev_meta.get("description", "")

            if not out.get("homepage"):
                links = depsdev_meta.get("links", {})
                out["homepage"] = links.get("homepage") or links.get("repo") or f"https://crates.io/crates/{name}"
    except Exception:
        pass

    # Fallback to crates.io API
    if not out.get("component_license") or not out.get("release_date"):
        try:
            cargo_meta = fetch_cargo_meta(name, None if ver == "UNKNOWN" else ver)
            if cargo_meta:
                if not out.get("component_license"):
                    lic = extract_license_from_cargo_meta(cargo_meta)
                    if lic:
                        out["component_license"] = lic

                if not out.get("release_date"):
                    release_date = extract_release_date_from_cargo(cargo_meta)
                    if release_date:
                        out["release_date"] = release_date

                if not out.get("component_description"):
                    crate = cargo_meta.get("crate", {})
                    out["component_description"] = crate.get("description", "")

                if not out.get("component_supplier"):
                    version_info = cargo_meta.get("version", {})
                    authors = version_info.get("authors", [])
                    if authors:
                        out["component_supplier"] = authors[0] if isinstance(authors[0], str) else "Unknown"

                if not out.get("hashes"):
                    checksum = extract_checksum_from_cargo(cargo_meta)
                    if checksum:
                        out["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        except Exception:
            pass

    # Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("crates.io", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://crates.io/crates/{name}")
    out.setdefault("release_date", "Unknown")
    out.setdefault("hashes", [])
    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Swift (CocoaPods / SPM) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_swift_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Swift/CocoaPods package entry with:
      - CocoaPods trunk API
      - OSV vulnerability data
    """
    name = pkg.get("name") or pkg.get("component_name")
    ver = pkg.get("version") or "UNKNOWN"

    out = dict(pkg)

    if ver != "UNKNOWN":
        purl = f"pkg:cocoapods/{name}@{ver}"
    else:
        purl = f"pkg:cocoapods/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try CocoaPods trunk API
    try:
        import requests
        from sbom.src.config.config import COCOAPODS_API, API_TIMEOUT

        url = f"{COCOAPODS_API}/pods/{name}"
        resp = requests.get(url, timeout=API_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()

            if not out.get("component_description"):
                out["component_description"] = data.get("summary", "")

            if not out.get("homepage"):
                out["homepage"] = data.get("homepage") or f"https://cocoapods.org/pods/{name}"

            if not out.get("component_license"):
                license_info = data.get("license", {})
                if isinstance(license_info, dict):
                    out["component_license"] = license_info.get("type", "NOASSERTION")
                elif isinstance(license_info, str):
                    out["component_license"] = license_info

            if not out.get("component_supplier"):
                authors = data.get("authors", {})
                if isinstance(authors, dict):
                    out["component_supplier"] = ", ".join(authors.keys()) if authors else "Unknown"
                elif isinstance(authors, str):
                    out["component_supplier"] = authors
    except Exception:
        pass

    # Vulnerability enrichment
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("CocoaPods", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://cocoapods.org/pods/{name}")
    out.setdefault("release_date", "Unknown")
    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out


# ──────────────────────────────────────────────────────────────────────
#  Conda (Anaconda) enrichment
# ──────────────────────────────────────────────────────────────────────
def enrich_conda_pkg(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a Conda package entry with:
      - Anaconda.org API
      - OSV vulnerability data
    """
    name = pkg.get("name") or pkg.get("component_name")
    ver = pkg.get("version") or "UNKNOWN"
    channel = pkg.get("channel", "conda-forge")

    out = dict(pkg)

    if ver != "UNKNOWN":
        purl = f"pkg:conda/{channel}/{name}@{ver}"
    else:
        purl = f"pkg:conda/{channel}/{name}"
    out["purl"] = purl
    out["unique_identifier"] = purl

    # Try Anaconda.org API
    try:
        from sbom.src.clients.anaconda_client import AnacondaClient
        client = AnacondaClient()
        conda_meta = client.get_package_info(name, channel)

        if conda_meta:
            if not out.get("component_description"):
                out["component_description"] = conda_meta.get("summary", "") or conda_meta.get("description", "")

            if not out.get("homepage"):
                out["homepage"] = conda_meta.get("home") or conda_meta.get("dev_url") or f"https://anaconda.org/{channel}/{name}"

            if not out.get("component_license"):
                out["component_license"] = conda_meta.get("license", "NOASSERTION")

            if not out.get("component_supplier"):
                out["component_supplier"] = conda_meta.get("owner", "Unknown")
    except Exception:
        pass

    # Vulnerability enrichment - Use PyPI as proxy since many conda packages are Python packages
    try:
        if pkg.get("vulnerabilities"):
            out["vulnerabilities"] = pkg["vulnerabilities"]
        else:
            osv = vulnerability_provider.query_osv_package("PyPI", name, None if ver == "UNKNOWN" else ver) or []
            out["vulnerabilities"] = vulnerability_provider.normalize_osv_entries(osv)
    except Exception:
        out["vulnerabilities"] = []

    # Fill defaults
    out.setdefault("component_description", "No description available")
    out.setdefault("component_supplier", "Unknown")
    out.setdefault("component_license", "NOASSERTION")
    out.setdefault("homepage", f"https://anaconda.org/{channel}/{name}")
    out.setdefault("release_date", "Unknown")
    out.setdefault("component_name", name)
    out.setdefault("component_version", ver)

    return out
