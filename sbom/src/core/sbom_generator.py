from typing import Dict, Any, List
import json
from datetime import datetime, timezone
from copy import deepcopy
from sbom.src.core.sbom_utils import (
    enrich_python_pkg,
    enrich_npm_pkg,
    enrich_ruby_pkg,
    enrich_php_pkg,
    enrich_go_pkg,
    enrich_java_pkg,
    enrich_rust_pkg,
    enrich_dotnet_pkg,
    enrich_swift_pkg,
    enrich_conda_pkg,
)

# Configuration
from sbom.src.config import config
from sbom.src.registry.language_registry import get_purl_type


def _generate_cpe(name: str, version: str, vendor: str = "*", language: str = "") -> str:
    """
    Generate CPE 2.3 identifier for a package.
    Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """
    # Normalize inputs
    name = name.lower().replace(" ", "_").replace("-", "_")
    version = version.replace("UNKNOWN", "*")
    vendor = vendor.lower().replace(" ", "_") if vendor and vendor != "*" else "*"
    
    # For NPM/PyPI, we don't always know the vendor, use package name as fallback
    if vendor == "*":
        # Try to extract vendor from scoped packages (@org/name)
        if "/" in name:
            parts = name.split("/")
            vendor = parts[0].replace("@", "")
            name = parts[1]
    
    return f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"


def _extract_external_refs(pkg: Dict[str, Any], metadata: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract external references (homepage, repository, etc.) from package metadata."""
    refs = []
    language = pkg.get("language", "").lower()
    name = pkg.get("name") or pkg.get("component_name")
    version = pkg.get("version") or pkg.get("component_version")
    
    # Try to get from enriched metadata in properties
    props = pkg.get("properties", []) if isinstance(pkg.get("properties"), list) else []
    
    # Look for metadata stored during enrichment
    if language == "python":
        # PyPI URLs (use config)
        if name:
            refs.append({
                "type": "distribution",
                "url": config.get_download_location("pypi", name)
            })
    elif language in ["javascript", "node"]:
        # NPM URLs (use config)
        if name:
            refs.append({
                "type": "distribution",
                "url": config.get_download_location("npm", name)
            })
    
    # Add homepage if available
    homepage = pkg.get("homepage") or pkg.get("home_page")
    if homepage and homepage not in ["", "NOASSERTION", "Unknown"]:
        refs.append({
            "type": "website",
            "url": homepage
        })
    
    # Add repository if available
    repository = pkg.get("repository") or pkg.get("project_url")
    if repository and repository not in ["", "NOASSERTION", "Unknown"]:
        refs.append({
            "type": "vcs",
            "url": repository
        })
    
    return refs



CERT21_FIELDS = [
    "component_name", "component_version", "component_description", "component_supplier", "component_license",
    "component_dependencies", "vulnerabilities", "patch_status", "release_date",
    "criticality", "hashes", "unique_identifier", "homepage", "dependency_type",
    "eol_status", "is_deprecated"
]


def _ensure_repo_meta(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure metadata has required fields, using config for tool info."""
    m = deepcopy(metadata or {})
    m.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    m.setdefault("tool", {
        "name": config.TOOL_NAME,
        "vendor": config.TOOL_VENDOR,
        "version": config.TOOL_VERSION
    })
    return m


def _normalize_pkg(pkg: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a package entry into strictly CERT-21 fields.
    """
    # Language-specific enrichment with fallback strategy:
    # deps.dev (primary) → registry API (fallback) → cache

    language = pkg.get("language", "").lower()

    # Enrich based on language
    if language == "python":
        pkg = enrich_python_pkg(pkg)
    elif language in ["javascript", "node"]:
        pkg = enrich_npm_pkg(pkg)
    elif language in ["ruby", "gem"]:
        pkg = enrich_ruby_pkg(pkg)
    elif language in ["php", "composer"]:
        pkg = enrich_php_pkg(pkg)
    elif language in ["go", "golang"]:
        pkg = enrich_go_pkg(pkg)
    elif language in ["java", "maven", "gradle"]:
        pkg = enrich_java_pkg(pkg)
    elif language in ["rust", "cargo"]:
        pkg = enrich_rust_pkg(pkg)
    elif language in ["dotnet", ".net", "csharp", "nuget"]:
        pkg = enrich_dotnet_pkg(pkg)
    elif language in ["swift", "cocoapods", "pods"]:
        pkg = enrich_swift_pkg(pkg)
    elif language in ["conda", "anaconda"]:
        pkg = enrich_conda_pkg(pkg)

    # 1. Map internal keys to CERT-21 keys
    mapped = {}
    
    # Basic mappings
    mapped["component_name"] = pkg.get("component_name") or pkg.get("name") or "UNKNOWN"
    
    # Clean version string - strip operators like ==, >=, etc.
    raw_version = pkg.get("component_version") or pkg.get("version") or "UNKNOWN"
    if raw_version and raw_version != "UNKNOWN":
        # Strip leading operators: ==, >=, <=, ~=, !=, <, >, ^, ~
        import re
        cleaned_version = re.sub(r'^[=<>!~^]+', '', str(raw_version)).strip()
        mapped["component_version"] = cleaned_version
    else:
        mapped["component_version"] = raw_version
    
    mapped["component_description"] = pkg.get("component_description") or pkg.get("description") or "No description available"
    mapped["component_supplier"] = pkg.get("component_supplier") or pkg.get("supplier") or "Unknown"
    mapped["homepage"] = pkg.get("homepage") or pkg.get("home_page") or "N/A"
    
    # License: Check both fields, but handle empty strings and invalid values properly
    # Don't fall back to NOASSERTION if we have a real license string
    license_value = pkg.get("component_license") or pkg.get("license")
    invalid_licenses = ("", "NOASSERTION", "non-standard", "unknown", "N/A", None)
    if license_value and license_value not in invalid_licenses:
        mapped["component_license"] = license_value
    else:
        mapped["component_license"] = "NOASSERTION"
    
    # Dependencies
    deps_from_component = pkg.get("component_dependencies", [])
    deps_from_plain = pkg.get("dependencies", [])
    deps = deps_from_component or deps_from_plain
    # Use [0] to explicitly indicate zero dependencies (vs unknown/unscanned)
    mapped["component_dependencies"] = deps if deps else []
    
    # Vulnerabilities: pass through
    vulnerabilities = pkg.get("vulnerabilities", [])
    # Use empty array to indicate zero vulnerabilities found (vs unknown)
    mapped["vulnerabilities"] = vulnerabilities if vulnerabilities else []
    
    # Patch status: Calculate based on vulnerabilities (CERT-IN format)
    patch_status = pkg.get("patch_status")
    if not patch_status or patch_status.lower() in ["", "unknown", "none"]:
        from sbom.src.utils.patch_utils import determine_patch_status
        pkg_version = pkg.get("component_version") or pkg.get("version", "")
        patch_status = determine_patch_status(pkg_version, vulnerabilities)
    mapped["patch_status"] = patch_status

    
    # Dates
    mapped["release_date"] = pkg.get("release_date") or "Unknown"
    
    # Criticality: Use pre-calculated value or calculate
    criticality = pkg.get("criticality")
    if not criticality or criticality.lower() in ["", "unknown"]:
        from sbom.src.core.vulnerability_provider import calculate_criticality
        criticality = calculate_criticality(pkg)
    mapped["criticality"] = criticality
    
    # Hashes
    hashes = pkg.get("hashes", [])
    # Use empty array to indicate zero hashes (registry had none)
    mapped["hashes"] = hashes if hashes else []
    
    # Dependency type (direct/transitive)
    is_direct = pkg.get("is_direct_dependency", pkg.get("is_direct", True))
    mapped["dependency_type"] = "direct" if is_direct else "transitive"
    
    # Unique Identifier (CERT-IN compliant PURL with supplier prefix)
    # Always generate CERT-IN format, ignore any existing simple PURL from cataloger
    language = pkg.get("language", "").lower()
    ecosystem = get_purl_type(language)
    supplier = mapped.get("component_supplier", "")
    
    # Generate CERT-IN format: pkg:supplier/SupplierName/PackageName@version?arch=x86_64&os=linux
    purl = config.generate_cert_in_identifier(
        ecosystem=ecosystem,
        name=mapped["component_name"],
        version=mapped["component_version"],
        supplier=supplier
    )
    
    mapped["unique_identifier"] = purl
    
    # EOL Status and Deprecation
    mapped["eol_status"] = pkg.get("eol_status", "Unknown")
    mapped["is_deprecated"] = pkg.get("is_deprecated", False)

    # 2. Construct final dict with ONLY the 21 fields
    final_pkg = {k: mapped.get(k, "") for k in CERT21_FIELDS}
    
    # 3. Preserve additional fields from original package (needed for SBOM generation)
    # is_direct_dependency: needed for JSON SBOM direct/transitive split
    if "is_direct_dependency" in pkg:
        final_pkg["is_direct_dependency"] = pkg["is_direct_dependency"]
    
    # language: needed for CPE generation and external refs in CycloneDX
    if "language" in pkg:
        final_pkg["language"] = pkg["language"]
    
    return final_pkg


def _build_components(catalog: Dict[str, Any], meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = []
    
    # First pass: Normalize all packages and build name->PURL mapping
    normalized_packages = []
    purl_map = {}  # Maps simple package names to CERT-IN PURLs
    detail_map = {}  # Maps CERT-IN PURL to details for nested views
    
    for pkg in catalog.get("packages", []):
        norm = _normalize_pkg(pkg, meta)
        normalized_packages.append(norm)
        
        # Build mapping: "Flask" -> "pkg:supplier/Pallets/Flask@3.0.0?arch=x86_64&os=linux"
        pkg_name = norm.get("component_name")
        unique_id = norm.get("unique_identifier")
        if pkg_name and unique_id:
            purl_map[pkg_name] = unique_id
            # Also map common variations
            purl_map[pkg_name.lower()] = unique_id
            purl_map[pkg_name.replace("-", "_")] = unique_id
            purl_map[pkg_name.replace("_", "-")] = unique_id
            detail_map[unique_id] = {
                "purl": unique_id,
                "name": norm.get("component_name"),
                "version": norm.get("component_version"),
                "supplier": norm.get("component_supplier")
            }

    # Second pass: Build CycloneDX components with updated dependencies
    for norm in normalized_packages:
        # Update component_dependencies to use CERT-IN format PURLs
        deps = norm.get("component_dependencies", [])
        if deps:
            updated_deps = []
            detailed_deps = []
            for dep_purl in deps:
                # Extract package name from simple PURL like "pkg:pypi/Flask"
                if "/" in dep_purl:
                    dep_name = dep_purl.split("/")[-1].split("@")[0]
                    # Look up the CERT-IN PURL for this dependency
                    cert_in_purl = purl_map.get(dep_name) or purl_map.get(dep_name.lower())
                    final_purl = cert_in_purl if cert_in_purl else dep_purl
                    updated_deps.append(final_purl)
                    detailed_deps.append(detail_map.get(final_purl, {"purl": final_purl}))
                else:
                    updated_deps.append(dep_purl)
                    detailed_deps.append(detail_map.get(dep_purl, {"purl": dep_purl}))
            norm["component_dependencies"] = updated_deps
        else:
            detailed_deps = []
        
        # Fields to exclude from properties (will be in dedicated nested fields)
        exclude_from_props = {"component_dependencies", "vulnerabilities"}
        
        # Build properties as flat dict (key: value) instead of [{name, value}] array
        props = {
            k: v
            for k, v in norm.items()
            if k not in exclude_from_props
        }

        name = norm.get("component_name")
        version = norm.get("component_version")
        supplier_name = norm.get("component_supplier")
        language = norm.get("language", "")
        
        # Extract group from scoped NPM packages
        group = None
        if language in ["javascript", "node"] and name and "/" in name and name.startswith("@"):
            group = name.split("/")[0].replace("@", "")
        
        # Generate CPE
        cpe = _generate_cpe(name=name, version=version, vendor="*", language=language)
        
        # Extract external references
        external_refs = _extract_external_refs(norm, meta)
        
        # Determine scope (dev vs required)
        # Default to "required", could be enhanced to detect devDependencies
        scope = "required"

        comp = {
            "bom-ref": norm.get("unique_identifier"),
            "type": "library",
            "group": group,  # NPM scope
            "name": norm.get("component_name"),
            "version": norm.get("component_version"),
            "scope": scope,  # required/optional
            "licenses": [
                {"license": {"id": norm.get("component_license", "NOASSERTION")}}
            ],
            "purl": norm.get("unique_identifier"), # purl is mapped to unique_identifier
            "cpe": cpe,  # CPE 2.3 identifier
            "externalReferences": external_refs if external_refs else None,
            "properties": props,
            "hashes": norm.get("hashes", []),
            "supplier": {"name": norm.get("component_supplier")} if norm.get("component_supplier") else None,
            "description": norm.get("component_description"),
            "component_dependencies": detailed_deps,  # Nested array (not JSON string)
            "vulnerabilities": norm.get("vulnerabilities", [])  # Nested array (not JSON string)
        }
        
        # Remove None values to keep JSON clean
        comp = {k: v for k, v in comp.items() if v is not None}
        
        comps.append(comp)

    return comps


def _mk_cyclonedx_dict(catalog: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return CycloneDX document as dict (not serialized string).
    """
    comps = _build_components(catalog, meta)
    
    # Extract vulnerabilities for root-level list
    vulns_list = []
    for comp in comps:
        # Get vulnerabilities directly from nested array (not from properties)
        v_data = comp.get("vulnerabilities", [])
        for v in v_data:
            # Map to CycloneDX vulnerability format
            cdx_vuln = {
                "id": v.get("id"),
                "source": {"name": v.get("source", "OSV")},
                "description": v.get("summary"),
                "affects": [{"ref": comp["bom-ref"]}]
            }
            
            # Map severity — use severity_level (parsed by OSV client) for the
            # CycloneDX rating, and the raw CVSS vector string for the vector field.
            sev_str = v.get("severity", "Unknown")        # raw CVSS vector or keyword
            sev_level = v.get("severity_level", "")       # parsed: CRITICAL/HIGH/MEDIUM/LOW
            
            if sev_str and sev_str != "Unknown":
                # Map parsed severity_level to CycloneDX severity enum
                cdx_severity_map = {
                    "CRITICAL": "critical",
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "low",
                    "NONE": "low",
                }
                cdx_sev = cdx_severity_map.get(sev_level.upper(), "high") if sev_level else "high"
                
                rating = {
                    "source": {"name": "CVSS"},
                    "severity": cdx_sev
                }
                
                sev_upper = str(sev_str).upper()
                if "CVSS:4" in sev_upper:
                    rating["vector"] = str(sev_str)
                    rating["method"] = "CVSSv4"
                elif "CVSS:3" in sev_upper:
                    rating["vector"] = str(sev_str)
                    rating["method"] = "CVSSv31" if "CVSS:3.1" in sev_upper else "CVSSv3"
                elif "CVSS:2" in sev_upper:
                    rating["vector"] = str(sev_str)
                    rating["method"] = "CVSSv2"
                elif "CVSS" in sev_upper:
                    rating["vector"] = str(sev_str)
                    rating["method"] = "CVSSv3"
                # else: keyword severity (HIGH, CRITICAL etc.) — no vector, just severity
                
                cdx_vuln["ratings"] = [rating]
                
            # References
            if v.get("references"):
                cdx_vuln["advisories"] = [{"url": r} for r in v.get("references")]
                
            vulns_list.append(cdx_vuln)

    # Extract dependencies graph from nested array (not from properties)
    dependencies = []
    for comp in comps:
        ref = comp["bom-ref"]
        comp_deps = comp.get("component_dependencies", [])
        if comp_deps:
            # Extract just the PURL from detailed deps
            deps_purls = []
            for dep in comp_deps:
                if isinstance(dep, dict):
                    deps_purls.append(dep.get("purl", ""))
                else:
                    deps_purls.append(str(dep))
            if deps_purls:
                dependencies.append({
                    "ref": ref,
                    "dependsOn": deps_purls
                })

    # Clean up: Remove component_dependencies and vulnerabilities from individual
    # components — they're now in the root-level "dependencies" and "vulnerabilities"
    # sections per CycloneDX spec.  Keeping them inside each component produces
    # redundant empty arrays ("component_dependencies": [], "vulnerabilities": []).
    for comp in comps:
        comp.pop("component_dependencies", None)
        comp.pop("vulnerabilities", None)

    # Build key-value components map (component_name -> component)
    components_map: Dict[str, Any] = {}
    for comp in comps:
        key = comp.get("name") or comp.get("bom-ref") or ""
        if key:
            components_map[key] = comp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": meta["timestamp"],
            "tools": [meta["tool"]],
            "component": {"type": "application", "name": meta.get("source", "")}
        },
        "components": components_map,
        "dependencies": dependencies,
        "vulnerabilities": vulns_list
    }


def _mk_spdx_dict(catalog: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return SPDX document as dict (not serialized).
    """
    packages_spdx = []
    relationships = []
    purl_to_spdxid = {}
    normalized_pkgs = []
    purl_map = {}  # Maps simple package names to CERT-IN PURLs

    # First pass: Create packages and build maps
    for p in catalog.get("packages", []):
        norm = _normalize_pkg(p, meta)
        normalized_pkgs.append(norm)
        
        spdx_id = f"SPDXRef-Package-{(norm.get('component_name') or '').replace(' ', '-')}"
        unique_id = norm.get("unique_identifier")
        if unique_id:
            purl_to_spdxid[unique_id] = spdx_id
        
        # Build name->PURL mapping for dependency resolution
        pkg_name = norm.get("component_name")
        if pkg_name and unique_id:
            purl_map[pkg_name] = unique_id
            purl_map[pkg_name.lower()] = unique_id
            purl_map[pkg_name.replace("-", "_")] = unique_id
            purl_map[pkg_name.replace("_", "-")] = unique_id
            
        # Determine download location
        download_location = "NOASSERTION"
        language = p.get("language", "").lower()
        pkg_name = norm.get("component_name")
        if language == "python" and pkg_name:
            download_location = config.get_download_location("pypi", pkg_name)
        elif language in ["javascript", "node"] and pkg_name:
            download_location = config.get_download_location("npm", pkg_name)
        
        # Build SPDX package with all CERT-21 fields
        deps_for_comment = norm.get("component_dependencies", [])
        comment_text = norm.get("comments")
        if not comment_text:
            comment_text = f"Dependencies: {len(deps_for_comment)}" if deps_for_comment else "No dependencies"

        spdx_pkg = {
            "SPDXID": spdx_id,
            "name": norm.get("component_name"),
            "versionInfo": norm.get("component_version"),
            "licenseConcluded": norm.get("component_license", "NOASSERTION"),
            "downloadLocation": download_location,
            "filesAnalyzed": False,
            "supplier": f"Person: {norm.get('component_supplier')}" if norm.get("component_supplier") else "NOASSERTION",
            "description": norm.get("component_description", ""),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": norm.get("unique_identifier")
                }
            ] if norm.get("unique_identifier") else [],
            "comment": comment_text,
            # Add all CERT-21 fields as annotations
            "annotations": [
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "OTHER",
                    "annotationDate": meta["timestamp"],
                    "comment": f"component_dependencies: {json.dumps(norm.get('component_dependencies', []))}"
                },
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "SECURITY",
                    "annotationDate": meta["timestamp"],
                    "comment": f"vulnerabilities_count: {len(norm.get('vulnerabilities', []))}"
                },
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "SECURITY",
                    "annotationDate": meta["timestamp"],
                    "comment": f"patch_status: {norm.get('patch_status', '')}"
                },
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "OTHER",
                    "annotationDate": meta["timestamp"],
                    "comment": f"release_date: {norm.get('release_date', '')}"
                },
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "SECURITY",
                    "annotationDate": meta["timestamp"],
                    "comment": f"criticality: {norm.get('criticality', '')}"
                },
                {
                    "annotator": f"Tool: {config.TOOL_NAME}",
                    "annotationType": "OTHER",
                    "annotationDate": meta["timestamp"],
                    "comment": f"hashes: {json.dumps(norm.get('hashes', []))}"
                }
            ]
        }
        
        # Add checksums if available
        if norm.get("hashes"):
            spdx_pkg["checksums"] = [
                {
                    "algorithm": h.get("alg", "SHA-512"),
                    "checksumValue": h.get("content", "")
                }
                for h in norm.get("hashes", [])
            ]
        
        packages_spdx.append(spdx_pkg)

    # Second pass: Build relationships with updated dependency PURLs
    for norm in normalized_pkgs:
        spdx_id = f"SPDXRef-Package-{(norm.get('component_name') or '').replace(' ', '-')}"
        
        # Get dependencies and convert to CERT-IN format PURLs
        deps = norm.get("component_dependencies", [])
        for dep_purl in deps:
            # Extract package name from simple PURL like "pkg:pypi/Flask"
            cert_in_purl = dep_purl
            if "/" in dep_purl:
                dep_name = dep_purl.split("/")[-1].split("@")[0]
                # Look up the CERT-IN PURL for this dependency
                cert_in_purl = purl_map.get(dep_name) or purl_map.get(dep_name.lower()) or dep_purl
            
            # Build relationship using CERT-IN PURL
            if cert_in_purl in purl_to_spdxid:
                relationships.append({
                    "spdxElementId": spdx_id,
                    "relatedSpdxElement": purl_to_spdxid[cert_in_purl],
                    "relationshipType": "DEPENDS_ON"
                })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": meta.get("source", "SBOM"),
        "documentNamespace": f"http://spdx.org/spdxdocs/{meta.get('source', 'sbom')}-{meta['timestamp']}",
        "creationInfo": {
            "creators": [f"Tool: {meta['tool']['name']}-{meta['tool']['version']}"],
            "created": meta["timestamp"]
        },
        "packages": packages_spdx,
        "relationships": relationships
    }


def _mk_json_sbom(catalog: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a simple JSON SBOM representation with summary and direct_dependencies.
    
    Separates packages into direct (from manifest) and transitive (dependencies of those).
    Groups components by language for multi-language repos.
    The cataloger marks each package with is_direct_dependency=True/False.
    """
    components = []
    purl_map = {}
    
    # First pass: normalize packages and build PURL mapping
    for p in catalog.get("packages", []):
        norm = _normalize_pkg(p, meta)
        components.append(norm)
        
        # Build mapping: package name -> CERT-IN PURL
        pkg_name = norm.get("component_name")
        unique_id = norm.get("unique_identifier")
        if pkg_name and unique_id:
            purl_map[pkg_name] = unique_id
            # Map common variations (case, dash/underscore)
            purl_map[pkg_name.lower()] = unique_id
            purl_map[pkg_name.replace("-", "_")] = unique_id
            purl_map[pkg_name.replace("_", "-")] = unique_id
    
    # Second pass: update component dependencies to use CERT-IN PURLs
    # Only include dependencies that exist in the catalog (scanned components)
    for comp in components:
        deps = comp.get("component_dependencies", [])
        if deps:
            updated_deps = []
            for dep_purl in deps:
                # Extract package name from old PURL like "pkg:pypi/Flask"
                if "/" in dep_purl:
                    dep_name = dep_purl.split("/")[-1].split("@")[0]
                    # Look up the CERT-IN PURL for this dependency
                    cert_in_purl = purl_map.get(dep_name) or purl_map.get(dep_name.lower())
                    # Only include if the dependency was scanned and is in our catalog
                    if cert_in_purl:
                        updated_deps.append(cert_in_purl)
                    # Skip dependencies not in catalog (transitive/dev deps not scanned)
                else:
                    updated_deps.append(dep_purl)
            comp["component_dependencies"] = updated_deps
    
    # Separate direct and transitive dependencies based on is_direct_dependency field
    direct_deps = [c for c in components if c.get("is_direct_dependency") == True]
    transitive_deps = [c for c in components if c.get("is_direct_dependency") != True]

    discovered_manifests = catalog.get("discovered_manifests") or catalog.get("manifests", [])
    workspace = catalog.get("workspace") or catalog.get("source", "")
    
    # Get license_detection from catalog (passed from API/CLI)
    license_detection = catalog.get("license_detection") or catalog.get("repo_license")

    result = {
        "metadata": {
            "timestamp": meta["timestamp"],
            "tool": meta["tool"],
            "source": meta.get("source", "")
        },
        "summary": {
            "total_components": len(components),
            "direct_dependencies": len(direct_deps),
            "transitive_dependencies": len(transitive_deps)
        },
        "direct_dependencies": direct_deps,
        "transitive_dependencies": transitive_deps,
        "discovered_manifests": discovered_manifests,
        "workspace": workspace
    }
    
    # Add license_detection if available
    if license_detection:
        result["license_detection"] = license_detection
    
    return result


def generate_json_sbom(catalog: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate JSON SBOM format only.
    
    Args:
        catalog: Package catalog from orchestrator
        metadata: Scan metadata
        
    Returns:
        JSON SBOM dictionary
    """
    meta = _ensure_repo_meta(metadata)
    return _mk_json_sbom(catalog, meta)


def generate_spdx_sbom(catalog: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate SPDX SBOM format only.
    
    Args:
        catalog: Package catalog from orchestrator
        metadata: Scan metadata
        
    Returns:
        SPDX SBOM dictionary
    """
    meta = _ensure_repo_meta(metadata)
    return _mk_spdx_dict(catalog, meta)


def generate_cyclonedx_sbom(catalog: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate CycloneDX SBOM format only.
    
    Args:
        catalog: Package catalog from orchestrator
        metadata: Scan metadata
        
    Returns:
        CycloneDX SBOM dictionary
    """
    meta = _ensure_repo_meta(metadata)
    return _mk_cyclonedx_dict(catalog, meta)


def generate_all(catalog: Dict[str, Any], metadata: Dict[str, Any], resolve_transitives: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Produce both SBOM and AIBOM artifacts.

    Returns:
      {
        "sbom": {"spdx": dict, "cyclonedx": dict, "json": dict}
      }
    """
    meta = _ensure_repo_meta(metadata)

    # Build SBOM artifacts (dicts)
    try:
        sb_spdx = _mk_spdx_dict(catalog, meta)
    except Exception as e:
        print(f"[WARNING] Error building SPDX dict: {e}")
        sb_spdx = {}

    try:
        sb_cdx = _mk_cyclonedx_dict(catalog, meta)
    except Exception as e:
        print(f"[WARNING] Error building CycloneDX dict: {e}")
        sb_cdx = {}

    try:
        sb_json = _mk_json_sbom(catalog, meta)
    except Exception as e:
        print(f"[WARNING] Error building JSON SBOM: {e}")
        sb_json = {}

    return {
        "sbom": {
            "spdx": sb_spdx,
            "cyclonedx": sb_cdx,
            "json": sb_json
        }
    }


def generate_remediation_sbom(catalog: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate remediation report with actionable fix recommendations.
    
    This report focuses on vulnerable packages and provides:
    - Current vulnerable version
    - Recommended fix version (fixed_in)
    - Patch status
    - Remediation action recommendation
    
    Args:
        catalog: Package catalog from orchestrator
        metadata: Scan metadata
        
    Returns:
        Remediation report dictionary matching CLI format
    """
    meta = _ensure_repo_meta(metadata)
    
    # Group vulnerabilities by library
    library_vulns = {}  # library_name -> {vulns: [], version: str, ...}
    total_vulns = 0
    
    for pkg in catalog.get("packages", []):
        vulns = pkg.get("vulnerabilities", [])
        if not vulns:
            continue
        
        pkg_name = pkg.get("name") or pkg.get("component_name")
        pkg_version = pkg.get("version") or pkg.get("component_version")
        language = pkg.get("language", "python").lower()
        
        if pkg_name not in library_vulns:
            library_vulns[pkg_name] = {
                "version": pkg_version,
                "language": language,
                "vulns": [],
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "used_in_files": pkg.get("used_in_files", ["Not found in source code analysis"])
            }
        
        for v in vulns:
            total_vulns += 1
            
            # Calculate severity level
            severity = v.get("severity", "UNKNOWN")
            cvss_score = v.get("cvss_score")
            
            if cvss_score and isinstance(cvss_score, (int, float)):
                if cvss_score >= 9.0:
                    severity_level = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity_level = "HIGH"
                elif cvss_score >= 4.0:
                    severity_level = "MEDIUM"
                else:
                    severity_level = "LOW"
            else:
                severity_level = v.get("severity_level", "HIGH").upper()
                if severity_level not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    sev_upper = str(severity).upper()
                    if "CRITICAL" in sev_upper:
                        severity_level = "CRITICAL"
                    elif "HIGH" in sev_upper:
                        severity_level = "HIGH"
                    elif "MEDIUM" in sev_upper or "MODERATE" in sev_upper:
                        severity_level = "MEDIUM"
                    elif "LOW" in sev_upper:
                        severity_level = "LOW"
                    else:
                        severity_level = "HIGH"
            
            # Update severity breakdown
            sev_key = severity_level.lower()
            if sev_key in library_vulns[pkg_name]["severity_breakdown"]:
                library_vulns[pkg_name]["severity_breakdown"][sev_key] += 1
            
            library_vulns[pkg_name]["vulns"].append({
                "id": v.get("id"),
                "severity_level": severity_level,
                "fixed_in": v.get("fixed_in") or v.get("fixed_version")
            })
    
    # Build vulnerable_libraries list in user's expected format
    vulnerable_libraries = []
    upgrade_count = 0
    declare_count = 0
    investigate_count = 0
    critical_actions = 0
    
    for lib_name, lib_data in library_vulns.items():
        vulns = lib_data["vulns"]
        severity_breakdown = lib_data["severity_breakdown"]
        version = lib_data["version"]
        language = lib_data["language"]
        
        # Determine priority based on highest severity
        if severity_breakdown["critical"] > 0:
            priority = "CRITICAL"
            critical_actions += 1
        elif severity_breakdown["high"] > 0:
            priority = "HIGH"
        elif severity_breakdown["medium"] > 0:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        
        # Find the best fixed version (highest version that fixes most vulns)
        fixed_versions = [v["fixed_in"] for v in vulns if v.get("fixed_in") and v["fixed_in"] not in ["Unknown", "N/A", "", None]]
        
        if fixed_versions:
            # Sort versions and get the highest one
            try:
                from packaging.version import Version
                fixed_versions_sorted = sorted(set(fixed_versions), key=lambda x: Version(x) if x else Version("0"), reverse=True)
                best_fixed_version = fixed_versions_sorted[0]
            except:
                best_fixed_version = max(set(fixed_versions), key=fixed_versions.count)
            
            # Determine fix command based on language
            if language in ["python", "pip"]:
                fix_command = f"pip install {lib_name}>={best_fixed_version}"
            elif language in ["javascript", "npm", "node"]:
                fix_command = f"npm install {lib_name}@{best_fixed_version}"
            else:
                fix_command = f"Update {lib_name} to version {best_fixed_version}"
            
            recommended_action = {
                "type": "upgrade",
                "action": f"Upgrade from {version} to {best_fixed_version} or later",
                "current_version": version,
                "fixed_version": best_fixed_version,
                "fix_command": fix_command,
                "fixes_vulnerabilities": len(fixed_versions),
                "status": "action_required"
            }
            upgrade_count += 1
        else:
            # No fix available
            recommended_action = {
                "type": "investigate",
                "action": f"No fix available for {lib_name}@{version}. Consider alternative package or monitor for updates.",
                "current_version": version,
                "fixed_version": None,
                "fix_command": None,
                "fixes_vulnerabilities": 0,
                "status": "investigation_required"
            }
            investigate_count += 1
        
        # Simplified vulnerable library format (without severity_breakdown, used_in_files, severity_level)
        vulnerable_libraries.append({
            "library": lib_name,
            "current_version": version,
            "vulnerabilities_count": len(vulns),
            "priority": priority,
            "recommended_action": recommended_action
        })
    
    # Sort by priority (CRITICAL first, then HIGH, etc.)
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulnerable_libraries.sort(key=lambda x: priority_order.get(x["priority"], 4))
    
    # Count critical actions
    critical_actions = sum(1 for vl in vulnerable_libraries if vl["priority"] == "CRITICAL")
    
    # Group vulnerable libraries by language
    _LANG_DISPLAY = {
        "python": "Python", "javascript": "JavaScript", "node": "JavaScript",
        "go": "Go", "golang": "Go",
        "java": "Java", "maven": "Java", "gradle": "Java",
        "dotnet": ".NET", ".net": ".NET", "csharp": ".NET", "nuget": ".NET",
        "ruby": "Ruby", "rust": "Rust", "php": "PHP",
    }
    vulns_by_language = {}
    for vl in vulnerable_libraries:
        raw_lang = library_vulns.get(vl["library"], {}).get("language", "unknown")
        display = _LANG_DISPLAY.get(raw_lang, raw_lang.capitalize() if raw_lang != "unknown" else "Other")
        vulns_by_language.setdefault(display, []).append(vl)
    
    return {
        "scan_metadata": {
            "scan_id": meta.get("scan_id", ""),
            "timestamp": meta["timestamp"],
            "repository": meta.get("source", ""),
            "scan_type": "full",
            "tool": meta["tool"].get("name", "SBOM") if isinstance(meta["tool"], dict) else "SBOM"
        },
        "summary": {
            "total_libraries_with_vulnerabilities": len(vulnerable_libraries),
            "total_vulnerabilities": total_vulns,
            "critical_actions": critical_actions,
            "languages_affected": sorted(vulns_by_language.keys())
        },
        "vulnerable_libraries_by_language": {lang: libs for lang, libs in sorted(vulns_by_language.items())},
        "vulnerable_libraries": vulnerable_libraries,
        "action_summary": {
            "total_actions_required": len(vulnerable_libraries),
            "by_type": {
                "upgrade": upgrade_count,
                "declare": declare_count,
                "investigate": investigate_count
            },
            "estimated_vulnerabilities_fixed": sum(
                vl["recommended_action"]["fixes_vulnerabilities"] 
                for vl in vulnerable_libraries 
                if vl["recommended_action"]["fixes_vulnerabilities"]
            ),
            "estimated_fix_time": "5-10 minutes" if len(vulnerable_libraries) <= 5 else "15-30 minutes"
        }
    }
