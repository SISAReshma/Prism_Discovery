"""
NPM package enricher.
"""
from typing import Dict, Any, List
import urllib.parse as urlparse

from src.enrichers.base import BaseEnricher
from src.utils.package_metadata_utils import (
    fetch_npm_meta,
    extract_release_date_from_npm,
    infer_license_type
)
from src.core import vulnerability_provider

class NpmEnricher(BaseEnricher):
    """Enricher for NPM packages."""
    
    @property
    def supported_ecosystems(self) -> List[str]:
        return ["npm"]

    def enrich(self, pkg: Dict[str, Any]) -> Dict[str, Any]:
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
                        encoded_constraint = urlparse.quote(dep_constraint)
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
        if not out.get("component_origin"):
            license_str = out.get("component_license", "")
            out["component_origin"] = infer_license_type(license_str)

        # EOL date - Dynamic lookup from deps.dev API only
        try:
            from src.utils.eol_fetcher import get_eol_date_with_fallback
            eol_date = get_eol_date_with_fallback(name, ver, ecosystem="npm")
            out["eol_date"] = eol_date or "Unknown"
        except Exception:
            out["eol_date"] = "Unknown"
        
        out.setdefault("criticality", "Medium")
        
        defaults = [
            "comments", "author_of_sbom_data", "timestamp",
            "executable", "archive", "structured_properties",
        ]
        for f in defaults:
            out.setdefault(f, "")

        out.setdefault("component_name", name)
        out.setdefault("component_version", ver)

        return out
