"""
Python package enricher.
"""
from typing import Dict, Any, List
import urllib.parse as urlparse

from src.enrichers.base import BaseEnricher
from src.utils.hash_utils import hashes_for_files
from src.utils.package_metadata_utils import (
    fetch_pypi_meta,
    extract_license_from_pypi_meta,
    extract_hashes_from_pypi_meta,
    extract_release_date_from_pypi,
    infer_license_type
)
from src.core import vulnerability_provider

class PythonEnricher(BaseEnricher):
    """Enricher for Python/PyPI packages."""
    
    @property
    def supported_ecosystems(self) -> List[str]:
        return ["pypi"]

    def enrich(self, pkg: Dict[str, Any]) -> Dict[str, Any]:
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
                        out["license"] = lic  # Also set the "license" field
                elif out.get("license") and not out.get("component_license"):
                    # Cataloger set "license", copy to "component_license"
                    out["component_license"] = out["license"]
                
                # release_date - Extract from PyPI metadata
                if not scanner_enrichments.get("release_date"):
                    release_date = extract_release_date_from_pypi(pypi, ver if ver != "UNKNOWN" else None)
                    if release_date:
                        out["release_date"] = release_date
                
                # hashes (SHA-256)
                hashes = extract_hashes_from_pypi_meta(pypi, ver if ver != "UNKNOWN" else None)
                if hashes:
                    out["hashes"] = hashes

                # store distributions
                out["_pypi_distributions"] = pypi.get("urls", [])

        except Exception:
            pass  # best-effort

        # -----------------------------
        # 3) Resolve dependencies list
        # -----------------------------
        if not scanner_enrichments.get("component_dependencies"):
            raw_deps = pkg.get("dependencies", [])
            dep_purls = []
            for dep in raw_deps:
                if isinstance(dep, str):
                    if dep.startswith("pkg:"):
                        dep_purls.append(dep)
                    else:
                        dep_purls.append(f"pkg:pypi/{dep}")
                elif isinstance(dep, dict):
                    dep_name = dep.get("name")
                    dep_constraint = dep.get("version_constraint", "")
                    
                    if dep.get("purl"):
                        dep_purls.append(dep.get("purl"))
                    elif dep_name:
                        if dep_constraint and dep_constraint != "UNKNOWN" and dep_constraint.strip():
                            encoded_constraint = urlparse.quote(dep_constraint)
                            dep_purls.append(f"pkg:pypi/{dep_name}?version_constraint={encoded_constraint}")
                        else:
                            dep_purls.append(f"pkg:pypi/{dep_name}")
            out["component_dependencies"] = dep_purls
        else:
            out["component_dependencies"] = scanner_enrichments["component_dependencies"]

        # -----------------------------
        # 4) Hash files for evidence
        # -----------------------------
        if not out.get("hashes"):
            locations = pkg.get("locations", [])
            file_paths = [loc.get("path") for loc in locations if loc.get("path")]
            try:
                if file_paths:
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
        if not out.get("component_origin"):
            license_str = out.get("component_license", "")
            out["component_origin"] = infer_license_type(license_str)

        # EOL date - Dynamic lookup from deps.dev API only
        try:
            from src.utils.eol_fetcher import get_eol_date_with_fallback
            eol_date = get_eol_date_with_fallback(name, ver, ecosystem="pypi")
            out["eol_date"] = eol_date or "Unknown"
        except Exception:
            out["eol_date"] = "Unknown"
        
        # Set criticality with [default] suffix if not computed from vulnerabilities
        if not out.get("criticality"):
            from src.config.config import DEFAULT_VALUES
            out["criticality"] = DEFAULT_VALUES.get("criticality", "Low [default]")
        
        # Set other defaults with [default] suffix
        from src.config.config import DEFAULT_VALUES
        default_fields = ["comments", "author_of_sbom_data", "timestamp", "executable", "archive", "structured_properties"]
        for f in default_fields:
            if not out.get(f):
                out[f] = DEFAULT_VALUES.get(f, "")

        out.setdefault("component_name", name)
        out.setdefault("component_version", ver)

        # -----------------------------
        # 7) RESTORE scanner enrichments
        # -----------------------------
        for key, value in scanner_enrichments.items():
            if value:
                out[key] = value

        return out
