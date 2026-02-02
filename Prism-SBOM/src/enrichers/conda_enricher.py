"""
Conda package enricher.
"""
from typing import Dict, Any, List

from src.enrichers.base import BaseEnricher
from src.core import vulnerability_provider


class CondaEnricher(BaseEnricher):
    """Enricher for Conda packages."""
    
    @property
    def supported_ecosystems(self) -> List[str]:
        return ["conda"]
    
    def enrich(self, pkg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a conda package entry.
        
        Note: Conda cataloger already handles metadata enrichment from Anaconda API.
        This enricher adds standardized fields for SBOM generation.
        """
        name = pkg.get("name")
        ver = pkg.get("version") or "UNKNOWN"
        channel = pkg.get("channel", "conda-forge")
        
        out = dict(pkg)
        
        # -----------------------------
        # 1) Ensure canonical PURL
        # -----------------------------
        if ver != "UNKNOWN":
            purl = f"pkg:conda/{channel}/{name}@{ver}"
        else:
            purl = f"pkg:conda/{channel}/{name}"
        out["purl"] = purl
        out["unique_identifier"] = purl
        
        # -----------------------------
        # 2) Vulnerability enrichment
        # -----------------------------
        try:
            if pkg.get("vulnerabilities"):
                out["vulnerabilities"] = pkg["vulnerabilities"]
            else:
                # Note: OSV doesn't have conda ecosystem yet
                # Falling back to empty list
                out["vulnerabilities"] = []
        except Exception:
            out["vulnerabilities"] = []
        
        # patch status
        if out["vulnerabilities"]:
            has_fix = any(
                v.get("fixed_versions")
                for v in out["vulnerabilities"]
            )
            out["patch_status"] = "fix_available" if has_fix else "unknown"
        else:
            out["patch_status"] = "none"
        
        # -----------------------------
        # 3) Fill CERT default fields
        # -----------------------------
        out.setdefault("component_license", pkg.get("license", "NOASSERTION"))
        out.setdefault("component_description", pkg.get("description", ""))
        out.setdefault("component_supplier", pkg.get("supplier", "Conda Community"))
        out.setdefault("component_origin", "open-source")
        out.setdefault("eol_date", "Unknown")
        out.setdefault("criticality", "Medium")
        
        defaults = [
            "comments", "author_of_sbom_data", "timestamp",
            "executable", "archive", "structured_properties",
        ]
        for f in defaults:
            out.setdefault(f, "")
        
        out.setdefault("component_name", name)
        out.setdefault("component_version", ver)
        out.setdefault("hashes", [])
        
        return out
