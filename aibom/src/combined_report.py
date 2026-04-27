"""
Combined AIBOM + SBOM Report Builder.

Merges AI Bill of Materials and Software Bill of Materials into a single
unified JSON report.  Used by both CLI and API orchestrator so that both
paths produce identical output structures.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


TOOL_NAME = "PrismDiscovery"
TOOL_VERSION = "1.0.0"


def build_combined_report(
    aibom_data: Optional[Dict[str, Any]] = None,
    sbom_data: Optional[Dict[str, Any]] = None,
    scan_id: str = "",
    project_name: str = "",
) -> Dict[str, Any]:
    """
    Build a unified report that includes both AIBOM and SBOM results.

    Args:
        aibom_data:    Full AIBOM CycloneDX dict (from build_aibom / aibom-connector endpoint).
        sbom_data:     Full SBOM CycloneDX dict (from generate_cyclonedx_sbom / generate-sbom endpoint).
                       If the endpoint wraps the CycloneDX in a response envelope
                       (with ``reports.cyclonedx``), pass the inner CycloneDX dict.
        scan_id:       Scan identifier.
        project_name:  Repository / project name.

    Returns:
        Combined report dict ready for JSON serialization.
    """
    aibom = aibom_data or {}
    sbom = sbom_data or {}
    now = datetime.now(timezone.utc).isoformat()

    # ── AIBOM summary ───────────────────────────────────────────────────────
    aibom_meta = aibom.get("_connector_meta", {})
    aibom_components = aibom.get("components", [])
    aibom_vulns = aibom.get("vulnerabilities", [])

    ai_models_detected = aibom_meta.get("models_processed", len(aibom_components))
    ai_models_resolved = aibom_meta.get("models_found", 0)
    ai_models_not_found = aibom_meta.get("models_not_found", 0)

    deprecated_count = 0
    dep_summary = aibom_meta.get("deprecation_summary", {})
    if dep_summary:
        deprecated_count = dep_summary.get("deprecated_count", 0)

    # AI model names from AIBOM components
    ai_model_names: List[str] = []
    for comp in aibom_components:
        comp_type = comp.get("type", "")
        if comp_type != "library":
            ai_model_names.append(comp.get("name", ""))

    # ── SBOM summary ────────────────────────────────────────────────────────
    sbom_components = sbom.get("components", {})

    # components can be a dict (key→value map) or a list
    if isinstance(sbom_components, dict):
        sbom_components_list = list(sbom_components.values()) if sbom_components else []
        software_components_count = len(sbom_components)
    elif isinstance(sbom_components, list):
        sbom_components_list = sbom_components
        software_components_count = len(sbom_components)
    else:
        sbom_components_list = []
        software_components_count = 0

    sbom_vulns = sbom.get("vulnerabilities", [])
    software_vulnerabilities = len(sbom_vulns)

    # Count SBOM vulnerability severities
    sbom_severity_breakdown: Dict[str, int] = {}
    for v in sbom_vulns:
        for r in v.get("ratings", []):
            sev = r.get("severity", "unknown")
            sbom_severity_breakdown[sev] = sbom_severity_breakdown.get(sev, 0) + 1

    # Extract license summary from SBOM components
    license_counts: Dict[str, int] = {}
    for comp in sbom_components_list:
        for lic_entry in comp.get("licenses", []):
            lic = lic_entry.get("license", {})
            lid = lic.get("id", lic.get("name", "unknown"))
            if lid:
                license_counts[lid] = license_counts.get(lid, 0) + 1

    # ── Build combined report ───────────────────────────────────────────────
    combined: Dict[str, Any] = {
        "reportFormat": "PrismDiscovery",
        "version": "1.0",
        "scan_id": scan_id,
        "project_name": project_name,
        "timestamp": now,
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
        },
        "summary": {
            # AI Models
            "ai_models_detected": ai_models_detected,
            "ai_models_resolved": ai_models_resolved,
            "ai_models_not_found": ai_models_not_found,
            "ai_models_deprecated": deprecated_count,
            "ai_deprecation_vulnerabilities": len(aibom_vulns),
            "ai_model_names": ai_model_names,
            # Software
            "software_components": software_components_count,
            "software_vulnerabilities": software_vulnerabilities,
            "software_vulnerability_severity": sbom_severity_breakdown,
            "software_license_summary": license_counts,
        },
        # Full AIBOM and SBOM CycloneDX payloads
        "aibom": aibom if aibom else None,
        "sbom": sbom if sbom else None,
    }

    # Remove None sections if only one BOM was generated
    if combined["aibom"] is None:
        del combined["aibom"]
    if combined["sbom"] is None:
        del combined["sbom"]

    return combined
