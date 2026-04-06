"""
VEX (Vulnerability Exploitability eXchange) Generator

Generates VEX documents that answer: "Is this CVE actually exploitable
in THIS product?" — reducing false-positive noise from SBOM vulnerability lists.

Supported output formats:
  - OpenVEX  (JSON-LD, https://openvex.dev/ns/v0.2.0)
  - CycloneDX VEX statements (for embedding in CycloneDX SBOM)

Auto-determination logic (no manual input required):
  1. current_version >= all fixed versions  → fixed
  2. in_cisa_kev OR epss_score > 0.5       → affected (confirmed exploited/high risk)
  3. fixed_in exists, current < fixed       → affected (upgrade needed)
  4. No fixed_in / Unknown                 → under_investigation
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_OPENVEX_AUTHOR = "SISA Prism SBOM Tool"
_OPENVEX_ROLE = "Automated VEX Generator"

# VEX statuses
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# CycloneDX analysis state mapping
_CDX_STATE_MAP: Dict[str, str] = {
    STATUS_AFFECTED: "exploitable",
    STATUS_FIXED: "resolved",
    STATUS_NOT_AFFECTED: "false_positive",
    STATUS_UNDER_INVESTIGATION: "in_triage",
}

# CycloneDX response mapping
_CDX_RESPONSE_MAP: Dict[str, List[str]] = {
    STATUS_AFFECTED: ["update"],
    STATUS_FIXED: ["update"],
    STATUS_NOT_AFFECTED: ["will_not_fix"],
    STATUS_UNDER_INVESTIGATION: [],
}


# ===========================================================================
# Core status determination
# ===========================================================================

def _determine_vex_status(
    vuln: Dict[str, Any],
    current_version: str,
) -> Tuple[str, str, Optional[str]]:
    """
    Determine VEX status for a single (package version, vulnerability) pair.

    Returns:
        Tuple of (status, impact_statement, action_statement)
    """
    fixed_raw = vuln.get("fixed_in") or vuln.get("fixed_version")
    in_kev = bool(vuln.get("in_cisa_kev"))
    epss = float(vuln.get("epss_score") or 0)
    vuln_id = vuln.get("id", "Unknown")

    # ── Parse fixed versions ──────────────────────────────────────────────
    fixed_versions = []
    if fixed_raw and str(fixed_raw).strip() not in ("Unknown", "N/A", ""):
        raw_str = str(fixed_raw)
        fixed_versions = [v.strip() for v in raw_str.split(",") if v.strip()]

    # ── Rule 1: Already at or above every fixed version → fixed ───────────
    if fixed_versions and current_version:
        try:
            from packaging.version import Version as PkgVer
            current_v = PkgVer(current_version)
            parsed_fixed = [PkgVer(v) for v in fixed_versions]
            if all(current_v >= fv for fv in parsed_fixed):
                best = str(max(parsed_fixed))
                return (
                    STATUS_FIXED,
                    f"Version {current_version} is at or above the patched version ({best}). "
                    f"This package is not vulnerable to {vuln_id}.",
                    None,
                )
        except Exception:
            pass

    # ── Rule 2: CISA KEV → confirmed exploited in the wild ───────────────
    if in_kev:
        kev_date = vuln.get("kev_date_added", "")
        due = vuln.get("kev_due_date", "")
        action = (
            f"Upgrade to {fixed_versions[0]} or later."
            if fixed_versions
            else "Apply vendor patch when available."
        )
        due_msg = f" CISA remediation deadline: {due}." if due else ""
        return (
            STATUS_AFFECTED,
            f"This CVE is in the CISA Known Exploited Vulnerabilities catalog "
            f"(added {kev_date}).{due_msg} Active real-world exploitation confirmed.",
            action,
        )

    # ── Rule 3: High EPSS → high exploitation probability ────────────────
    if epss > 0.5:
        action = (
            f"Upgrade to {fixed_versions[0]} or later."
            if fixed_versions
            else "Apply vendor patch when available."
        )
        return (
            STATUS_AFFECTED,
            f"EPSS score {epss * 100:.1f}% — high probability of exploitation "
            f"in the next 30 days. Immediate action recommended.",
            action,
        )

    # ── Rule 4: Fix exists, current < fixed → needs upgrade ──────────────
    if fixed_versions:
        best_fix = fixed_versions[0]
        try:
            from packaging.version import Version as PkgVer
            best_fix = str(max(PkgVer(v) for v in fixed_versions))
        except Exception:
            pass
        epss_note = (
            f" EPSS: {epss * 100:.1f}% exploitation probability."
            if epss > 0.01
            else ""
        )
        return (
            STATUS_AFFECTED,
            f"Current version {current_version} is below the patched version "
            f"({best_fix}).{epss_note} Upgrade required.",
            f"Upgrade {vuln.get('package_name', 'the package')} to {best_fix} or later.",
        )

    # ── Rule 5: No fix released yet → under investigation ────────────────
    epss_note = (
        f" EPSS: {epss * 100:.1f}% exploitation probability."
        if epss > 0.01
        else ""
    )
    return (
        STATUS_UNDER_INVESTIGATION,
        f"No fixed version has been released for {vuln_id}.{epss_note} "
        f"Monitoring advisories for a patch.",
        None,
    )


# ===========================================================================
# OpenVEX document generation
# ===========================================================================

def generate_openvex(catalog: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """
    Generate an OpenVEX document from a package catalog.

    Args:
        catalog:  Package catalog (from orchestrator / vulnerability_provider)
        scan_id:  Unique scan identifier (used as document ID)

    Returns:
        OpenVEX document dict (JSON-serialisable)
    """
    statements: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for pkg in catalog.get("packages", []):
        pkg_name = pkg.get("name") or pkg.get("component_name", "unknown")
        pkg_version = pkg.get("version") or pkg.get("component_version", "")
        language = pkg.get("language", "")
        purl = _build_purl(pkg_name, pkg_version, language)

        for vuln in pkg.get("vulnerabilities", []):
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            status, impact, action = _determine_vex_status(vuln, pkg_version)

            stmt: Dict[str, Any] = {
                "vulnerability": {
                    "@id": _vuln_url(vuln_id),
                    "name": vuln_id,
                },
                "products": [{"@id": purl}],
                "status": status,
                "status_notes": impact,
                "timestamp": now,
            }

            if action:
                stmt["action_statement"] = action

            # Enrich with EPSS / KEV context
            epss = vuln.get("epss_score")
            if epss is not None:
                stmt["epss_score"] = epss
                stmt["epss_percentile"] = vuln.get("epss_percentile")

            if vuln.get("in_cisa_kev"):
                stmt["cisa_kev"] = {
                    "date_added": vuln.get("kev_date_added"),
                    "due_date": vuln.get("kev_due_date"),
                    "required_action": vuln.get("kev_required_action"),
                    "known_ransomware": vuln.get("known_ransomware", "Unknown"),
                }

            statements.append(stmt)

    logger.info(f"[VEX] Generated {len(statements)} OpenVEX statements for scan {scan_id}")

    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": f"https://prism.sisa.ai/vex/{scan_id}",
        "author": _OPENVEX_AUTHOR,
        "role": _OPENVEX_ROLE,
        "timestamp": now,
        "version": 1,
        "tooling": "SISA Prism SBOM v1.0",
        "statements": statements,
    }


# ===========================================================================
# CycloneDX VEX statements (for embedding in CycloneDX SBOM)
# ===========================================================================

def generate_cyclonedx_vex_statements(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate CycloneDX 1.5 vulnerability analysis entries for all packages.

    Returns a list to be merged into CycloneDX SBOM's ``vulnerabilities`` array.
    Each entry gets an ``analysis`` block with state + detail + responses.
    """
    cdx_vulns: List[Dict[str, Any]] = []

    for pkg in catalog.get("packages", []):
        pkg_name = pkg.get("name") or pkg.get("component_name", "unknown")
        pkg_version = pkg.get("version") or pkg.get("component_version", "")
        language = pkg.get("language", "")
        purl = _build_purl(pkg_name, pkg_version, language)
        bom_ref = pkg.get("bom_ref") or f"{pkg_name}@{pkg_version}"

        for vuln in pkg.get("vulnerabilities", []):
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            status, impact, action = _determine_vex_status(vuln, pkg_version)
            cdx_state = _CDX_STATE_MAP.get(status, "in_triage")
            cdx_responses = _CDX_RESPONSE_MAP.get(status, [])

            ratings = []
            epss = vuln.get("epss_score")
            if epss is not None:
                ratings.append({
                    "source": {"name": "EPSS", "url": "https://epss.cyentia.com"},
                    "score": epss,
                    "severity": _epss_to_severity(epss),
                    "method": "EPSS",
                })

            entry: Dict[str, Any] = {
                "id": vuln_id,
                "source": {
                    "name": vuln.get("source", "OSV").upper(),
                    "url": vuln.get("url") or _vuln_url(vuln_id),
                },
                "ratings": ratings,
                "affects": [{"ref": bom_ref}],
                "analysis": {
                    "state": cdx_state,
                    "detail": action or impact,
                    "responses": cdx_responses,
                },
                "properties": _build_cdx_properties(vuln),
            }

            cdx_vulns.append(entry)

    return cdx_vulns


# ===========================================================================
# Summary statistics
# ===========================================================================

def generate_vex_summary(catalog: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """
    Generate a full VEX payload including both formats + summary stats.
    Used by the /sbom/generate-remediation and /sbom/generate-vex endpoints.
    """
    openvex_doc = generate_openvex(catalog, scan_id)
    statements = openvex_doc.get("statements", [])

    # Count by status
    counts: Dict[str, int] = {
        STATUS_AFFECTED: 0,
        STATUS_FIXED: 0,
        STATUS_NOT_AFFECTED: 0,
        STATUS_UNDER_INVESTIGATION: 0,
    }
    kev_count = 0
    high_epss_count = 0

    for stmt in statements:
        status = stmt.get("status", STATUS_UNDER_INVESTIGATION)
        counts[status] = counts.get(status, 0) + 1
        if stmt.get("cisa_kev"):
            kev_count += 1
        if (stmt.get("epss_score") or 0) >= 0.1:
            high_epss_count += 1

    return {
        "summary": {
            "total_statements": len(statements),
            "affected": counts[STATUS_AFFECTED],
            "fixed": counts[STATUS_FIXED],
            "not_affected": counts[STATUS_NOT_AFFECTED],
            "under_investigation": counts[STATUS_UNDER_INVESTIGATION],
            "kev_confirmed": kev_count,
            "high_epss_count": high_epss_count,
        },
        "openvex": openvex_doc,
    }


# ===========================================================================
# Helpers
# ===========================================================================

def _build_purl(name: str, version: str, language: str) -> str:
    """Build a Package URL (purl) string."""
    lang_lower = (language or "").lower()
    _PURL_TYPE = {
        "python": "pypi",
        "javascript": "npm",
        "go": "golang",
        "java": "maven",
        "dotnet": "nuget",
        "ruby": "gem",
        "rust": "cargo",
        "php": "composer",
        "swift": "swift",
        "cpp": "conan",
    }
    purl_type = _PURL_TYPE.get(lang_lower, lang_lower or "generic")
    ver_suffix = f"@{version}" if version else ""
    return f"pkg:{purl_type}/{name}{ver_suffix}"


def _vuln_url(vuln_id: str) -> str:
    """Return a canonical URL for a vulnerability ID."""
    uid = vuln_id.upper()
    if uid.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if uid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


def _epss_to_severity(score: float) -> str:
    """Map EPSS score to a severity label."""
    if score >= 0.5:
        return "critical"
    if score >= 0.1:
        return "high"
    if score >= 0.01:
        return "medium"
    return "low"


def _build_cdx_properties(vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build CycloneDX properties list from exploit intel data."""
    props = []
    if vuln.get("in_cisa_kev"):
        props.append({"name": "cisa:kev", "value": "true"})
    if vuln.get("kev_date_added"):
        props.append({"name": "cisa:kev:dateAdded", "value": vuln["kev_date_added"]})
    if vuln.get("kev_due_date"):
        props.append({"name": "cisa:kev:dueDate", "value": vuln["kev_due_date"]})
    epss = vuln.get("epss_score")
    if epss is not None:
        props.append({"name": "epss:score", "value": str(epss)})
    pct = vuln.get("epss_percentile")
    if pct is not None:
        props.append({"name": "epss:percentile", "value": str(pct)})
    return props
