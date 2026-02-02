"""Background scan task helpers."""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

from src.core.orchestrator import ScanOrchestrator, ScanResult
from src.api.services.session_state import SessionData, ScanState
from src.config.config import TEMP_DIR as CONFIG_TEMP_DIR


def run_scan_task(session: SessionData, orchestrator: ScanOrchestrator) -> None:
    """
    Background task to run the SBOM scan using the unified orchestrator.
    """
    # Progress callback to update session from orchestrator
    def update_session_progress(step_num: int, step_name: str, progress_percent: int):
        """Callback to update session progress from orchestrator."""
        session.progress = progress_percent
        session.current_step = step_name

    try:
        session.state = ScanState.RUNNING
        session.progress = 0
        session.current_step = "Initializing orchestrator..."

        # Determine source and source type
        if session.upload_type == "repository":
            source = session.repository_url
            source_type = "repo"
        else:
            source = str(session.temp_path)
            source_type = "local"

        session.progress = 5
        session.current_step = "Starting scan pipeline..."

        result: ScanResult = orchestrator.run_scan(
            source=source,
            source_type=source_type,
            token=session.token,
            project_name=session.repo_name or "uploaded_project",
            cleanup_after=(session.upload_type == "repository"),
            progress_callback=update_session_progress,
        )

        session.scan_id = result.scan_id

        if not result.success:
            raise Exception(", ".join(result.errors) if result.errors else "Scan failed")

        session.progress = 95
        session.current_step = "Processing results..."

        packages = result.packages
        vulnerabilities = []

        print(f"[DEBUG] Packages count: {len(packages) if packages else 0}")
        print(f"[DEBUG] Vuln count from orchestrator: {result.vulnerabilities_count}")

        for pkg in packages:
            pkg_vulns = pkg.get("vulnerabilities", [])
            if pkg_vulns:
                print(
                    f"[DEBUG] Package {pkg.get('name', 'unknown')} has {len(pkg_vulns)} vulnerabilities"
                )
            for vuln in pkg_vulns:
                vulnerabilities.append(
                    {
                        "id": vuln.get("id", "Unknown"),
                        "package": pkg.get("name", "Unknown"),
                        "version": pkg.get("version", "Unknown"),
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "severity_level": vuln.get("severity_level", "UNKNOWN"),
                        "title": vuln.get("summary", "No title"),
                        "description": vuln.get("details", "No description"),
                        "published_date": vuln.get("published", "Unknown"),
                        "fixed_version": vuln.get("fixed_in", "Unknown"),
                        "url": vuln.get("url", ""),
                    }
                )

        session.progress = 90
        session.current_step = "Finalizing results..."

        remediation = []
        seen_packages = set()

        for vuln in vulnerabilities:
            pkg_key = f"{vuln['package']}@{vuln['version']}"
            if pkg_key not in seen_packages:
                seen_packages.add(pkg_key)

                urgency = "STANDARD"
                severity_level = vuln.get("severity_level", "UNKNOWN").upper()
                if severity_level == "CRITICAL":
                    urgency = "IMMEDIATE"
                elif severity_level == "HIGH":
                    urgency = "HIGH"
                elif severity_level == "MEDIUM":
                    urgency = "STANDARD"

                remediation.append(
                    {
                        "package": vuln["package"],
                        "current_version": vuln["version"],
                        "fix_version": vuln.get("fixed_version", "Unknown"),
                        "severity": vuln["severity"],
                        "severity_level": severity_level,
                        "urgency": urgency,
                        "action": f"Upgrade to version {vuln.get('fixed_version', 'latest')} or later",
                        "cves_fixed": [
                            v["id"] for v in vulnerabilities if v["package"] == vuln["package"]
                        ],
                    }
                )

        urgency_order = {"IMMEDIATE": 0, "URGENT": 1, "HIGH": 2, "STANDARD": 3}
        remediation.sort(key=lambda x: urgency_order.get(x.get("urgency", "STANDARD"), 3))

        session.scan_results = {
            "scan_id": result.scan_id,
            "project_name": session.repo_name or "uploaded_project",
            "scan_timestamp": datetime.now().isoformat(),
            "total_components": len(packages),
            "total_vulnerabilities": result.vulnerabilities_count,
            "ecosystems": session.ecosystems_detected,
            "duration_seconds": result.duration_seconds,
            "components": packages,
        }
        session.vulnerabilities = vulnerabilities
        session.remediation = remediation
        session.scan_timestamp = datetime.now().isoformat()
        session.sbom_files = result.reports
        session.remediation_path = result.remediation_path

        session.progress = 100
        session.current_step = "Scan completed"
        session.state = ScanState.COMPLETED

        print(f"[SUCCESS] Scan completed: {result.scan_id}")
        print(f"  - Packages: {len(packages)}")
        print(f"  - Vulnerabilities: {result.vulnerabilities_count}")
        print(f"  - Duration: {result.duration_seconds:.2f}s")

        if session.upload_type in ("files", "zip") and session.temp_path:
            try:
                temp_path = Path(session.temp_path)
                if temp_path.parent.exists() and str(temp_path.parent).startswith(
                    str(CONFIG_TEMP_DIR)
                ):
                    shutil.rmtree(temp_path.parent, ignore_errors=True)
                    print(f"[CLEANUP] Removed temp folder: {temp_path.parent}")
            except Exception as cleanup_error:
                print(f"[WARN] Cleanup failed: {cleanup_error}")

    except Exception as e:
        session.state = ScanState.FAILED
        session.error_message = str(e)
        session.current_step = f"Scan failed: {str(e)}"
        import traceback

        traceback.print_exc()
