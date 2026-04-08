"""
Remediation Reporter - Generate actionable fix recommendations
Shows which files use vulnerable libraries and exact commands to fix them

V2 TODO: Add EPSS and CISA KEV data for prioritization.
"""
from pathlib import Path
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging
from sbom.src.config.config import TOOL_NAME

# Exploit Intelligence: EPSS and CISA KEV
try:
    from sbom.src.clients.exploit_intel_client import (
        check_cisa_kev,
        fetch_epss_score,
        fetch_epss_batch,
    )
    EXPLOIT_INTEL_AVAILABLE = True
except ImportError:
    EXPLOIT_INTEL_AVAILABLE = False


logger = logging.getLogger(__name__)

# Python standard library modules (don't need to be in requirements.txt)
PYTHON_STDLIB = {
    # Built-in modules
    'sys', 'os', 'io', 'time', 'datetime', 'math', 'random', 'json', 'csv',
    'xml', 'sqlite3', 'pickle', 'shelve', 'gzip', 'zipfile', 'tarfile',
    
    # Data structures
    'collections', 'array', 'heapq', 'bisect', 'queue', 'enum', 'types',
    
    # String processing
    're', 'string', 'textwrap', 'unicodedata', 'difflib',
    
    # Functional programming
    'functools', 'itertools', 'operator',
    
    # File/path handling  
    'pathlib', 'glob', 'shutil', 'tempfile', 'fileinput', 'stat', 'posixpath',
    
    # Process/threading
    'subprocess', 'threading', 'multiprocessing', 'concurrent', 'asyncio',
    'signal', 'sched',
    
    # System/platform
    'platform', 'ctypes', 'errno', 'warnings', 'traceback', 'inspect',
    'atexit', 'gc', 'weakref', 'copy', 'pprint', 'getpass', 'uuid',
    
    # Networking/web
    'urllib', 'http', 'email', 'smtplib', 'ftplib', 'socketserver',
    'ssl', 'socket', 'select', 'webbrowser',
    
    # Typing/annotations
    'typing', 'typing_extensions', '__future__', '_typeshed',
    
    # Context/utilities
    'contextlib', 'abc', 'importlib', 'pkgutil', 'modulefinder',
    
    # Logging/config
    'logging', 'argparse', 'configparser', 'getopt', 'optparse',
    
    # Testing (often in stdlib)
    'unittest', 'doctest',
    
    # Encoding/decoding
    'base64', 'binascii', 'codecs', 'encodings', 'gettext', 'locale',
    
    # Hashing/crypto (basic)
    'hashlib', 'hmac', 'secrets',
    
    # Misc
    'keyword', 'token', 'tokenize', 'ast', 'code', 'codeop',
    'dis', 'fractions', 'decimal', 'numbers', 'cmath',
    
    # Platform-specific
    'msvcrt', 'winreg', 'winsound', 'posix', 'pwd', 'grp',
    'tty', 'termios', 'fcntl', 'pty', 'shlex',
    
    # Internal/private (relative imports within package)
    '_compat', '_utils', '_termui_impl', '_winconsole', '_textwrap',
    
    # Common local module names that aren't external packages
    'utils', 'core', 'exceptions', 'types', 'globals', 'parser',
    'shell_completion', 'termui', 'decorators', 'formatting', 'complex'
}

# Node.js built-in modules (don't need to be in package.json)
NODEJS_BUILTINS = {
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
    'constants', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http',
    'http2', 'https', 'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
    'process', 'punycode', 'querystring', 'readline', 'repl', 'stream',
    'string_decoder', 'timers', 'tls', 'trace_events', 'tty', 'url', 'util',
    'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
}


class RemediationReporter:
    def __init__(self, scan_id: str, reports_dir: str = None):
        from sbom.src.config.config import REPORTS_DIR
        self.scan_id = scan_id
        self.reports_dir = Path(reports_dir or REPORTS_DIR)
        self.scan_dir = self.reports_dir / scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, catalog: Dict, import_map: Dict[str, List[str]], metadata: Dict) -> str:
        """
        Generate remediation actions report
        
        Args:
            catalog: SBOM catalog with components and vulnerabilities
            import_map: Map of library names to files that import them
            metadata: Scan metadata (repository, timestamp, etc.)
        
        Returns:
            Path to generated report file
        """
        vulnerable_libs = []
        undeclared_deps = []
        
        # Get set of declared package names (use "packages" key, not "components")
        declared_names = {pkg.get("name") for pkg in catalog.get("packages", [])}
        
        # Process vulnerable declared dependencies
        for pkg in catalog.get("packages", []):
            vulns = pkg.get("vulnerabilities", [])
            if not vulns:
                continue
            
            lib_name = pkg.get("name")
            files_using = import_map.get(lib_name, ["Not found in source code analysis"])
            
            # Count vulnerabilities by severity
            severity_breakdown = self._count_by_severity(vulns)
            
            # Calculate priority
            priority = self._calculate_priority(severity_breakdown, vulns)
            
            # Get recommended action
            action = self._get_recommended_action(pkg, vulns)
            
            # ── Exploit Intelligence ─────────────────────────────────────────
            # EPSS and CISA KEV are stamped onto each vuln by vulnerability_provider.
            # _extract_exploit_intel() reads those fields — no extra API call here.
            exploit_intel = self._extract_exploit_intel(vulns)

            vulnerable_libs.append({
                "library": lib_name,
                "current_version": pkg.get("version"),
                "vulnerabilities_count": len(vulns),
                "severity_breakdown": severity_breakdown,
                "used_in_files": files_using[:10],
                "priority": priority,
                "recommended_action": action,
                "exploit_intel": exploit_intel,
            })
        
        # ========================================
        # DISABLED: Undeclared dependencies tracking
        # ========================================
        # This section was tracking local project files (ai_trader.py, market_data.py, etc.)
        # as "undeclared dependencies" instead of external packages.
        # User requested removal since it's not tracking actual missing packages.
        # ========================================
        
        undeclared_deps = []  # Keep empty for now
        
        # Original code (disabled):
        # for lib_name, files in import_map.items():
        #     if lib_name in stdlib_modules:
        #         continue
        #     normalized_lib = lib_name.lower().replace('_', '-').replace('.', '-')
        #     is_declared = any(...)
        #     if not is_declared:
        #         undeclared_deps.append({...})

        
        # Sort: KEV first, then CRITICAL, then EPSS descending, then CVSS priority
        def _sort_key(lib):
            ei = lib.get("exploit_intel", {})
            in_kev = any(
                v.get("in_cisa_kev") for v in
                next((p.get("vulnerabilities", []) for p in catalog.get("packages", [])
                      if p.get("name") == lib["library"]), [])
            )
            return (
                0 if in_kev else 1,
                priority_order.get(lib["priority"], 4),
                -(ei.get("max_epss_score") or 0),
            )
        vulnerable_libs.sort(key=_sort_key)
        undeclared_deps.sort(key=lambda x: len(x["used_in_files"]), reverse=True)

        # Compute KEV + EPSS summary stats
        kev_libraries = sum(
            1 for lib in vulnerable_libs
            if lib.get("exploit_intel", {}).get("in_cisa_kev")
        )
        high_epss_libraries = sum(
            1 for lib in vulnerable_libs
            if (lib.get("exploit_intel", {}).get("max_epss_score") or 0) >= 0.1
        )
        
        report = {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "repository": metadata.get("repository", ""),
                "scan_type": metadata.get("scan_type", ""),
                "tool": TOOL_NAME
            },
            "summary": {
                "total_libraries_with_vulnerabilities": len(vulnerable_libs),
                "total_vulnerabilities": sum(lib["vulnerabilities_count"] for lib in vulnerable_libs),
                "critical_actions": sum(
                    1 for lib in vulnerable_libs if lib["priority"] == "CRITICAL"
                ),
                "kev_affected_libraries": kev_libraries,
                "high_epss_libraries": high_epss_libraries,
                "exploit_intel_available": EXPLOIT_INTEL_AVAILABLE,
            },
            "vulnerable_libraries": vulnerable_libs,
            "action_summary": self._generate_action_summary(vulnerable_libs, [])  # Empty undeclared list
        }
        
        # Write report
        output_file = self.scan_dir / f"{self.scan_id}_remediation_actions.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Remediation report written to: {output_file}")
        return str(output_file)
    
    def _count_by_severity(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        severity_breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for vuln in vulns:
            # Check severity_level first (new format), then parse from severity
            severity = vuln.get("severity_level", "")
            
            if not severity:
                # Fallback: parse from severity CVSS string
                severity_str = str(vuln.get("severity", "")).upper()
                
                # Check for keywords in CVSS string
                if "CRITICAL" in severity_str or severity_str.startswith("10") or severity_str.startswith("9"):
                    severity = "CRITICAL"
                elif "HIGH" in severity_str or severity_str.startswith("8") or severity_str.startswith("7"):
                    severity = "HIGH"
                elif "MEDIUM" in severity_str or severity_str.startswith("6") or severity_str.startswith("5") or severity_str.startswith("4"):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            severity = severity.upper()
            if severity == "CRITICAL":
                severity_breakdown["critical"] += 1
            elif severity == "HIGH":
                severity_breakdown["high"] += 1
            elif severity == "MEDIUM":
                severity_breakdown["medium"] += 1
            else:
                severity_breakdown["low"] += 1
        
        return severity_breakdown

    def _extract_exploit_intel(self, vulns: List[Dict]) -> Dict:
        """
        Summarise EPSS + CISA KEV data already stamped on each vulnerability.
        Data is stamped by exploit_intel_client via vulnerability_provider — 
        this method just aggregates it into a per-library summary.
        """
        high_epss_vulns = []
        max_epss = 0.0
        in_kev = False
        kev_date_added = None
        kev_due_date = None
        kev_required_action = None
        known_ransomware = "Unknown"

        for vuln in vulns:
            vuln_id = vuln.get("id", "Unknown")

            # CISA KEV
            if vuln.get("in_cisa_kev"):
                in_kev = True
                kev_date_added = kev_date_added or vuln.get("kev_date_added")
                kev_due_date = kev_due_date or vuln.get("kev_due_date")
                kev_required_action = kev_required_action or vuln.get("kev_required_action")
                known_ransomware = vuln.get("known_ransomware", "Unknown")

            # EPSS
            epss = vuln.get("epss_score") or 0
            if epss > max_epss:
                max_epss = epss
            if epss >= 0.1:
                high_epss_vulns.append({
                    "id": vuln_id,
                    "epss_score": epss,
                    "epss_percentile": vuln.get("epss_percentile"),
                    "probability": f"{epss * 100:.1f}%",
                })

        high_epss_vulns.sort(key=lambda x: x.get("epss_score", 0), reverse=True)

        return {
            "max_epss_score": max_epss,
            "max_epss_percentage": f"{max_epss * 100:.1f}%",
            "high_epss_count": len(high_epss_vulns),
            "high_epss_vulns": high_epss_vulns[:5],
            "urgency": self._determine_urgency(max_epss),
            "in_cisa_kev": in_kev,
            "kev_date_added": kev_date_added,
            "kev_due_date": kev_due_date,
            "kev_required_action": kev_required_action,
            "known_ransomware": known_ransomware,
        }
    
    def _determine_urgency(self, max_epss: float) -> str:
        """Determine urgency level based on EPSS score."""
        if max_epss > 0.5:
            return "URGENT"  # High probability of exploitation
        elif max_epss > 0.1:
            return "HIGH"  # Notable exploitation risk
        elif max_epss > 0.01:
            return "MODERATE"
        return "STANDARD"

    def _calculate_priority(self, severity_breakdown: Dict[str, int], vulns: List[Dict] = None) -> str:
        """
        Calculate remediation priority.

        Priority rules (first match wins):
          1. CISA KEV — actively exploited RIGHT NOW → always CRITICAL
          2. EPSS > 0.5 — 50%+ exploitation probability in 30 days → CRITICAL
          3. EPSS > 0.1 — 10%+ exploitation probability → HIGH minimum
          4. CVSS CRITICAL count → CRITICAL
          5. CVSS HIGH ≥ 3 → CRITICAL
          6. CVSS HIGH > 0 → HIGH
          7. CVSS MEDIUM → MEDIUM
          8. Default → LOW
        """
        if vulns:
            for vuln in vulns:
                # Rule 1: CISA KEV always forces CRITICAL
                if vuln.get("in_cisa_kev"):
                    return "CRITICAL"
                # Rule 2: High EPSS forces CRITICAL
                epss = vuln.get("epss_score") or 0
                if epss > 0.5:
                    return "CRITICAL"

            # Rule 3: Notable EPSS → floor at HIGH
            for vuln in vulns:
                if (vuln.get("epss_score") or 0) > 0.1:
                    # Still allow CRITICAL from CVSS below; just raise floor
                    if severity_breakdown["critical"] == 0 and severity_breakdown["high"] < 3:
                        return "HIGH"

        # Rules 4-8: traditional CVSS-based priority
        if severity_breakdown["critical"] > 0:
            return "CRITICAL"
        if severity_breakdown["high"] >= 3:
            return "CRITICAL"
        if severity_breakdown["high"] > 0:
            return "HIGH"
        if severity_breakdown["medium"] > 0:
            return "MEDIUM"
        return "LOW"
    
    def _get_recommended_action(self, pkg: Dict, vulns: List[Dict]) -> Dict:
        """Generate specific remediation action for a vulnerable package"""
        fixed_version = self._get_fixed_version(vulns)
        ecosystem = pkg.get("ecosystem", "pypi")
        pkg_name = pkg.get("name")
        current_version = pkg.get("version", "")
        
        if fixed_version:
            # Compare versions to check if upgrade is actually needed
            needs_upgrade = self._version_compare(current_version, fixed_version)
            
            if needs_upgrade:
                if ecosystem == "pypi":
                    fix_command = f"pip install {pkg_name}>={fixed_version}"
                else:  # npm
                    fix_command = f"npm install {pkg_name}@>={fixed_version}"
                
                return {
                    "type": "upgrade",
                    "action": f"Upgrade from {current_version} to {fixed_version} or later",
                    "current_version": current_version,
                    "fixed_version": fixed_version,
                    "fix_command": fix_command,
                    "fixes_vulnerabilities": len(vulns),
                    "status": "action_required"
                }
            else:
                # Current version is >= fixed version, but vulnerability still detected
                # This could mean: newer vuln found, or detection is based on affected ranges
                return {
                    "type": "verify",
                    "action": f"Version {current_version} should be patched (fix was in {fixed_version})",
                    "current_version": current_version,
                    "fixed_version": fixed_version,
                    "note": "Vulnerability may affect ranges above the initial fix. Check latest advisories.",
                    "recommendation": f"Verify {pkg_name} is truly patched or upgrade to latest stable",
                    "status": "needs_verification"
                }
        else:
            return {
                "type": "investigate",
                "action": "Review vulnerabilities manually - no fixed version available yet",
                "current_version": current_version,
                "reason": "No patch released or version information missing",
                "recommendation": f"Check {pkg_name} GitHub/security advisories for updates",
                "status": "no_fix_available"
            }
    
    def _version_compare(self, current: str, fixed: str) -> bool:
        """
        Compare versions to determine if upgrade is needed.
        Returns True if current < fixed (upgrade needed), False otherwise.
        """
        try:
            from packaging.version import parse, InvalidVersion
            try:
                current_v = parse(current)
                fixed_v = parse(fixed)
                return current_v < fixed_v
            except InvalidVersion:
                # Fallback: simple string comparison if versions are non-standard
                return current < fixed
        except ImportError:
            # packaging not installed, use simple comparison
            # Split by . and compare numerically
            try:
                current_parts = [int(x) for x in current.split('.')]
                fixed_parts = [int(x) for x in fixed.split('.')]
                return current_parts < fixed_parts
            except (ValueError, AttributeError):
                return True  # Assume upgrade needed if can't compare
    
    def _get_fixed_version(self, vulns: List[Dict]) -> str:
        """Extract the fixed version from simplified vulnerabilities"""
        for vuln in vulns:
            # Simplified: 'fixed_in' key holds the version
            fixed = vuln.get("fixed_in")
            if fixed and fixed != "Unknown":
                return fixed
        return None
    
    def _get_undeclared_action(self, lib_name: str, ecosystem: str) -> Dict:
        """Generate action for undeclared dependency"""
        if ecosystem == "pypi":
            manifest = "requirements.txt"
            cmd = f"echo '{lib_name}' >> requirements.txt"
        else:  # npm
            manifest =  "package.json"
            cmd = f"npm install {lib_name} --save"
        
        return {
            "type": "declare",
            "action": f"Add '{lib_name}' to {manifest}",
            "fix_command": cmd,
            "reason": "Missing from manifest - will cause ModuleNotFoundError at runtime"
        }
    
    def _generate_action_summary(self, vulnerable_libs: List[Dict], undeclared_deps: List[Dict]) -> Dict:
        """Generate summary of all actions required"""
        upgrade_count = sum(
            1 for lib in vulnerable_libs if lib["recommended_action"]["type"] == "upgrade"
        )
        investigate_count = sum(
            1 for lib in vulnerable_libs if lib["recommended_action"]["type"] == "investigate"
        )
        declare_count = len(undeclared_deps)
        
        total_vulns_fixable = sum(
            lib["recommended_action"].get("fixes_vulnerabilities", 0)
            for lib in vulnerable_libs
            if lib["recommended_action"]["type"] == "upgrade"
        )
        
        return {
            "total_actions_required": len(vulnerable_libs) + len(undeclared_deps),
            "by_type": {
                "upgrade": upgrade_count,
                "declare": declare_count,
                "investigate": investigate_count
            },
            "estimated_vulnerabilities_fixed": total_vulns_fixable,
            "estimated_fix_time": self._estimate_fix_time(upgrade_count, declare_count)
        }
    
    def _estimate_fix_time(self, upgrade_count: int, declare_count: int) -> str:
        """Estimate time to complete all actions"""
        # ~2 mins per upgrade, ~1 min per declaration
        total_minutes = (upgrade_count * 2) + (declare_count * 1)
        
        if total_minutes < 10:
            return "5-10 minutes"
        elif total_minutes < 30:
            return "15-30 minutes"
        elif total_minutes < 60:
            return "30-60 minutes"
        else:
            hours = total_minutes // 60
            return f"{hours}-{hours+1} hours"
