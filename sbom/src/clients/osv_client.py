"""
OSV (Open Source Vulnerability) API Client

Fetches vulnerability data from Google's OSV.dev database.
Primary source for vulnerability information in the SBOM pipeline.
With local file-based caching support.
"""

from __future__ import annotations
import requests
from typing import Dict, Any, List, Optional, Set
import logging
import time
from functools import lru_cache

# Import rate limiter
from sbom.src.utils.rate_limiter import get_rate_limiter

# Import API URL from centralized config
from sbom.src.config.config import OSV_API

# Enable local file cache for OSV results
try:
    from sbom.src.utils.cache_manager import get_osv_cache, set_osv_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiter
_rate_limiter = get_rate_limiter()


class OSVClient:
    """
    Client for OSV (Open Source Vulnerability) API.
    
    Fetches vulnerability information for packages including:
    - Vulnerability IDs (OSV, CVE, GHSA, etc.)
    - Severity (CVSS scores)
    - Summary and details
    - Fixed versions
    - References
    
    Includes rate limiting, connection pooling, and caching support.
    """
    
    def __init__(self, timeout: int = 15):
        """
        Initialize OSV client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = OSV_API
        
        # Connection pooling for performance
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=requests.adapters.Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
    
    def _make_request(self, url: str, method: str = "GET", json_data: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make a rate-limited HTTP request with connection pooling.
        
        Args:
            url: URL to fetch
            method: HTTP method (GET or POST)
            json_data: JSON payload for POST requests
            
        Returns:
            Response object or None if rate limited/failed
        """
        # Check rate limit
        usage = _rate_limiter.get_current_usage("osv")
        if usage['remaining'] <= 0:
            logger.warning("[RATE LIMIT] OSV: Rate limit exceeded, skipping request")
            return None
        
        # Record the call
        _rate_limiter.record_call("osv")
        
        # Add small delay between requests (50ms) to avoid bursts
        time.sleep(0.05)
        
        try:
            if method == "POST":
                return self.session.post(url, json=json_data, timeout=self.timeout)
            else:
                return self.session.get(url, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"[OSV] Request failed: {e}")
            return None
    
    def query_package(
        self, 
        name: str, 
        ecosystem: Optional[str] = None, 
        version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Query OSV for vulnerabilities affecting a package.
        
        Args:
            name: Package name
            ecosystem: Package ecosystem (PyPI, npm, etc.)
            version: Optional version to filter results
            
        Returns:
            Dict with vulnerabilities and success status
            {
                "success": bool,
                "vulnerabilities": List[Dict],
                "raw_data": List[Dict] (optional, raw OSV response)
            }
        """
        result = {
            "success": False,
            "vulnerabilities": [],
            "rate_limited": False
        }
        
        if not name:
            return result
        
        # Build query payload
        payload: Dict[str, Any] = {"package": {"name": name}}
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
        if version:
            payload["version"] = version
        
        # Try API first
        logger.debug(f"[API CALL] OSV: {name}@{version} (ecosystem: {ecosystem})")
        url = f"{self.base_url}/query"
        resp = self._make_request(url, method="POST", json_data=payload)
        
        if resp and resp.status_code == 200:
            data = resp.json()
            raw_vulns = data.get("vulns") or []
            result["success"] = True
            result["raw_data"] = raw_vulns
            result["vulnerabilities"] = self._normalize_vulnerabilities(raw_vulns)
            
            # Cache the result for future fallback
            if CACHE_AVAILABLE:
                set_osv_cache(ecosystem or "unknown", name, raw_vulns, version)
                
        elif resp and resp.status_code == 429:
            # Rate limited - mark for cache fallback
            logger.warning(f"[RATE LIMITED] OSV: {name}@{version}")
            result["rate_limited"] = True
        else:
            # API error
            logger.debug(f"[API ERROR] OSV: {name}@{version} - status {resp.status_code if resp else 'None'}")
        
        # Fallback to cache if API failed
        if not result["success"] and CACHE_AVAILABLE:
            cached_vulns = get_osv_cache(ecosystem or "unknown", name, version)
            if cached_vulns is not None:
                logger.debug(f"[CACHE FALLBACK] OSV: {name}@{version}")
                result["success"] = True
                result["vulnerabilities"] = self._normalize_vulnerabilities(cached_vulns)
                result["from_cache"] = True
        
        return result
    
    def get_vulnerability(self, vuln_id: str) -> Dict[str, Any]:
        """
        Get details for a specific vulnerability ID.
        
        Args:
            vuln_id: Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx", "CVE-2024-xxxx")
            
        Returns:
            Dict with vulnerability details
        """
        result = {
            "success": False,
            "vulnerability": None
        }
        
        if not vuln_id:
            return result
        
        logger.debug(f"[API CALL] OSV: fetching {vuln_id}")
        url = f"{self.base_url}/vulns/{vuln_id}"
        resp = self._make_request(url)
        
        if resp and resp.status_code == 200:
            data = resp.json()
            result["success"] = True
            result["vulnerability"] = self._normalize_single_vulnerability(data)
            result["raw_data"] = data
        
        return result
    
    def _normalize_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize raw OSV entries into minimized vulnerability dicts.
        
        Args:
            vulns: Raw OSV vulnerability entries
            
        Returns:
            List of normalized vulnerability dicts
        """
        return [self._normalize_single_vulnerability(v) for v in vulns or []]
    
    def _normalize_single_vulnerability(self, v: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single OSV entry.
        
        Args:
            v: Raw OSV vulnerability entry
            
        Returns:
            Normalized vulnerability dict with essential fields only
        """
        # Extract best CVSS string using a priority cascade:
        #   1. Top-level severity[] (prefer CVSSv3.1 > v3.0 > v4.0 > v2)
        #   2. affected[].severity[] (many OSV entries only have it here)
        #   3. database_specific.severity (keyword like "HIGH")
        #   4. affected[].database_specific.severity / ecosystem_specific.severity
        severity_str = self._extract_best_severity_string(v)
        
        # Parse CVSS to get (numeric_score, severity_level) using 3-tier approach:
        #   Tier 1: Direct keyword (HIGH, CRITICAL, etc.)  → score=None
        #   Tier 2: Embedded numeric score in CVSS string   → score=float
        #   Tier 3: Calculate from vector (FIRST.org formula)→ score=float
        cvss_score, severity_level = self._parse_cvss_severity(severity_str)
        
        # Safety net: If all 3 tiers failed, estimate severity from the
        # vulnerability's own text (summary + details) rather than blindly
        # defaulting to MEDIUM.  A vuln that says "remote code execution"
        # is very different from "minor information disclosure".
        if severity_level == "UNKNOWN":
            severity_level = self._estimate_severity_from_text(v)
        
        # Map NONE (CVSS 0.0 — virtually impossible for a real vuln) → LOW
        if severity_level == "NONE":
            severity_level = "LOW"
        
        # Filter sentinel values: -1.0 means "could not parse" and must
        # never appear in the API response.  Expose only valid 0.0–10.0.
        if cvss_score is not None and cvss_score < 0:
            cvss_score = None
        
        # Extract fixed_in from affected[].ranges[].events
        fixed_in = self._extract_fixed_version(v)
        
        # Extract primary URL from references
        url = self._extract_primary_url(v)
        
        return {
            "id": v.get("id"),
            "severity": severity_str,
            "severity_level": severity_level,
            "cvss_score": cvss_score,  # Numeric 0.0–10.0, or None if unavailable
            "summary": v.get("summary"),
            "fixed_in": fixed_in,
            "url": url,
            "modified": v.get("modified"),
            "published": v.get("published"),
            "aliases": v.get("aliases", []),
            "details": v.get("details"),
        }
    
    @staticmethod
    def _pick_best_cvss(severity_array: list) -> str:
        """
        From an OSV severity[] array, pick the best CVSS entry.
        Preference: CVSSv3.1 > CVSSv3.0 > CVSSv4.0 > CVSSv2 > first available.
        """
        if not severity_array:
            return "Unknown"
        
        best = None
        best_priority = -1
        
        # Priority map: higher is better
        priority_map = {
            "CVSS_V3": 4,     # OSV type field for CVSSv3.x
            "CVSS_V4": 3,     # OSV type field for CVSSv4
            "CVSS_V2": 2,     # OSV type field for CVSSv2
        }
        
        for entry in severity_array:
            if isinstance(entry, dict):
                score = entry.get("score", "")
                stype = entry.get("type", "").upper()
                
                # Determine priority from explicit type or by inspecting the vector
                priority = priority_map.get(stype, 0)
                if priority == 0 and isinstance(score, str):
                    if "CVSS:3.1" in score.upper():
                        priority = 4
                    elif "CVSS:3.0" in score.upper():
                        priority = 3
                    elif "CVSS:4.0" in score.upper():
                        priority = 2
                    elif "CVSS:2" in score.upper():
                        priority = 1
                
                if priority > best_priority and score:
                    best_priority = priority
                    best = score
            elif isinstance(entry, str) and entry:
                if best is None:
                    best = entry
        
        return best if best else "Unknown"
    
    def _extract_best_severity_string(self, v: Dict[str, Any]) -> str:
        """
        Extract the best available severity/CVSS string from an OSV entry.
        
        Checks (in order):
          1. Top-level severity[] array
          2. affected[].severity[] arrays
          3. database_specific.severity (keyword)
          4. affected[].database_specific.severity / ecosystem_specific.severity
        """
        # 1. Top-level severity[]
        top_sev = v.get("severity", [])
        result = self._pick_best_cvss(top_sev)
        if result != "Unknown":
            return result
        
        # 2. affected[].severity[] — many OSV entries only have severity here
        for affected_block in v.get("affected", []):
            aff_sev = affected_block.get("severity", [])
            candidate = self._pick_best_cvss(aff_sev)
            if candidate != "Unknown":
                return candidate
        
        # 3. database_specific.severity (top-level) — keyword like "HIGH" or "MODERATE"
        db_sev = v.get("database_specific", {}).get("severity")
        if db_sev and isinstance(db_sev, str):
            return db_sev
        
        # 4. affected[].database_specific.severity / ecosystem_specific.severity
        for affected_block in v.get("affected", []):
            for key in ("database_specific", "ecosystem_specific"):
                nested_sev = affected_block.get(key, {}).get("severity")
                if nested_sev and isinstance(nested_sev, str):
                    return nested_sev
        
        return "Unknown"
    
    def _parse_cvss_severity(self, cvss_string: str) -> tuple:
        """
        Parse CVSS vector string or score and return (cvss_score, severity_level).
        
        Three-tier parsing:
          Tier 1: Direct severity keyword (HIGH, CRITICAL, etc.)
          Tier 2: Embedded numeric score in string
          Tier 3: Full CVSS v3.1 formula calculation from vector components
        
        Uses NIST/FIRST standard thresholds:
        - CRITICAL: 9.0 – 10.0
        - HIGH: 7.0 – 8.9
        - MEDIUM: 4.0 – 6.9
        - LOW: 0.1 – 3.9
        - NONE: 0.0
        
        Returns:
            Tuple of (cvss_score: float or None, severity_level: str)
            cvss_score is None when only a keyword is available (no numeric score)
        """
        if not cvss_string or cvss_string == "Unknown":
            return (None, "UNKNOWN")
        
        cvss_upper = cvss_string.upper()
        
        # Tier 1: Check for known severity keywords
        if "CRITICAL" in cvss_upper:
            return (None, "CRITICAL")
        if "HIGH" in cvss_upper:
            return (None, "HIGH")
        if "MEDIUM" in cvss_upper or "MODERATE" in cvss_upper:
            return (None, "MEDIUM")
        if "LOW" in cvss_upper:
            return (None, "LOW")
        
        import re
        
        # Tier 2a: Direct numeric score (e.g., "7.5", "9.8")
        score_match = re.search(r'^(\d+\.?\d*)$', cvss_string.strip())
        if score_match:
            try:
                score = float(score_match.group(1))
                return (score, self._cvss_score_to_severity(score))
            except ValueError:
                pass
        
        # Tier 2b + 3: CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
        if "CVSS:4" in cvss_upper or "CVSS:3" in cvss_upper or "CVSS:2" in cvss_upper:
            # Strip the "CVSS:X.Y/" version prefix before looking for embedded scores.
            # Without this, re.findall picks up "3.1" from "CVSS:3.1/..." and
            # treats the version number as a score → maps 3.1 → LOW (WRONG).
            remainder = re.sub(r'^CVSS:\d+\.?\d*/', '', cvss_string.strip(), flags=re.IGNORECASE)
            
            # Tier 2b: Look for an embedded numeric score in the remainder
            scores = re.findall(r'(\d+\.\d+)', remainder)
            if scores:
                try:
                    score = float(scores[-1])
                    if 0 <= score <= 10:
                        return (score, self._cvss_score_to_severity(score))
                except ValueError:
                    pass
            
            # Tier 3: No embedded score → calculate from vector
            # CVSS v4.0 uses different metrics → route to the v4 estimator
            if "CVSS:4" in cvss_upper:
                return self._estimate_cvss4_base_score(cvss_upper)
            # CVSS v3.x / v2 → official FIRST.org v3.1 formula
            return self._calculate_severity_from_vector(cvss_upper)
        
        return (None, "UNKNOWN")
    
    @staticmethod
    def _estimate_severity_from_text(v: Dict[str, Any]) -> str:
        """
        Estimate severity from vulnerability summary/details when no CVSS data
        is available.  Uses keyword analysis based on common vulnerability
        patterns from MITRE CWE and NVD descriptions.
        
        Returns one of: CRITICAL, HIGH, MEDIUM, LOW
        Default (no signal): HIGH (conservative — unscored vulns are often new/emerging)
        """
        text = " ".join(filter(None, [
            v.get("summary", ""),
            v.get("details", ""),
        ])).upper()
        
        if not text.strip():
            # No description at all → conservative HIGH
            return "HIGH"
        
        # CRITICAL indicators — full system compromise, wormable, no auth needed
        critical_patterns = [
            "REMOTE CODE EXECUTION", "RCE", "ARBITRARY CODE EXECUTION",
            "EXECUTE ARBITRARY CODE", "EXECUTING ARBITRARY CODE",
            "UNAUTHENTICATED", "PRE-AUTH", "WORMABLE",
            "PRIVILEGE ESCALATION TO ROOT", "PRIVILEGE ESCALATION TO ADMIN",
            "SUPPLY CHAIN", "BACKDOOR", "ZERO-DAY", "0-DAY",
        ]
        
        # HIGH indicators — significant impact but not full compromise
        high_patterns = [
            "ARBITRARY CODE", "CODE EXECUTION", "CODE INJECTION",
            "SQL INJECTION", "COMMAND INJECTION", "OS COMMAND",
            "BUFFER OVERFLOW", "HEAP OVERFLOW", "STACK OVERFLOW",
            "USE AFTER FREE", "USE-AFTER-FREE", "DOUBLE FREE",
            "PRIVILEGE ESCALATION", "AUTHENTICATION BYPASS",
            "DESERIALIZATION", "UNSAFE DESERIALIZATION",
            "SERVER-SIDE REQUEST FORGERY", "SSRF",
            "XML EXTERNAL ENTITY", "XXE",
            "REMOTE FILE INCLUSION", "PATH TRAVERSAL",
            "DIRECTORY TRAVERSAL",
        ]
        
        # MEDIUM indicators — moderate impact
        medium_patterns = [
            "CROSS-SITE SCRIPTING", "XSS", "REFLECTED XSS", "STORED XSS",
            "CROSS-SITE REQUEST FORGERY", "CSRF",
            "OPEN REDIRECT", "URL REDIRECT",
            "INFORMATION DISCLOSURE", "INFORMATION LEAK",
            "SENSITIVE DATA EXPOSURE", "DATA EXPOSURE",
            "DENIAL OF SERVICE", "DOS", "CRASH",
            "REGEX DENIAL", "REDOS",
            "IMPROPER INPUT VALIDATION", "INPUT VALIDATION",
            "INSECURE DEFAULT", "WEAK ENCRYPTION",
            "CLEARTEXT", "PLAINTEXT CREDENTIAL",
            "MEMORY LEAK",
        ]
        
        # LOW indicators — minimal impact
        low_patterns = [
            "MINOR", "COSMETIC", "LOW IMPACT", "LOW SEVERITY",
            "VERBOSE ERROR", "DEBUG INFORMATION",
            "VERSION DISCLOSURE", "BANNER DISCLOSURE",
            "CLICKJACKING",
        ]
        
        for pattern in critical_patterns:
            if pattern in text:
                return "CRITICAL"
        
        for pattern in high_patterns:
            if pattern in text:
                return "HIGH"
        
        for pattern in medium_patterns:
            if pattern in text:
                return "MEDIUM"
        
        for pattern in low_patterns:
            if pattern in text:
                return "LOW"
        
        # No keyword match — default to HIGH (conservative: unscored vulns
        # are often new/emerging and haven't been fully analyzed yet)
        return "HIGH"
    
    def _cvss_score_to_severity(self, score: float) -> str:
        """
        Convert CVSS base score to severity level using NIST/FIRST standard thresholds.
        
        Reference: https://nvd.nist.gov/vuln-metrics/cvss
        
        Args:
            score: CVSS base score (0.0 - 10.0)
            
        Returns:
            Severity level string
        """
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "NONE"  # CVSS score of exactly 0.0 = NONE per NIST spec
    
    @staticmethod
    def calculate_cvss3_base_score(cvss_vector: str) -> float:
        """
        Calculate CVSS v3.0/v3.1 base score from a vector string using the
        official FIRST.org formula.
        
        Reference: https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
        
        Args:
            cvss_vector: CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            
        Returns:
            Base score 0.0–10.0, or -1.0 if the vector cannot be parsed
        """
        import math, re
        
        vec = cvss_vector.upper()
        
        def _get(metric: str) -> str:
            """Extract a single metric value from the vector."""
            m = re.search(rf'/{metric}:([A-Z]+)', vec)
            return m.group(1) if m else ""
        
        # --- Metric value maps (FIRST.org spec Table 15–22) ---
        av_map  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map  = {"L": 0.77, "H": 0.44}
        ui_map  = {"N": 0.85, "R": 0.62}
        cia_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        
        # Privileges Required depends on Scope
        scope_changed = (_get("S") == "C")
        if scope_changed:
            pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
        else:
            pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
        
        try:
            av = av_map[_get("AV")]
            ac = ac_map[_get("AC")]
            pr = pr_map[_get("PR")]
            ui = ui_map[_get("UI")]
            c  = cia_map[_get("C")]
            i  = cia_map[_get("I")]
            a  = cia_map[_get("A")]
        except KeyError:
            return -1.0  # Missing or invalid metric
        
        # --- CVSS v3.1 Base Score formula ---
        # ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        
        if iss <= 0:
            return 0.0
        
        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        
        if impact <= 0:
            return 0.0
        
        # Exploitability = 8.22 × AV × AC × PR × UI
        exploitability = 8.22 * av * ac * pr * ui
        
        # Final score
        if scope_changed:
            raw = 1.08 * (impact + exploitability)
        else:
            raw = impact + exploitability
        
        # Roundup: smallest number ≥ x with 1 decimal place
        # e.g. Roundup(4.02) = 4.1, Roundup(4.00) = 4.0
        score = math.ceil(min(raw, 10.0) * 10) / 10
        return score
    
    def _calculate_severity_from_vector(self, cvss_vector: str) -> tuple:
        """
        Calculate base score and severity from a CVSS v3.x vector string
        using the official FIRST.org formula.
        
        Args:
            cvss_vector: Uppercase CVSS vector string
            
        Returns:
            Tuple of (cvss_score: float, severity_level: str)
            Returns (-1.0, "UNKNOWN") if vector cannot be parsed
        """
        score = self.calculate_cvss3_base_score(cvss_vector)
        if score < 0:
            return (-1.0, "UNKNOWN")
        return (score, self._cvss_score_to_severity(score))
    
    def _estimate_cvss4_base_score(self, cvss_vector: str) -> tuple:
        """
        Rough CVSS v4.0 estimation by mapping v4 metrics to approximate
        v3.1 equivalents and running the v3.1 base-score formula.

        CVSS v4.0 introduces different metric names (VC/VI/VA instead of C/I/A,
        AT instead of no equivalent, UI:P/A instead of R, SC/SI/SA for subsequent
        system impact).  This method translates them so we get a reasonable
        numeric score rather than falling back to text estimation.

        Mapping rules:
          AV, AC, PR  → identical in both versions
          AT:P (attack requirements present) → downgrade AC to H (harder attack)
          UI:P/A → UI:R (requires interaction)
          VC/VI/VA → C/I/A (vulnerable system impact)
          SC/SI/SA any H → Scope:Changed, else Scope:Unchanged

        Args:
            cvss_vector: Uppercase CVSS v4.0 vector string

        Returns:
            Tuple of (cvss_score: float, severity_level: str)
            Returns (None, "UNKNOWN") if the vector cannot be estimated
        """
        import re

        vec = cvss_vector.upper()

        def _get(metric: str) -> str:
            m = re.search(rf'/{metric}:([A-Z]+)', vec)
            return m.group(1) if m else ""

        # --- Map v4 metrics to v3.1 equivalents ---
        av = _get("AV") or "N"
        ac = _get("AC") or "L"
        pr = _get("PR") or "N"

        # AT (Attack Requirements): v4 only. P → harder attack → bump AC to H
        at = _get("AT")
        if at == "P" and ac == "L":
            ac = "H"

        # UI: v4 has N / P (Passive) / A (Active) → map P,A → R (Requires)
        ui_v4 = _get("UI") or "N"
        ui = "N" if ui_v4 == "N" else "R"

        # Impact: use VC/VI/VA (vulnerable system) as primary C/I/A
        c = _get("VC") or "N"
        i = _get("VI") or "N"
        a = _get("VA") or "N"

        # Scope: if any subsequent-system impact (SC/SI/SA) is H → Changed
        sc = _get("SC") or "N"
        si = _get("SI") or "N"
        sa = _get("SA") or "N"
        s = "C" if any(x == "H" for x in [sc, si, sa]) else "U"

        # Build synthetic CVSS v3.1 vector and score it
        synth = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        score = self.calculate_cvss3_base_score(synth)

        if score < 0:
            return (None, "UNKNOWN")
        return (score, self._cvss_score_to_severity(score))

    def _extract_fixed_version(self, osv_entry: Dict[str, Any]) -> str:
        """
        Extract fixed version from OSV affected[].ranges[].events.
        
        Args:
            osv_entry: OSV vulnerability entry
            
        Returns:
            Comma-separated list of fixed versions, or "Unknown"
        """
        fixed_versions = []
        for affected in osv_entry.get("affected", []):
            for range_obj in affected.get("ranges", []):
                for event in range_obj.get("events", []):
                    if isinstance(event, dict) and "fixed" in event:
                        fixed_versions.append(event["fixed"])
        
        if fixed_versions:
            unique = sorted(set(fixed_versions))
            return ", ".join(unique)
        return "Unknown"
    
    def _extract_primary_url(self, osv_entry: Dict[str, Any]) -> str:
        """
        Extract primary URL from references.
        Prioritizes NVD advisory URLs.
        
        Args:
            osv_entry: OSV vulnerability entry
            
        Returns:
            Primary reference URL or empty string
        """
        references = osv_entry.get("references", [])
        
        # Priority 1: NVD advisory URL
        for ref in references:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                if "nvd.nist.gov" in url:
                    return url
        
        # Priority 2: Any ADVISORY type
        for ref in references:
            if isinstance(ref, dict):
                if ref.get("type") == "ADVISORY":
                    return ref.get("url", "")
        
        # Priority 3: First available URL
        for ref in references:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                if url:
                    return url
        
        return ""
    
    def extract_cve_ids(self, osv_entry: Dict[str, Any]) -> Set[str]:
        """
        Extract CVE IDs from an OSV entry.
        
        Args:
            osv_entry: OSV vulnerability entry
            
        Returns:
            Set of CVE IDs found in the entry
        """
        import re
        ids: Set[str] = set()
        
        # From aliases
        for a in osv_entry.get("aliases", []):
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                ids.add(a.upper())
        
        # From references
        for ref in osv_entry.get("references", []):
            url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
            if "CVE-" in url.upper():
                for m in re.findall(r"CVE-\d{4}-\d{4,}", url.upper()):
                    ids.add(m)
        
        # From id itself
        vid = osv_entry.get("id", "")
        if vid.upper().startswith("CVE-"):
            ids.add(vid.upper())
        
        return ids


# Convenience function for direct calls
def query_osv_package(
    name: str, 
    ecosystem: Optional[str] = None, 
    version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Query OSV for vulnerabilities affecting a package.
    
    Args:
        name: Package name
        ecosystem: Package ecosystem
        version: Optional version
        
    Returns:
        Dict with vulnerabilities
    """
    client = OSVClient()
    return client.query_package(name, ecosystem, version)


def get_osv_vulnerability(vuln_id: str) -> Dict[str, Any]:
    """
    Get details for a specific vulnerability ID.
    
    Args:
        vuln_id: Vulnerability ID
        
    Returns:
        Dict with vulnerability details
    """
    client = OSVClient()
    return client.get_vulnerability(vuln_id)
