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
from src.utils.rate_limiter import get_rate_limiter

# Import API URL from centralized config
from src.config.config import OSV_API

# Enable local file cache for OSV results
try:
    from src.utils.cache_manager import get_osv_cache, set_osv_cache
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
    
    Includes rate limiting and caching support.
    """
    
    def __init__(self, timeout: int = 15):
        """
        Initialize OSV client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = OSV_API
    
    def _make_request(self, url: str, method: str = "GET", json_data: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make a rate-limited HTTP request.
        
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
                return requests.post(url, json=json_data, timeout=self.timeout)
            else:
                return requests.get(url, timeout=self.timeout)
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
        # Extract severity string from CVSS array
        severity_str = "Unknown"
        severity_array = v.get("severity", [])
        if severity_array:
            first_score = severity_array[0]
            if isinstance(first_score, dict):
                severity_str = first_score.get("score", "Unknown")
            else:
                severity_str = str(first_score)
        elif v.get("database_specific", {}).get("severity"):
            severity_str = v.get("database_specific", {}).get("severity")
        
        # Parse CVSS to get severity level
        severity_level = self._parse_cvss_severity(severity_str)
        
        # Extract fixed_in from affected[].ranges[].events
        fixed_in = self._extract_fixed_version(v)
        
        # Extract primary URL from references
        url = self._extract_primary_url(v)
        
        return {
            "id": v.get("id"),
            "severity": severity_str,
            "severity_level": severity_level,
            "summary": v.get("summary"),
            "fixed_in": fixed_in,
            "url": url,
            "modified": v.get("modified"),
            "published": v.get("published"),
            "aliases": v.get("aliases", []),
            "details": v.get("details"),
        }
    
    def _parse_cvss_severity(self, cvss_string: str) -> str:
        """
        Parse CVSS vector string or score and return severity level.
        
        Uses NIST/FIRST standard CVSS v3.x severity thresholds:
        - CRITICAL: 9.0 - 10.0
        - HIGH: 7.0 - 8.9
        - MEDIUM: 4.0 - 6.9
        - LOW: 0.1 - 3.9
        - NONE: 0.0
        
        Reference: https://www.first.org/cvss/v3.1/specification-document
        
        Args:
            cvss_string: CVSS vector string, score, or severity keyword
            
        Returns:
            CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN
        """
        if not cvss_string or cvss_string == "Unknown":
            return "UNKNOWN"
        
        cvss_upper = cvss_string.upper()
        
        # Check for known severity keywords first
        if "CRITICAL" in cvss_upper:
            return "CRITICAL"
        if "HIGH" in cvss_upper:
            return "HIGH"
        if "MEDIUM" in cvss_upper or "MODERATE" in cvss_upper:
            return "MEDIUM"
        if "LOW" in cvss_upper:
            return "LOW"
        
        # Try to extract numeric CVSS score
        # OSV sometimes returns just a score like "7.5" or "CVSS:3.1/.../score:7.5"
        import re
        
        # Pattern 1: Direct numeric score (e.g., "7.5", "9.8")
        score_match = re.search(r'^(\d+\.?\d*)$', cvss_string.strip())
        if score_match:
            try:
                score = float(score_match.group(1))
                return self._cvss_score_to_severity(score)
            except ValueError:
                pass
        
        # Pattern 2: CVSS vector with embedded score
        # Some formats: "CVSS:3.1/AV:N/.../score:7.5" or just the vector
        if "CVSS:3" in cvss_upper or "CVSS:2" in cvss_upper:
            # Try to find numeric score in the string
            scores = re.findall(r'(\d+\.\d+)', cvss_string)
            if scores:
                # Take the last numeric value (often the base score)
                try:
                    score = float(scores[-1])
                    if 0 <= score <= 10:
                        return self._cvss_score_to_severity(score)
                except ValueError:
                    pass
            
            # Fallback: Calculate approximate severity from vector components
            return self._calculate_severity_from_vector(cvss_upper)
        
        return "UNKNOWN"
    
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
            return "UNKNOWN"
    
    def _calculate_severity_from_vector(self, cvss_vector: str) -> str:
        """
        Approximate severity from CVSS 3.x vector string when no score is available.
        
        This uses a weighted point system based on CVSS v3.1 metric values.
        While not as precise as the official CVSS formula, it provides a 
        reasonable approximation for severity categorization.
        
        Args:
            cvss_vector: Uppercase CVSS vector string
            
        Returns:
            Approximate severity level
        """
        try:
            risk_points = 0
            
            # Attack Vector (AV) - Network is highest risk
            if "/AV:N" in cvss_vector:
                risk_points += 2
            elif "/AV:A" in cvss_vector:
                risk_points += 1
            
            # Attack Complexity (AC) - Low complexity is higher risk
            if "/AC:L" in cvss_vector:
                risk_points += 1
            
            # Privileges Required (PR) - None is highest risk
            if "/PR:N" in cvss_vector:
                risk_points += 2
            elif "/PR:L" in cvss_vector:
                risk_points += 1
            
            # User Interaction (UI) - None is higher risk
            if "/UI:N" in cvss_vector:
                risk_points += 1
            
            # Scope (S) - Changed scope increases severity
            if "/S:C" in cvss_vector:
                risk_points += 2
            
            # Impact metrics (C/I/A) - High impact scores highest
            for metric in ["/C:H", "/I:H", "/A:H"]:
                if metric in cvss_vector:
                    risk_points += 2
            for metric in ["/C:L", "/I:L", "/A:L"]:
                if metric in cvss_vector:
                    risk_points += 1
            
            # Map points to severity (max ~15 points possible)
            # Calibrated to approximate standard CVSS thresholds
            if risk_points >= 12:
                return "CRITICAL"
            elif risk_points >= 9:
                return "HIGH"
            elif risk_points >= 5:
                return "MEDIUM"
            elif risk_points >= 1:
                return "LOW"
        except Exception:
            pass
        
        return "UNKNOWN"
    
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
