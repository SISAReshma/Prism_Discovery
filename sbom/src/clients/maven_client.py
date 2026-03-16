"""
Maven Central Client for Java package metadata enrichment.

Provides functions to:
- Fetch artifact metadata from Maven Central Search API
- Extract license information from POM files
- Get artifact details (description, supplier, hashes)

Maven Central APIs used:
- Search API: https://search.maven.org/solrsearch/select
- Repository: https://repo1.maven.org/maven2

Note: Maven Central Search API returns limited metadata.
For full license/description info, we need to parse the POM file.
deps.dev is the preferred source for Java metadata enrichment.
"""

from __future__ import annotations
import requests
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List

from sbom.src.config.config import MAVEN_CENTRAL_API, MAVEN_CENTRAL_REPO, API_TIMEOUT
from sbom.src.utils.cache_manager import get_maven_cache, set_maven_cache


def fetch_maven_meta(group_id: str, artifact_id: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata for a Maven artifact.
    
    Strategy (fast path first):
    1. If groupId + artifactId + version are all known → fetch POM directly
       from repo1.maven.org (fast CDN, no search needed).
    2. If version is missing → use search.maven.org to discover the latest version,
       then fetch POM.
    3. Cache results; use cache as fallback on errors.
    """
    if not artifact_id:
        return None
    
    # ── FAST PATH: Direct POM fetch (skips slow search API) ──
    if group_id and artifact_id and version and version not in ("UNKNOWN", "unknown", ""):
        cached = get_maven_cache(group_id, artifact_id, version)
        if cached:
            return cached
        
        pom_meta = fetch_pom_metadata(group_id, artifact_id, version)
        if pom_meta:
            result = {
                "groupId": group_id,
                "artifactId": artifact_id,
                "version": version,
                **pom_meta,
            }
            set_maven_cache(group_id, artifact_id, version, result)
            return result
    
    # ── SLOW PATH: Search API (only when version is unknown) ──
    try:
        if group_id:
            query = f'g:"{group_id}" AND a:"{artifact_id}"'
        else:
            query = f'a:"{artifact_id}"'
        
        if version and version not in ("UNKNOWN", "unknown", ""):
            query += f' AND v:"{version}"'
        
        params = {
            "q": query,
            "rows": 1,
            "wt": "json"
        }
        
        resp = requests.get(MAVEN_CENTRAL_API, params=params, timeout=min(API_TIMEOUT, 15))
        
        if resp.status_code == 429:
            print(f"[RATE LIMITED] Maven: {group_id}:{artifact_id}@{version} - falling back to cache")
            if version:
                cached = get_maven_cache(group_id, artifact_id, version)
                if cached:
                    return cached
            return None
        
        resp.raise_for_status()
        
        data = resp.json()
        docs = data.get("response", {}).get("docs", [])
        
        if docs:
            doc = docs[0]
            result = {
                "groupId": doc.get("g", group_id),
                "artifactId": doc.get("a", artifact_id),
                "version": doc.get("latestVersion") or doc.get("v") or version,
                "timestamp": doc.get("timestamp"),
                "ec": doc.get("ec", []),
            }
            
            target_version = result.get("version") or version
            if target_version:
                pom_meta = fetch_pom_metadata(group_id or doc.get("g"), artifact_id, target_version)
                if pom_meta:
                    result.update(pom_meta)
            
            if version:
                set_maven_cache(group_id, artifact_id, version, result)
            
            return result
        
        return None
        
    except Exception as e:
        print(f"[WARN] Maven Central API error for {group_id}:{artifact_id}: {e} - falling back to cache")
        if version:
            cached = get_maven_cache(group_id, artifact_id, version)
            if cached:
                return cached
        return None


def fetch_maven_jar_hashes(group_id: str, artifact_id: str, version: str) -> List[Dict[str, str]]:
    """
    Fetch SHA-1 and MD5 hashes for a Maven JAR artifact.
    Maven Central stores .sha1 and .md5 companion files alongside every artifact.
    """
    if not all([group_id, artifact_id, version]):
        return []
    
    hashes = []
    group_path = group_id.replace(".", "/")
    base_url = f"{MAVEN_CENTRAL_REPO}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.jar"
    
    for alg, ext in [("SHA-1", ".sha1"), ("MD5", ".md5")]:
        try:
            resp = requests.get(f"{base_url}{ext}", timeout=5)
            if resp.status_code == 200:
                content = resp.text.strip().split()[0]  # Some files have extra text after hash
                if content and len(content) >= 32:  # MD5=32, SHA-1=40
                    hashes.append({"alg": alg, "content": content})
        except Exception:
            pass
    
    return hashes


def infer_supplier_from_maven(group_id: str, meta: Optional[Dict] = None) -> str:
    """
    Infer supplier/organization from Maven metadata when POM has no <developers>/<organization>.
    
    Strategy:
    1. POM developers/organization (already extracted)
    2. Homepage/SCM URL → GitHub org name (e.g. github.com/FasterXML → "FasterXML")
    3. GroupId domain inference (e.g. com.fasterxml.jackson.core → "fasterxml")
    """
    # 1) Check if meta already has developer/organization
    if meta:
        devs = meta.get("developers") or []
        if isinstance(devs, list) and devs:
            return devs[0]
        dev = meta.get("developer")
        if dev:
            return dev
        org = meta.get("organization")
        if org:
            return org
    
    # 2) Try to extract org from homepage/scm URL (GitHub/GitLab)
    if meta:
        for url_key in ("homepage", "scm_url"):
            url = meta.get(url_key, "") or ""
            if url:
                import re
                # Match github.com/OrgName or gitlab.com/OrgName
                m = re.search(r'(?:github|gitlab)\.com/([^/]+)', url, re.IGNORECASE)
                if m:
                    org_name = m.group(1)
                    # Skip generic names
                    if org_name.lower() not in ("topics", "search", "explore", "settings"):
                        return org_name
    
    # 3) Infer from groupId: com.fasterxml.jackson.core → "fasterxml"
    if group_id:
        parts = group_id.split(".")
        # Skip common TLD prefixes: com, org, io, net, dev, me
        _tld = {"com", "org", "io", "net", "dev", "me", "de", "uk", "co", "fr", "ru", "cn"}
        meaningful = [p for p in parts if p.lower() not in _tld]
        if meaningful:
            return meaningful[0]  # First meaningful segment (e.g., "fasterxml", "google", "apache")
    
    return "Unknown"


def fetch_pom_metadata(group_id: str, artifact_id: str, version: str) -> Optional[Dict[str, Any]]:
    """Fetch and parse POM file for extended metadata, including JAR hashes."""
    if not all([group_id, artifact_id, version]):
        return None
    
    try:
        group_path = group_id.replace(".", "/")
        pom_url = f"{MAVEN_CENTRAL_REPO}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
        
        resp = requests.get(pom_url, timeout=min(API_TIMEOUT, 10))
        if resp.status_code != 200:
            return None
        
        result = parse_pom_content(resp.text)
        
        # Fetch JAR hashes (SHA-1 + MD5)
        jar_hashes = fetch_maven_jar_hashes(group_id, artifact_id, version)
        if jar_hashes:
            result["hashes"] = jar_hashes
        
        # Infer supplier if POM has no developers/organization
        if not result.get("developer") and not result.get("organization"):
            inferred = infer_supplier_from_maven(group_id, result)
            if inferred and inferred != "Unknown":
                result["developer"] = inferred
                result["developers"] = [inferred]
        
        return result
        
    except Exception:
        return None


def parse_pom_content(pom_xml: str) -> Dict[str, Any]:
    """Parse POM XML content to extract metadata."""
    result = {}
    
    try:
        import re
        pom_xml = re.sub(r'\sxmlns\s*=\s*"[^"]*"', '', pom_xml, count=1)
        root = ET.fromstring(pom_xml)
        
        # Description
        desc_elem = root.find("description")
        if desc_elem is not None and desc_elem.text:
            result["description"] = desc_elem.text.strip()
        
        # Name
        name_elem = root.find("name")
        if name_elem is not None and name_elem.text:
            result["project_name"] = name_elem.text.strip()
        
        # URL
        url_elem = root.find("url")
        if url_elem is not None and url_elem.text:
            result["homepage"] = url_elem.text.strip()
        
        # Licenses
        licenses_elem = root.find("licenses")
        if licenses_elem is not None:
            licenses = []
            for lic in licenses_elem.findall("license"):
                name = lic.find("name")
                if name is not None and name.text:
                    licenses.append(name.text.strip())
            if licenses:
                result["license"] = licenses[0]
                result["licenses"] = licenses
        
        # Developers (suppliers)
        developers_elem = root.find("developers")
        if developers_elem is not None:
            developers = []
            for dev in developers_elem.findall("developer"):
                name = dev.find("name")
                org = dev.find("organization")
                if name is not None and name.text:
                    developers.append(name.text.strip())
                elif org is not None and org.text:
                    developers.append(org.text.strip())
            if developers:
                result["developer"] = developers[0]
                result["developers"] = developers
        
        # Organization
        org_elem = root.find("organization")
        if org_elem is not None:
            name = org_elem.find("name")
            if name is not None and name.text:
                result["organization"] = name.text.strip()
                if "developer" not in result:
                    result["developer"] = name.text.strip()
        
        # SCM (source control)
        scm_elem = root.find("scm")
        if scm_elem is not None:
            url = scm_elem.find("url")
            if url is not None and url.text:
                result["scm_url"] = url.text.strip()
                if "homepage" not in result:
                    result["homepage"] = url.text.strip()
        
    except Exception:
        pass  # POM parsing is best-effort
    
    return result


def extract_license_from_maven_meta(meta: Optional[Dict]) -> str:
    """Extract license string from Maven metadata."""
    if not meta:
        return "NOASSERTION"
    
    license_str = meta.get("license", "")
    if license_str:
        return license_str
    
    licenses = meta.get("licenses", [])
    if licenses:
        return licenses[0]
    
    return "NOASSERTION"


def extract_release_date_from_maven(meta: Optional[Dict]) -> str:
    """Extract release date from Maven metadata."""
    if not meta:
        return ""
    
    timestamp = meta.get("timestamp")
    if timestamp:
        try:
            from datetime import datetime
            dt = datetime.utcfromtimestamp(timestamp / 1000)
            return dt.isoformat() + "Z"
        except Exception:
            pass
    
    return ""


def infer_license_type(license_str: str) -> str:
    """Infer component origin (open-source vs commercial) from license."""
    if not license_str or license_str.upper() in ("NOASSERTION", "UNKNOWN"):
        return "third-party"
    
    open_source_indicators = [
        "apache", "mit", "bsd", "gpl", "lgpl", "mpl", "cddl",
        "epl", "eclipse", "artistic", "isc", "unlicense", "wtfpl",
        "cc0", "public domain", "zlib", "boost"
    ]
    
    lower = license_str.lower()
    for indicator in open_source_indicators:
        if indicator in lower:
            return "open-source"
    
    return "third-party"
