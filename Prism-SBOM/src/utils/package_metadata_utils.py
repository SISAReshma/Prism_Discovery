# File: src/utils/package_metadata_utils.py
"""
Package metadata fetching - API First, DB Cache Fallback

Strategy:
1. Call API (PyPI, npm, deps.dev)
2. If SUCCESS → Return data AND cache to MySQL DB (if not already cached)
3. If FAILURE (rate limit, network error) → Try DB cache as fallback
4. If all fail → Return None

NOTE: Local file cache is NOT used (data is same as DB cache, redundant)
"""

from typing import Optional, Dict, Any, List
import urllib.parse
import requests
import logging

logger = logging.getLogger(__name__)

# DB cache import
try:
    from src.clients.db_cache_client import (
        get_pypi_from_db, set_pypi_to_db,
        get_npm_from_db, set_npm_to_db,
        get_depsdev_from_db, set_depsdev_to_db,
        get_osv_from_db, set_osv_to_db,
        PYMYSQL_AVAILABLE
    )
    DB_CACHE_AVAILABLE = PYMYSQL_AVAILABLE
except ImportError:
    DB_CACHE_AVAILABLE = False
    def get_pypi_from_db(pkg, ver=None): return None
    def set_pypi_to_db(pkg, data, ver=None): return False
    def get_npm_from_db(pkg, ver=None): return None
    def set_npm_to_db(pkg, data, ver=None): return False
    def get_depsdev_from_db(eco, pkg, ver): return None
    def set_depsdev_to_db(eco, pkg, ver, data): return False
    def get_osv_from_db(eco, pkg, ver=None): return None
    def set_osv_to_db(eco, pkg, vulns, ver=None): return False

DEFAULT_TIMEOUT = 10.0


def _api_get(url, timeout=DEFAULT_TIMEOUT):
    """Simple GET wrapper for API calls."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def fetch_pypi_meta(pkg, ver=None, timeout=DEFAULT_TIMEOUT):
    """
    Fetch from PyPI API first, then DB cache as fallback.
    
    Strategy:
    1. Call PyPI API
    2. If success → cache to DB (if not already) → return data
    3. If fail → try DB cache → return cached data
    4. If all fail → return None
    """
    if not pkg:
        return None
    
    # Build URL
    if ver:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/{urllib.parse.quote(ver)}/json"
    else:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json"
    
    # Try API first
    result = _api_get(url, timeout=timeout)
    if result:
        # Cache to DB (for future fallback)
        if DB_CACHE_AVAILABLE:
            set_pypi_to_db(pkg, _minimize_pypi(result, pkg, ver), ver)
        return result
    
    # API failed - fallback to DB cache
    if DB_CACHE_AVAILABLE:
        cached = get_pypi_from_db(pkg, ver)
        if cached:
            logger.debug(f"[CACHE HIT] PyPI DB cache: {pkg}@{ver}")
            return _to_pypi_format(cached)
    
    # All failed
    return None


def _minimize_pypi(meta, pkg, ver=None):
    """Minimize PyPI response for DB caching."""
    info = meta.get("info", {}) or {}
    return {
        "name": pkg,
        "version": ver or info.get("version", ""),
        "license": extract_license_from_pypi_meta(meta),
        "supplier": info.get("author", "Unknown"),
        "description": (info.get("summary") or "")[:500],
        "release_date": extract_release_date_from_pypi(meta, ver),
        "homepage": info.get("home_page", ""),
        "hashes": extract_hashes_from_pypi_meta(meta, ver)
    }


def _to_pypi_format(cached):
    """Convert DB cache to PyPI-like format."""
    return {
        "info": {
            "name": cached.get("name"),
            "version": cached.get("version"),
            "license": cached.get("license", "NOASSERTION"),
            "author": cached.get("supplier", "Unknown"),
            "summary": cached.get("description", ""),
            "home_page": cached.get("homepage", ""),
        },
        "urls": [],
        "_from_cache": True
    }


def extract_license_from_pypi_meta(meta):
    """Extract license from PyPI metadata."""
    if not meta:
        return "NOASSERTION"
    info = meta.get("info", {}) or {}
    lic = (info.get("license") or "").strip()
    if lic:
        return lic
    for c in info.get("classifiers", []) or []:
        if "License ::" in c:
            return c.split("::")[-1].strip()
    return "NOASSERTION"


def extract_hashes_from_pypi_meta(meta, ver=None):
    """Extract SHA-256 hashes from PyPI metadata."""
    if not meta:
        return []
    for u in meta.get("urls", []) or []:
        sha = (u.get("digests", {}) or {}).get("sha256", "")
        if sha:
            return [{"alg": "SHA-256", "content": sha}]
    return []


def extract_release_date_from_pypi(meta, ver=None):
    """Extract release date from PyPI metadata."""
    if not meta:
        return ""
    if ver:
        for r in meta.get("releases", {}).get(ver, []):
            t = r.get("upload_time_iso_8601") or r.get("upload_time")
            if t:
                return t
    urls = meta.get("urls", [])
    if urls:
        t = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time")
        if t:
            return t
    return ""


def fetch_npm_meta(pkg, ver=None, timeout=DEFAULT_TIMEOUT):
    """
    Fetch from NPM API first, then DB cache as fallback.
    
    Strategy:
    1. Call npm registry API
    2. If success → cache to DB → return data
    3. If fail → try DB cache → return cached data
    4. If all fail → return None
    """
    if not pkg:
        return None
    
    url = f"https://registry.npmjs.org/{urllib.parse.quote(pkg)}"
    if ver:
        url += f"/{urllib.parse.quote(ver)}"
    
    result = _api_get(url, timeout=timeout)
    if result:
        if DB_CACHE_AVAILABLE:
            set_npm_to_db(pkg, _minimize_npm(result, pkg, ver), ver)
        return result
    
    # API failed - fallback to DB cache
    if DB_CACHE_AVAILABLE:
        cached = get_npm_from_db(pkg, ver)
        if cached:
            logger.debug(f"[CACHE HIT] npm DB cache: {pkg}@{ver}")
            return _to_npm_format(cached)
    
    # All failed
    return None


def _minimize_npm(meta, pkg, ver=None):
    """Minimize NPM response for DB caching."""
    if "versions" in meta:
        v = ver or meta.get("dist-tags", {}).get("latest", "")
        vd = meta.get("versions", {}).get(v, {})
    else:
        vd = meta
        v = ver or meta.get("version", "")
    
    author = vd.get("author", "Unknown")
    if isinstance(author, dict):
        author = author.get("name", "Unknown")
    
    return {
        "name": pkg,
        "version": v,
        "license": extract_license_from_npm_meta(vd),
        "supplier": str(author),
        "description": (vd.get("description") or "")[:500],
        "release_date": extract_release_date_from_npm(meta, v),
        "homepage": vd.get("homepage", ""),
        "hashes": extract_hashes_from_npm_meta(vd)
    }


def _to_npm_format(cached):
    """Convert DB cache to NPM-like format."""
    return {
        "name": cached.get("name"),
        "version": cached.get("version"),
        "license": cached.get("license", "NOASSERTION"),
        "author": cached.get("supplier", "Unknown"),
        "description": cached.get("description", ""),
        "homepage": cached.get("homepage", ""),
        "dist": {},
        "_from_cache": True
    }


def extract_license_from_npm_meta(meta):
    """Extract license from NPM metadata."""
    if not meta:
        return "NOASSERTION"
    lic = meta.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict):
        return lic.get("type", "NOASSERTION")
    return "NOASSERTION"


def extract_hashes_from_npm_meta(meta, ver=None):
    """Extract hashes from NPM metadata."""
    if not meta:
        return []
    dist = meta.get("dist", {})
    if dist.get("integrity"):
        i = dist["integrity"]
        if i.startswith("sha512-"):
            return [{"alg": "SHA-512", "content": i.replace("sha512-", "")}]
    if dist.get("shasum"):
        return [{"alg": "SHA-1", "content": dist["shasum"]}]
    return []


def extract_release_date_from_npm(meta, ver=None):
    """Extract release date from NPM metadata."""
    if not meta:
        return ""
    td = meta.get("time", {})
    if ver and ver in td:
        return td[ver]
    lt = meta.get("dist-tags", {}).get("latest")
    if lt and lt in td:
        return td[lt]
    return ""


def fetch_depsdev_meta(eco, pkg, ver, timeout=DEFAULT_TIMEOUT):
    """Fetch from deps.dev API first, then DB cache as fallback."""
    if not pkg or not ver:
        return None
    
    eco_map = {"python": "pypi", "javascript": "npm", "npm": "npm", "pypi": "pypi"}
    depsdev_eco = eco_map.get(eco.lower(), eco.lower())
    
    pkg_encoded = urllib.parse.quote(pkg, safe="")
    ver_encoded = urllib.parse.quote(ver, safe="")
    url = f"https://api.deps.dev/v3alpha/systems/{depsdev_eco}/packages/{pkg_encoded}/versions/{ver_encoded}"
    
    result = _api_get(url, timeout=timeout)
    if result:
        if DB_CACHE_AVAILABLE:
            set_depsdev_to_db(depsdev_eco, pkg, ver, _minimize_depsdev(result, pkg, ver))
        return result
    
    if DB_CACHE_AVAILABLE:
        cached = get_depsdev_from_db(depsdev_eco, pkg, ver)
        if cached:
            return cached
    
    return None


def _minimize_depsdev(meta, pkg, ver):
    """Minimize deps.dev response for DB caching."""
    if not meta:
        return {}
    
    lics = meta.get("licenses", [])
    if isinstance(lics, str):
        lic = lics
    elif lics:
        f = lics[0]
        lic = f.get("license", "NOASSERTION") if isinstance(f, dict) else str(f)
    else:
        lic = meta.get("license", "NOASSERTION")
    
    hp = ""
    for lk in meta.get("links", []):
        if isinstance(lk, dict) and lk.get("label") in ("HOMEPAGE", "SOURCE_REPO"):
            hp = lk.get("url", "")
            break
    
    return {
        "name": pkg,
        "version": ver,
        "license": lic,
        "homepage": hp,
        "description": meta.get("description", "")
    }


def infer_license_type(license_str):
    """Infer license type from license string."""
    if not license_str or license_str == "NOASSERTION":
        return "Unknown"
    ll = license_str.lower()
    if any(x in ll for x in ["proprietary", "commercial", "private"]):
        return "Proprietary"
    if any(x in ll for x in ["mit", "bsd", "apache", "isc", "gpl", "lgpl", "mpl", "eclipse", "unlicense", "cc0"]):
        return "Open Source"
    return "Unknown"


def get_cache_status():
    """Get status of cache backends."""
    st = {
        "db_cache_available": DB_CACHE_AVAILABLE,
        "strategy": "API First → DB Fallback (No local file cache)"
    }
    if DB_CACHE_AVAILABLE:
        try:
            from src.clients.db_cache_client import test_db_connection
            st["db_connection"] = test_db_connection()
        except Exception as e:
            st["db_connection"] = {"error": str(e)}
    return st
