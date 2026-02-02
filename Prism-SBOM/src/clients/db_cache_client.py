"""
MySQL Database Cache Client for StackSQScanner

Provides database-backed caching as FALLBACK when API calls fail.
Priority: API First → DB Cache Fallback

Tables used:
- pypi_cache: PyPI package metadata
- npm_cache: NPM package metadata
- depsdev_cache: deps.dev API metadata
- osv_cache: OSV vulnerability data

Connection: Uses PyMySQL for MySQL 8.0+
"""

import os
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Try to import pymysql
try:
    import pymysql
    from pymysql.cursors import DictCursor
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False
    logger.warning("pymysql not installed. Database cache will not be available.")

# Database configuration from environment or defaults
DB_CONFIG = {
    "host": os.environ.get("STACKSQ_DB_HOST", "localhost"),
    "port": int(os.environ.get("STACKSQ_DB_PORT", "3306")),
    "user": os.environ.get("STACKSQ_DB_USER", "root"),
    "password": os.environ.get("STACKSQ_DB_PASSWORD", ""),
    "database": os.environ.get("STACKSQ_DB_NAME", "stacksq_scanner"),
    "charset": "utf8mb4",
    "cursorclass": DictCursor if PYMYSQL_AVAILABLE else None,
    "autocommit": True,
}

# TTL in hours (should match cache_manager.py)
TTL_PYPI = 168  # 7 days
TTL_NPM = 168   # 7 days
TTL_DEPSDEV = 168  # 7 days
TTL_OSV = 24    # 24 hours


def get_db_connection():
    """Get a database connection."""
    if not PYMYSQL_AVAILABLE:
        return None
    
    try:
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None


def test_db_connection() -> Dict[str, Any]:
    """
    Test database connection and return status.
    
    Returns:
        Dict with connection status and details
    """
    result = {
        "connected": False,
        "pymysql_available": PYMYSQL_AVAILABLE,
        "host": DB_CONFIG["host"],
        "port": DB_CONFIG["port"],
        "database": DB_CONFIG["database"],
        "error": None
    }
    
    if not PYMYSQL_AVAILABLE:
        result["error"] = "pymysql not installed"
        return result
    
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1 as test")
                cursor.fetchone()
                result["connected"] = True
                
                # Get cache table counts
                for table in ["pypi_cache", "npm_cache", "depsdev_cache", "osv_cache"]:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
                        row = cursor.fetchone()
                        result[f"{table}_count"] = row["cnt"] if row else 0
                    except:
                        result[f"{table}_count"] = "table not found"
    except Exception as e:
        result["error"] = str(e)
    finally:
        if conn:
            conn.close()
    
    return result


# =============================================================================
# PyPI Cache Functions
# =============================================================================

def get_pypi_from_db(package: str, version: Optional[str] = None) -> Optional[Dict]:
    """
    Get PyPI package metadata from database cache.
    
    Args:
        package: Package name
        version: Optional version (None for any version)
        
    Returns:
        Cached metadata dict or None
    """
    if not PYMYSQL_AVAILABLE:
        return None
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        with conn.cursor() as cursor:
            if version:
                sql = """
                    SELECT package_name, version, license, supplier, description,
                           release_date, homepage, hashes, executable, archive, 
                           structured_properties, hit_count
                    FROM pypi_cache 
                    WHERE package_name = %s AND (version = %s OR version IS NULL)
                    AND expires_at > NOW()
                    ORDER BY version DESC
                    LIMIT 1
                """
                cursor.execute(sql, (package, version))
            else:
                sql = """
                    SELECT package_name, version, license, supplier, description,
                           release_date, homepage, hashes, executable, archive,
                           structured_properties, hit_count
                    FROM pypi_cache 
                    WHERE package_name = %s AND expires_at > NOW()
                    ORDER BY version DESC
                    LIMIT 1
                """
                cursor.execute(sql, (package,))
            
            row = cursor.fetchone()
            if row:
                # Update hit count
                cursor.execute(
                    "UPDATE pypi_cache SET hit_count = hit_count + 1 WHERE package_name = %s AND version = %s",
                    (package, row.get("version"))
                )
                
                # Parse hashes JSON if present
                hashes = row.get("hashes")
                if hashes and isinstance(hashes, str):
                    try:
                        hashes = json.loads(hashes)
                    except:
                        hashes = []
                
                return {
                    "name": row.get("package_name"),
                    "version": row.get("version"),
                    "license": row.get("license", "NOASSERTION"),
                    "supplier": row.get("supplier", "Unknown"),
                    "description": row.get("description", ""),
                    "release_date": row.get("release_date", ""),
                    "homepage": row.get("homepage", ""),
                    "hashes": hashes or [],
                    "executable": row.get("executable", ""),
                    "archive": row.get("archive", ""),
                    "structured_properties": row.get("structured_properties", ""),
                    "_from_db_cache": True
                }
    except Exception as e:
        logger.warning(f"DB cache lookup failed for pypi/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return None


def set_pypi_to_db(package: str, data: Dict, version: Optional[str] = None) -> bool:
    """
    Store PyPI package metadata in database cache.
    """
    if not PYMYSQL_AVAILABLE:
        return False
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        ver = version or data.get("version", "")
        expires_at = datetime.now() + timedelta(hours=TTL_PYPI)
        hashes_json = json.dumps(data.get("hashes", []))
        
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO pypi_cache 
                (package_name, version, license, supplier, description, release_date, 
                 homepage, hashes, executable, archive, structured_properties, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    license = VALUES(license),
                    supplier = VALUES(supplier),
                    description = VALUES(description),
                    release_date = VALUES(release_date),
                    homepage = VALUES(homepage),
                    hashes = VALUES(hashes),
                    executable = VALUES(executable),
                    archive = VALUES(archive),
                    structured_properties = VALUES(structured_properties),
                    expires_at = VALUES(expires_at),
                    updated_at = NOW()
            """
            cursor.execute(sql, (
                package,
                ver,
                data.get("license", "NOASSERTION"),
                data.get("supplier", "Unknown"),
                data.get("description", ""),
                data.get("release_date", ""),
                data.get("homepage", ""),
                hashes_json,
                data.get("executable", ""),
                data.get("archive", ""),
                data.get("structured_properties", ""),
                expires_at
            ))
            return True
    except Exception as e:
        logger.warning(f"DB cache write failed for pypi/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return False


# =============================================================================
# NPM Cache Functions
# =============================================================================

def get_npm_from_db(package: str, version: Optional[str] = None) -> Optional[Dict]:
    """Get NPM package metadata from database cache."""
    if not PYMYSQL_AVAILABLE:
        return None
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        with conn.cursor() as cursor:
            if version:
                sql = """
                    SELECT package_name, version, license, supplier, description,
                           release_date, homepage, hashes, executable, archive,
                           structured_properties, hit_count
                    FROM npm_cache 
                    WHERE package_name = %s AND (version = %s OR version IS NULL)
                    AND expires_at > NOW()
                    ORDER BY version DESC
                    LIMIT 1
                """
                cursor.execute(sql, (package, version))
            else:
                sql = """
                    SELECT package_name, version, license, supplier, description,
                           release_date, homepage, hashes, executable, archive,
                           structured_properties, hit_count
                    FROM npm_cache 
                    WHERE package_name = %s AND expires_at > NOW()
                    ORDER BY version DESC
                    LIMIT 1
                """
                cursor.execute(sql, (package,))
            
            row = cursor.fetchone()
            if row:
                # Update hit count
                cursor.execute(
                    "UPDATE npm_cache SET hit_count = hit_count + 1 WHERE package_name = %s AND version = %s",
                    (package, row.get("version"))
                )
                
                hashes = row.get("hashes")
                if hashes and isinstance(hashes, str):
                    try:
                        hashes = json.loads(hashes)
                    except:
                        hashes = []
                
                return {
                    "name": row.get("package_name"),
                    "version": row.get("version"),
                    "license": row.get("license", "NOASSERTION"),
                    "supplier": row.get("supplier", "Unknown"),
                    "description": row.get("description", ""),
                    "release_date": row.get("release_date", ""),
                    "homepage": row.get("homepage", ""),
                    "hashes": hashes or [],
                    "executable": row.get("executable", ""),
                    "archive": row.get("archive", ""),
                    "structured_properties": row.get("structured_properties", ""),
                    "_from_db_cache": True
                }
    except Exception as e:
        logger.warning(f"DB cache lookup failed for npm/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return None


def set_npm_to_db(package: str, data: Dict, version: Optional[str] = None) -> bool:
    """Store NPM package metadata in database cache."""
    if not PYMYSQL_AVAILABLE:
        return False
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        ver = version or data.get("version", "")
        expires_at = datetime.now() + timedelta(hours=TTL_NPM)
        hashes_json = json.dumps(data.get("hashes", []))
        
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO npm_cache 
                (package_name, version, license, supplier, description, release_date, 
                 homepage, hashes, executable, archive, structured_properties, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    license = VALUES(license),
                    supplier = VALUES(supplier),
                    description = VALUES(description),
                    release_date = VALUES(release_date),
                    homepage = VALUES(homepage),
                    hashes = VALUES(hashes),
                    executable = VALUES(executable),
                    archive = VALUES(archive),
                    structured_properties = VALUES(structured_properties),
                    expires_at = VALUES(expires_at),
                    updated_at = NOW()
            """
            cursor.execute(sql, (
                package,
                ver,
                data.get("license", "NOASSERTION"),
                data.get("supplier", "Unknown"),
                data.get("description", ""),
                data.get("release_date", ""),
                data.get("homepage", ""),
                hashes_json,
                data.get("executable", ""),
                data.get("archive", ""),
                data.get("structured_properties", ""),
                expires_at
            ))
            return True
    except Exception as e:
        logger.warning(f"DB cache write failed for npm/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return False


# =============================================================================
# deps.dev Cache Functions
# =============================================================================

def get_depsdev_from_db(ecosystem: str, package: str, version: str) -> Optional[Dict]:
    """Get deps.dev metadata from database cache."""
    if not PYMYSQL_AVAILABLE:
        return None
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        with conn.cursor() as cursor:
            sql = """
                SELECT ecosystem, package_name, version, license, homepage, description,
                       raw_response, hit_count
                FROM depsdev_cache 
                WHERE ecosystem = %s AND package_name = %s AND version = %s
                AND expires_at > NOW()
                LIMIT 1
            """
            cursor.execute(sql, (ecosystem, package, version))
            
            row = cursor.fetchone()
            if row:
                # Update hit count
                cursor.execute(
                    "UPDATE depsdev_cache SET hit_count = hit_count + 1 WHERE ecosystem = %s AND package_name = %s AND version = %s",
                    (ecosystem, package, version)
                )
                
                return {
                    "name": row.get("package_name"),
                    "version": row.get("version"),
                    "license": row.get("license", "NOASSERTION"),
                    "homepage": row.get("homepage", ""),
                    "description": row.get("description", ""),
                    "_from_db_cache": True
                }
    except Exception as e:
        logger.warning(f"DB cache lookup failed for depsdev/{ecosystem}/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return None


def set_depsdev_to_db(ecosystem: str, package: str, version: str, data: Dict) -> bool:
    """Store deps.dev metadata in database cache."""
    if not PYMYSQL_AVAILABLE:
        return False
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        expires_at = datetime.now() + timedelta(hours=TTL_DEPSDEV)
        raw_json = json.dumps(data) if data else None
        
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO depsdev_cache 
                (ecosystem, package_name, version, license, homepage, description, raw_response, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    license = VALUES(license),
                    homepage = VALUES(homepage),
                    description = VALUES(description),
                    raw_response = VALUES(raw_response),
                    expires_at = VALUES(expires_at),
                    updated_at = NOW()
            """
            cursor.execute(sql, (
                ecosystem,
                package,
                version,
                data.get("license", "NOASSERTION"),
                data.get("homepage", ""),
                data.get("description", ""),
                raw_json,
                expires_at
            ))
            return True
    except Exception as e:
        logger.warning(f"DB cache write failed for depsdev/{ecosystem}/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return False


# =============================================================================
# OSV Cache Functions
# =============================================================================

def get_osv_from_db(ecosystem: str, package: str, version: Optional[str] = None) -> Optional[List[Dict]]:
    """Get OSV vulnerability data from database cache."""
    if not PYMYSQL_AVAILABLE:
        return None
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        with conn.cursor() as cursor:
            if version:
                sql = """
                    SELECT vulnerabilities, vuln_count
                    FROM osv_cache 
                    WHERE ecosystem = %s AND package_name = %s AND version = %s
                    AND expires_at > NOW()
                    LIMIT 1
                """
                cursor.execute(sql, (ecosystem, package, version))
            else:
                sql = """
                    SELECT vulnerabilities, vuln_count
                    FROM osv_cache 
                    WHERE ecosystem = %s AND package_name = %s
                    AND expires_at > NOW()
                    ORDER BY version DESC
                    LIMIT 1
                """
                cursor.execute(sql, (ecosystem, package))
            
            row = cursor.fetchone()
            if row:
                vulns = row.get("vulnerabilities")
                if vulns and isinstance(vulns, str):
                    try:
                        vulns = json.loads(vulns)
                    except:
                        vulns = []
                return vulns if vulns else []
    except Exception as e:
        logger.warning(f"DB cache lookup failed for osv/{ecosystem}/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return None


def set_osv_to_db(ecosystem: str, package: str, vulns: List[Dict], version: Optional[str] = None) -> bool:
    """Store OSV vulnerability data in database cache."""
    if not PYMYSQL_AVAILABLE:
        return False
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        expires_at = datetime.now() + timedelta(hours=TTL_OSV)
        vulns_json = json.dumps(vulns) if vulns else "[]"
        
        # Count by severity
        vuln_count = len(vulns) if vulns else 0
        critical = sum(1 for v in (vulns or []) if v.get("severity", "").upper() == "CRITICAL")
        high = sum(1 for v in (vulns or []) if v.get("severity", "").upper() == "HIGH")
        medium = sum(1 for v in (vulns or []) if v.get("severity", "").upper() == "MEDIUM")
        low = sum(1 for v in (vulns or []) if v.get("severity", "").upper() == "LOW")
        
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO osv_cache 
                (ecosystem, package_name, version, vulnerabilities, vuln_count, 
                 critical_count, high_count, medium_count, low_count, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    vulnerabilities = VALUES(vulnerabilities),
                    vuln_count = VALUES(vuln_count),
                    critical_count = VALUES(critical_count),
                    high_count = VALUES(high_count),
                    medium_count = VALUES(medium_count),
                    low_count = VALUES(low_count),
                    expires_at = VALUES(expires_at),
                    updated_at = NOW()
            """
            cursor.execute(sql, (
                ecosystem,
                package,
                version or "",
                vulns_json,
                vuln_count,
                critical,
                high,
                medium,
                low,
                expires_at
            ))
            return True
    except Exception as e:
        logger.warning(f"DB cache write failed for osv/{ecosystem}/{package}: {e}")
    finally:
        if conn:
            conn.close()
    
    return False


# =============================================================================
# Database Cache Statistics
# =============================================================================

def get_db_cache_stats() -> Dict[str, Any]:
    """Get database cache statistics."""
    stats = {
        "db_available": PYMYSQL_AVAILABLE,
        "connected": False,
        "tables": {}
    }
    
    if not PYMYSQL_AVAILABLE:
        return stats
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return stats
        
        stats["connected"] = True
        
        with conn.cursor() as cursor:
            for table in ["pypi_cache", "npm_cache", "depsdev_cache", "osv_cache"]:
                try:
                    cursor.execute(f"SELECT COUNT(*) as total, SUM(hit_count) as hits FROM {table}")
                    row = cursor.fetchone()
                    cursor.execute(f"SELECT COUNT(*) as valid FROM {table} WHERE expires_at > NOW()")
                    valid_row = cursor.fetchone()
                    
                    stats["tables"][table] = {
                        "total_entries": row.get("total", 0) if row else 0,
                        "total_hits": row.get("hits", 0) if row else 0,
                        "valid_entries": valid_row.get("valid", 0) if valid_row else 0
                    }
                except Exception as e:
                    stats["tables"][table] = {"error": str(e)}
    except Exception as e:
        stats["error"] = str(e)
    finally:
        if conn:
            conn.close()
    
    return stats
