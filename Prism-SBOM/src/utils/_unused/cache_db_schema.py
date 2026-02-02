"""
Database Schema for Cache Storage

This module defines the database schema to replace file-based caching.
Supports SQLite (development) and PostgreSQL (production).

Tables:
1. depsdev_cache - deps.dev API responses
2. pypi_cache - PyPI registry metadata
3. npm_cache - npm registry metadata  
4. osv_cache - OSV vulnerability data
5. cache_stats - Cache hit/miss statistics

Usage:
    from src.utils.cache_db_schema import CacheDB
    
    db = CacheDB("sqlite:///cache.db")  # or PostgreSQL connection string
    db.create_tables()
    
    # Store deps.dev data
    db.set_depsdev("pypi", "flask", "2.0.1", {...})
    
    # Retrieve cached data
    data = db.get_depsdev("pypi", "flask", "2.0.1")
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import hashlib

# SQLAlchemy imports (install: pip install sqlalchemy)
try:
    from sqlalchemy import (
        create_engine, Column, String, Text, Integer, Float, Boolean,
        DateTime, JSON, Index, UniqueConstraint
    )
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    print("[WARN] SQLAlchemy not installed. Run: pip install sqlalchemy")


# =============================================================================
# DATABASE SCHEMA DEFINITIONS
# =============================================================================

if SQLALCHEMY_AVAILABLE:
    Base = declarative_base()
    
    class DepsDevCache(Base):
        """
        Cache for deps.dev API responses.
        
        Fields retrieved from deps.dev:
        - license: Package license (MIT, Apache-2.0, etc.)
        - homepage: Project homepage URL
        - description: Package description (optional)
        
        TTL: 7 days
        """
        __tablename__ = 'depsdev_cache'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        
        # Composite key fields
        ecosystem = Column(String(50), nullable=False, index=True)  # pypi, npm, go, maven
        package_name = Column(String(255), nullable=False, index=True)
        version = Column(String(100), nullable=False, index=True)
        
        # Cached data fields
        license = Column(String(255), default='NOASSERTION')
        homepage = Column(Text, default='')
        description = Column(Text, default='')
        
        # Metadata
        created_at = Column(DateTime, default=datetime.utcnow)
        expires_at = Column(DateTime, nullable=False)
        hit_count = Column(Integer, default=0)
        
        # Raw JSON response (for debugging/future fields)
        raw_response = Column(JSON, nullable=True)
        
        __table_args__ = (
            UniqueConstraint('ecosystem', 'package_name', 'version', name='uq_depsdev_pkg'),
            Index('ix_depsdev_lookup', 'ecosystem', 'package_name', 'version'),
            Index('ix_depsdev_expires', 'expires_at'),
        )
    
    
    class PyPICache(Base):
        """
        Cache for PyPI registry API responses.
        
        Fields retrieved from PyPI:
        - name: Package name (normalized)
        - version: Package version
        - license: Package license
        - supplier: Author/maintainer name
        - description: Package summary
        - release_date: When this version was released
        - homepage: Project URL
        - hashes: SHA-256 checksums (stored as JSON array)
        - executable: Whether package has CLI scripts
        - archive: Distribution format (wheel, tar.gz, etc.)
        
        TTL: 7 days
        """
        __tablename__ = 'pypi_cache'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        
        # Key fields
        package_name = Column(String(255), nullable=False, index=True)
        version = Column(String(100), nullable=True, index=True)  # Nullable for "latest"
        
        # Cached data fields (all fields we retrieve)
        license = Column(String(255), default='NOASSERTION')
        supplier = Column(String(255), default='Unknown')
        description = Column(Text, default='')
        release_date = Column(String(50), default='')  # ISO format
        homepage = Column(Text, default='')
        
        # Complex fields stored as JSON
        hashes = Column(JSON, default=list)  # [{"alg": "SHA-256", "content": "abc123..."}]
        
        # SBOM-specific fields
        executable = Column(String(255), default='')  # "Yes - Console scripts" or "No - Library"
        archive = Column(String(255), default='')  # "wheel (.whl) / source tarball (.tar.gz)"
        structured_properties = Column(String(255), default='')  # "PEP 517/518 compliant"
        
        # Metadata
        created_at = Column(DateTime, default=datetime.utcnow)
        expires_at = Column(DateTime, nullable=False)
        hit_count = Column(Integer, default=0)
        
        __table_args__ = (
            UniqueConstraint('package_name', 'version', name='uq_pypi_pkg'),
            Index('ix_pypi_lookup', 'package_name', 'version'),
            Index('ix_pypi_expires', 'expires_at'),
        )
    
    
    class NPMCache(Base):
        """
        Cache for npm registry API responses.
        
        Fields retrieved from npm:
        - name: Package name
        - version: Package version
        - license: Package license
        - supplier: Author name
        - description: Package description
        - release_date: Publication date
        - homepage: Homepage URL
        - hashes: SHA-1 or SHA-512 integrity hashes
        - executable: CLI bin commands
        - archive: Package format (tarball)
        
        TTL: 7 days
        """
        __tablename__ = 'npm_cache'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        
        # Key fields
        package_name = Column(String(255), nullable=False, index=True)
        version = Column(String(100), nullable=True, index=True)
        
        # Cached data fields
        license = Column(String(255), default='NOASSERTION')
        supplier = Column(String(255), default='Unknown')
        description = Column(Text, default='')
        release_date = Column(String(50), default='')
        homepage = Column(Text, default='')
        
        # Complex fields
        hashes = Column(JSON, default=list)  # [{"alg": "SHA-512", "content": "..."}]
        
        # SBOM-specific fields
        executable = Column(String(500), default='')  # "Yes - CLI commands: cmd1, cmd2"
        archive = Column(String(255), default='npm tarball (.tgz)')
        structured_properties = Column(String(255), default='CommonJS/ESM module')
        
        # Metadata
        created_at = Column(DateTime, default=datetime.utcnow)
        expires_at = Column(DateTime, nullable=False)
        hit_count = Column(Integer, default=0)
        
        __table_args__ = (
            UniqueConstraint('package_name', 'version', name='uq_npm_pkg'),
            Index('ix_npm_lookup', 'package_name', 'version'),
            Index('ix_npm_expires', 'expires_at'),
        )
    
    
    class OSVCache(Base):
        """
        Cache for OSV vulnerability API responses.
        
        Fields stored:
        - Vulnerability ID (GHSA-xxx, CVE-xxx, PYSEC-xxx)
        - Severity (CVSS string)
        - Severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
        - Summary
        - Fixed version
        - URL
        - Aliases (CVE, GHSA, PYSEC mappings)
        - Full details
        
        TTL: 24 hours (vulnerabilities change more frequently)
        """
        __tablename__ = 'osv_cache'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        
        # Key fields
        ecosystem = Column(String(50), nullable=False, index=True)
        package_name = Column(String(255), nullable=False, index=True)
        version = Column(String(100), nullable=True, index=True)
        
        # Vulnerability data stored as JSON array
        # Each element: {"id": "GHSA-xxx", "severity": "...", "summary": "...", ...}
        vulnerabilities = Column(JSON, default=list)
        
        # Summary counts for quick access
        vuln_count = Column(Integer, default=0)
        critical_count = Column(Integer, default=0)
        high_count = Column(Integer, default=0)
        medium_count = Column(Integer, default=0)
        low_count = Column(Integer, default=0)
        
        # Metadata
        created_at = Column(DateTime, default=datetime.utcnow)
        expires_at = Column(DateTime, nullable=False)
        hit_count = Column(Integer, default=0)
        
        __table_args__ = (
            UniqueConstraint('ecosystem', 'package_name', 'version', name='uq_osv_pkg'),
            Index('ix_osv_lookup', 'ecosystem', 'package_name', 'version'),
            Index('ix_osv_expires', 'expires_at'),
            Index('ix_osv_vuln_count', 'vuln_count'),
        )
    
    
    class CacheStats(Base):
        """
        Track cache performance statistics.
        """
        __tablename__ = 'cache_stats'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        cache_type = Column(String(50), nullable=False, index=True)  # depsdev, pypi, npm, osv
        date = Column(DateTime, default=datetime.utcnow)
        
        # Counts
        hits = Column(Integer, default=0)
        misses = Column(Integer, default=0)
        inserts = Column(Integer, default=0)
        expirations = Column(Integer, default=0)
        
        __table_args__ = (
            Index('ix_stats_type_date', 'cache_type', 'date'),
        )


# =============================================================================
# DATABASE OPERATIONS CLASS
# =============================================================================

class CacheDB:
    """
    Database-backed cache manager.
    
    Replaces file-based cache with SQLite or PostgreSQL.
    """
    
    # TTL values in hours
    TTL_DEPSDEV = 168  # 7 days
    TTL_PYPI = 168     # 7 days
    TTL_NPM = 168      # 7 days
    TTL_OSV = 24       # 24 hours
    
    def __init__(self, connection_string: str = "sqlite:///cache/cache.db"):
        """
        Initialize database connection.
        
        Args:
            connection_string: SQLAlchemy connection string
                - SQLite: "sqlite:///cache/cache.db"
                - PostgreSQL: "postgresql://user:pass@host:5432/dbname"
        """
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError("SQLAlchemy required. Install: pip install sqlalchemy")
        
        self.engine = create_engine(connection_string, echo=False)
        self.Session = sessionmaker(bind=self.engine)
    
    def create_tables(self):
        """Create all cache tables."""
        Base.metadata.create_all(self.engine)
    
    def drop_tables(self):
        """Drop all cache tables (use with caution!)."""
        Base.metadata.drop_all(self.engine)
    
    # -------------------------------------------------------------------------
    # deps.dev Cache Operations
    # -------------------------------------------------------------------------
    
    def get_depsdev(self, ecosystem: str, package: str, version: str) -> Optional[Dict]:
        """Get cached deps.dev data."""
        session = self.Session()
        try:
            record = session.query(DepsDevCache).filter_by(
                ecosystem=ecosystem,
                package_name=package,
                version=version
            ).filter(DepsDevCache.expires_at > datetime.utcnow()).first()
            
            if record:
                record.hit_count += 1
                session.commit()
                return {
                    "name": package,
                    "version": version,
                    "license": record.license,
                    "homepage": record.homepage,
                    "description": record.description
                }
            return None
        finally:
            session.close()
    
    def set_depsdev(self, ecosystem: str, package: str, version: str, data: Dict) -> bool:
        """Cache deps.dev data."""
        session = self.Session()
        try:
            expires = datetime.utcnow() + timedelta(hours=self.TTL_DEPSDEV)
            
            # Upsert
            record = session.query(DepsDevCache).filter_by(
                ecosystem=ecosystem,
                package_name=package,
                version=version
            ).first()
            
            if record:
                record.license = data.get("license", "NOASSERTION")
                record.homepage = data.get("homepage", "")
                record.description = data.get("description", "")
                record.expires_at = expires
                record.raw_response = data
            else:
                record = DepsDevCache(
                    ecosystem=ecosystem,
                    package_name=package,
                    version=version,
                    license=data.get("license", "NOASSERTION"),
                    homepage=data.get("homepage", ""),
                    description=data.get("description", ""),
                    expires_at=expires,
                    raw_response=data
                )
                session.add(record)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] set_depsdev: {e}")
            return False
        finally:
            session.close()
    
    # -------------------------------------------------------------------------
    # PyPI Cache Operations
    # -------------------------------------------------------------------------
    
    def get_pypi(self, package: str, version: Optional[str] = None) -> Optional[Dict]:
        """Get cached PyPI data."""
        session = self.Session()
        try:
            query = session.query(PyPICache).filter_by(package_name=package)
            if version:
                query = query.filter_by(version=version)
            
            record = query.filter(PyPICache.expires_at > datetime.utcnow()).first()
            
            if record:
                record.hit_count += 1
                session.commit()
                return {
                    "name": record.package_name,
                    "version": record.version or "",
                    "license": record.license,
                    "supplier": record.supplier,
                    "description": record.description,
                    "release_date": record.release_date,
                    "homepage": record.homepage,
                    "hashes": record.hashes or [],
                    "executable": record.executable,
                    "archive": record.archive,
                    "structured_properties": record.structured_properties
                }
            return None
        finally:
            session.close()
    
    def set_pypi(self, package: str, data: Dict, version: Optional[str] = None) -> bool:
        """Cache PyPI data."""
        session = self.Session()
        try:
            expires = datetime.utcnow() + timedelta(hours=self.TTL_PYPI)
            
            record = session.query(PyPICache).filter_by(
                package_name=package,
                version=version
            ).first()
            
            if record:
                record.license = data.get("license", "NOASSERTION")
                record.supplier = data.get("supplier", "Unknown")
                record.description = data.get("description", "")
                record.release_date = data.get("release_date", "")
                record.homepage = data.get("homepage", "")
                record.hashes = data.get("hashes", [])
                record.executable = data.get("executable", "")
                record.archive = data.get("archive", "")
                record.structured_properties = data.get("structured_properties", "")
                record.expires_at = expires
            else:
                record = PyPICache(
                    package_name=package,
                    version=version,
                    license=data.get("license", "NOASSERTION"),
                    supplier=data.get("supplier", "Unknown"),
                    description=data.get("description", ""),
                    release_date=data.get("release_date", ""),
                    homepage=data.get("homepage", ""),
                    hashes=data.get("hashes", []),
                    executable=data.get("executable", ""),
                    archive=data.get("archive", ""),
                    structured_properties=data.get("structured_properties", ""),
                    expires_at=expires
                )
                session.add(record)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] set_pypi: {e}")
            return False
        finally:
            session.close()
    
    # -------------------------------------------------------------------------
    # npm Cache Operations
    # -------------------------------------------------------------------------
    
    def get_npm(self, package: str, version: Optional[str] = None) -> Optional[Dict]:
        """Get cached npm data."""
        session = self.Session()
        try:
            query = session.query(NPMCache).filter_by(package_name=package)
            if version:
                query = query.filter_by(version=version)
            
            record = query.filter(NPMCache.expires_at > datetime.utcnow()).first()
            
            if record:
                record.hit_count += 1
                session.commit()
                return {
                    "name": record.package_name,
                    "version": record.version or "",
                    "license": record.license,
                    "supplier": record.supplier,
                    "description": record.description,
                    "release_date": record.release_date,
                    "homepage": record.homepage,
                    "hashes": record.hashes or [],
                    "executable": record.executable,
                    "archive": record.archive,
                    "structured_properties": record.structured_properties
                }
            return None
        finally:
            session.close()
    
    def set_npm(self, package: str, data: Dict, version: Optional[str] = None) -> bool:
        """Cache npm data."""
        session = self.Session()
        try:
            expires = datetime.utcnow() + timedelta(hours=self.TTL_NPM)
            
            record = session.query(NPMCache).filter_by(
                package_name=package,
                version=version
            ).first()
            
            if record:
                record.license = data.get("license", "NOASSERTION")
                record.supplier = data.get("supplier", "Unknown")
                record.description = data.get("description", "")
                record.release_date = data.get("release_date", "")
                record.homepage = data.get("homepage", "")
                record.hashes = data.get("hashes", [])
                record.executable = data.get("executable", "")
                record.archive = data.get("archive", "npm tarball (.tgz)")
                record.structured_properties = data.get("structured_properties", "CommonJS/ESM module")
                record.expires_at = expires
            else:
                record = NPMCache(
                    package_name=package,
                    version=version,
                    license=data.get("license", "NOASSERTION"),
                    supplier=data.get("supplier", "Unknown"),
                    description=data.get("description", ""),
                    release_date=data.get("release_date", ""),
                    homepage=data.get("homepage", ""),
                    hashes=data.get("hashes", []),
                    executable=data.get("executable", ""),
                    archive=data.get("archive", "npm tarball (.tgz)"),
                    structured_properties=data.get("structured_properties", "CommonJS/ESM module"),
                    expires_at=expires
                )
                session.add(record)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] set_npm: {e}")
            return False
        finally:
            session.close()
    
    # -------------------------------------------------------------------------
    # OSV Cache Operations
    # -------------------------------------------------------------------------
    
    def get_osv(self, ecosystem: str, package: str, version: Optional[str] = None) -> Optional[List[Dict]]:
        """Get cached OSV vulnerabilities."""
        session = self.Session()
        try:
            query = session.query(OSVCache).filter_by(
                ecosystem=ecosystem,
                package_name=package
            )
            if version:
                query = query.filter_by(version=version)
            
            record = query.filter(OSVCache.expires_at > datetime.utcnow()).first()
            
            if record:
                record.hit_count += 1
                session.commit()
                return record.vulnerabilities or []
            return None
        finally:
            session.close()
    
    def set_osv(self, ecosystem: str, package: str, vulns: List[Dict], version: Optional[str] = None) -> bool:
        """Cache OSV vulnerabilities."""
        session = self.Session()
        try:
            expires = datetime.utcnow() + timedelta(hours=self.TTL_OSV)
            
            # Count severity levels
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for v in vulns:
                severity = v.get("severity_level", "UNKNOWN")
                if severity in counts:
                    counts[severity] += 1
            
            record = session.query(OSVCache).filter_by(
                ecosystem=ecosystem,
                package_name=package,
                version=version
            ).first()
            
            if record:
                record.vulnerabilities = vulns
                record.vuln_count = len(vulns)
                record.critical_count = counts["CRITICAL"]
                record.high_count = counts["HIGH"]
                record.medium_count = counts["MEDIUM"]
                record.low_count = counts["LOW"]
                record.expires_at = expires
            else:
                record = OSVCache(
                    ecosystem=ecosystem,
                    package_name=package,
                    version=version,
                    vulnerabilities=vulns,
                    vuln_count=len(vulns),
                    critical_count=counts["CRITICAL"],
                    high_count=counts["HIGH"],
                    medium_count=counts["MEDIUM"],
                    low_count=counts["LOW"],
                    expires_at=expires
                )
                session.add(record)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] set_osv: {e}")
            return False
        finally:
            session.close()
    
    # -------------------------------------------------------------------------
    # Maintenance Operations
    # -------------------------------------------------------------------------
    
    def cleanup_expired(self) -> Dict[str, int]:
        """Remove all expired cache entries."""
        session = self.Session()
        results = {}
        now = datetime.utcnow()
        
        try:
            for model, name in [
                (DepsDevCache, "depsdev"),
                (PyPICache, "pypi"),
                (NPMCache, "npm"),
                (OSVCache, "osv")
            ]:
                count = session.query(model).filter(model.expires_at < now).delete()
                results[name] = count
            
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] cleanup_expired: {e}")
        finally:
            session.close()
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        session = self.Session()
        try:
            stats = {}
            for model, name in [
                (DepsDevCache, "depsdev"),
                (PyPICache, "pypi"),
                (NPMCache, "npm"),
                (OSVCache, "osv")
            ]:
                total = session.query(model).count()
                active = session.query(model).filter(model.expires_at > datetime.utcnow()).count()
                total_hits = session.query(model).with_entities(
                    # Sum of hit_count
                ).count()  # Simplified
                
                stats[name] = {
                    "total_entries": total,
                    "active_entries": active,
                    "expired_entries": total - active
                }
            
            return stats
        finally:
            session.close()


# =============================================================================
# MIGRATION HELPER - Import existing file cache to DB
# =============================================================================

def migrate_file_cache_to_db(cache_dir: str, db: CacheDB) -> Dict[str, int]:
    """
    Migrate existing file-based cache to database.
    
    Args:
        cache_dir: Path to existing cache directory
        db: CacheDB instance
    
    Returns:
        Dict with counts of migrated entries per cache type
    """
    import os
    from pathlib import Path
    
    cache_path = Path(cache_dir)
    results = {"depsdev": 0, "pypi": 0, "npm": 0, "osv": 0}
    
    for cache_type in ["depsdev", "pypi", "npm", "osv"]:
        type_path = cache_path / cache_type
        if not type_path.exists():
            continue
        
        for cache_file in type_path.glob("*.json"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Parse filename to get key
                # Format: ecosystem_package_version.json or package_version.json
                filename = cache_file.stem
                parts = filename.split("_")
                
                if cache_type == "depsdev":
                    if len(parts) >= 3:
                        ecosystem = parts[0]
                        version = parts[-1]
                        package = "_".join(parts[1:-1])
                        if db.set_depsdev(ecosystem, package, version, data):
                            results["depsdev"] += 1
                
                elif cache_type == "pypi":
                    if len(parts) >= 1:
                        version = parts[-1] if len(parts) > 1 else None
                        package = "_".join(parts[:-1]) if version else parts[0]
                        if db.set_pypi(package, data, version):
                            results["pypi"] += 1
                
                elif cache_type == "npm":
                    if len(parts) >= 1:
                        version = parts[-1] if len(parts) > 1 else None
                        package = "_".join(parts[:-1]) if version else parts[0]
                        if db.set_npm(package, data, version):
                            results["npm"] += 1
                
                elif cache_type == "osv":
                    if len(parts) >= 2:
                        ecosystem = parts[0]
                        version = parts[-1] if len(parts) > 2 else None
                        package = "_".join(parts[1:-1]) if version else "_".join(parts[1:])
                        if db.set_osv(ecosystem, package, data, version):
                            results["osv"] += 1
            
            except Exception as e:
                print(f"[MIGRATE] Error migrating {cache_file}: {e}")
    
    return results


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Example: Create SQLite database
    db = CacheDB("sqlite:///cache/cache.db")
    db.create_tables()
    
    # Example: Store PyPI data
    db.set_pypi("flask", {
        "name": "flask",
        "version": "2.0.1",
        "license": "BSD-3-Clause",
        "supplier": "Pallets",
        "description": "A lightweight WSGI web application framework",
        "release_date": "2021-05-21T00:00:00Z",
        "homepage": "https://palletsprojects.com/p/flask",
        "hashes": [{"alg": "SHA-256", "content": "abc123..."}],
        "executable": "Yes - Console scripts: flask",
        "archive": "wheel (.whl) / source tarball (.tar.gz)",
        "structured_properties": "PEP 517/518 compliant"
    }, version="2.0.1")
    
    # Example: Retrieve
    cached = db.get_pypi("flask", "2.0.1")
    print(f"Cached data: {cached}")
    
    # Example: Get stats
    stats = db.get_stats()
    print(f"Cache stats: {stats}")
