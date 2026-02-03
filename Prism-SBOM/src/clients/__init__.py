"""
Clients module for external API interactions

Clients for fetching package metadata from various sources:
- depsdev_client: Google's deps.dev API (license, dependencies, published date)
- pypi_client: Python Package Index (description, supplier, hashes)
- npm_client: npm Registry (description, supplier, hashes)
- osv_client: OSV.dev (vulnerability data)
- eol_client: endoflife.date (runtime EOL status)
"""

from src.clients import depsdev_client
from src.clients import pypi_client
from src.clients import npm_client
from src.clients import osv_client
from src.clients import eol_client

__all__ = ['depsdev_client', 'pypi_client', 'npm_client', 'osv_client', 'eol_client']
