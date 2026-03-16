"""
Conan / vcpkg Client for C/C++ package metadata enrichment.

Provides functions to:
- Fetch package metadata from Conan Center Index (GitHub-based)
- Fetch package metadata from vcpkg registry
- Extract description, author, license information

Note: deps.dev does NOT support C/C++ ecosystems.
All enrichment must come from Conan Center / vcpkg registries.

Conan Center Index: https://github.com/conan-io/conan-center-index
vcpkg packages: https://vcpkg.io/en/packages
"""

from __future__ import annotations

import logging
import requests
from typing import Optional, Dict, Any

from sbom.src.config.config import API_TIMEOUT

logger = logging.getLogger(__name__)

# Conan Center uses a GitHub-based index; the search API is v2
CONAN_SEARCH_URL = "https://center.conan.io/v2/conans/search"
# Conan Center web metadata (recipe info)
CONAN_RECIPE_URL = "https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes"

# vcpkg port metadata from the vcpkg registry
VCPKG_PORTS_URL = "https://raw.githubusercontent.com/microsoft/vcpkg/master/ports"


def fetch_conan_meta(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch metadata for a Conan / vcpkg package.

    Strategy:
    1. Try Conan Center Index first (GitHub raw files for recipe config.yml / conandata.yml)
    2. Fallback to vcpkg port metadata (CONTROL or vcpkg.json)

    Args:
        name: Package name (e.g., "zlib", "openssl", "boost")
        version: Optional specific version

    Returns:
        Dict with 'description', 'author', 'license', 'homepage' or None
    """
    if not name:
        return None

    meta = _try_conan_center(name, version)
    if meta:
        return meta

    meta = _try_vcpkg(name, version)
    if meta:
        return meta

    return None


def _try_conan_center(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Try to fetch metadata from Conan Center Index on GitHub.

    Reads the recipe's conanfile.py header or config.yml to extract
    description, author, homepage, and license.
    """
    try:
        # Try to fetch the conanfile.py for the recipe
        url = f"{CONAN_RECIPE_URL}/{name}/all/conanfile.py"
        resp = requests.get(url, timeout=API_TIMEOUT)

        if resp.status_code == 200:
            text = resp.text
            result: Dict[str, Any] = {"source": "conan"}

            # Extract description from conanfile.py
            import re
            desc_match = re.search(r'description\s*=\s*["\'](.+?)["\']', text)
            if desc_match:
                result["description"] = desc_match.group(1)

            # Extract homepage
            hp_match = re.search(r'homepage\s*=\s*["\'](.+?)["\']', text)
            if hp_match:
                result["homepage"] = hp_match.group(1)

            # Extract license
            lic_match = re.search(r'license\s*=\s*["\'](.+?)["\']', text)
            if lic_match:
                result["license"] = lic_match.group(1)

            # Extract author / topics
            author_match = re.search(r'author\s*=\s*["\'](.+?)["\']', text)
            if author_match:
                result["author"] = author_match.group(1)

            if result.get("description") or result.get("license"):
                return result

        # Fallback: try config.yml for basic info
        config_url = f"{CONAN_RECIPE_URL}/{name}/config.yml"
        config_resp = requests.get(config_url, timeout=API_TIMEOUT)
        if config_resp.status_code == 200:
            return {"source": "conan", "description": f"Conan package: {name}"}

    except requests.exceptions.Timeout:
        logger.debug(f"Conan Center timeout for {name}")
    except Exception as e:
        logger.debug(f"Conan Center fetch failed for {name}: {e}")

    return None


def _try_vcpkg(name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Try to fetch metadata from the vcpkg registry on GitHub.

    Reads the port's vcpkg.json manifest for description, homepage, license.
    """
    try:
        # vcpkg ports use vcpkg.json (newer format)
        url = f"{VCPKG_PORTS_URL}/{name}/vcpkg.json"
        resp = requests.get(url, timeout=API_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            result: Dict[str, Any] = {"source": "vcpkg"}

            result["description"] = data.get("description", "")
            if isinstance(result["description"], list):
                result["description"] = " ".join(result["description"])

            result["homepage"] = data.get("homepage", "")
            result["license"] = data.get("license", "")

            # vcpkg doesn't always have author info, use homepage as hint
            result["owner"] = data.get("maintainers", "Unknown")
            if isinstance(result["owner"], list):
                result["owner"] = ", ".join(result["owner"])

            return result

        # Fallback: try CONTROL file (older vcpkg format)
        control_url = f"{VCPKG_PORTS_URL}/{name}/CONTROL"
        control_resp = requests.get(control_url, timeout=API_TIMEOUT)
        if control_resp.status_code == 200:
            text = control_resp.text
            result = {"source": "vcpkg"}
            for line in text.splitlines():
                if line.startswith("Description:"):
                    result["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("Homepage:"):
                    result["homepage"] = line.split(":", 1)[1].strip()
                elif line.startswith("Maintainer:"):
                    result["owner"] = line.split(":", 1)[1].strip()
            if result.get("description"):
                return result

    except requests.exceptions.Timeout:
        logger.debug(f"vcpkg timeout for {name}")
    except Exception as e:
        logger.debug(f"vcpkg fetch failed for {name}: {e}")

    return None
