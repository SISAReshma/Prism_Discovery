"""
Anaconda API Client

Fetches package metadata from Anaconda.org API.
Supports multiple channels (conda-forge, anaconda, bioconda, etc.)
"""

import requests
import logging
from typing import Dict, Optional, List
from functools import lru_cache
from src.utils.rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class AnacondaClient:
    """
    Client for Anaconda.org API.
    
    Fetches package metadata from various conda channels.
    """
    
    def __init__(self):
        self.base_url = "https://api.anaconda.org"
        self.rate_limiter = get_rate_limiter()
        
        # Common channels in priority order
        self.channels = [
            'conda-forge',  # Largest community channel
            'anaconda',     # Official Anaconda channel
            'bioconda',     # Bioinformatics
            'pytorch',      # PyTorch packages
            'nvidia',       # NVIDIA packages
        ]
        
        # Session for connection pooling
        from src.config.config import TOOL_NAME, TOOL_VERSION
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'{TOOL_NAME}/{TOOL_VERSION}'
        })
    
    @lru_cache(maxsize=2048)
    def get_package_info(
        self,
        package_name: str,
        channel: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Get package metadata from Anaconda API.
        
        Args:
            package_name: Name of the conda package
            channel: Specific channel (or None to try all)
            
        Returns:
            dict: Package metadata or None if not found
        """
        # If channel specified, try only that one
        if channel:
            return self._fetch_from_channel(package_name, channel)
        
        # Otherwise try channels in order
        for ch in self.channels:
            result = self._fetch_from_channel(package_name, ch)
            if result:
                return result
        
        logger.debug(f"Package {package_name} not found in any channel")
        return None
    
    def _fetch_from_channel(
        self,
        package_name: str,
        channel: str
    ) -> Optional[Dict]:
        """
        Fetch package info from a specific channel.
        
        Args:
            package_name: Package name
            channel: Channel name
            
        Returns:
            dict: Package metadata or None
        """
        # Check rate limit
        if not self.rate_limiter.can_make_call('anaconda'):
            usage = self.rate_limiter.get_current_usage('anaconda')
            logger.warning(
                f"Anaconda API rate limit reached. "
                f"Reset in {usage['reset_in']}s. Skipping {package_name}"
            )
            return None
        
        url = f"{self.base_url}/package/{channel}/{package_name}"
        
        try:
            # Record the call
            self.rate_limiter.record_call('anaconda')
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Found {package_name} in {channel}")
                return self._parse_package_data(data, channel)
            
            elif response.status_code == 404:
                logger.debug(f"Package {package_name} not found in {channel}")
                return None
            
            elif response.status_code == 429:
                logger.warning(f"Rate limited by Anaconda API for {package_name}")
                return None
            
            else:
                logger.warning(
                    f"Anaconda API error for {package_name}: "
                    f"Status {response.status_code}"
                )
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching {package_name} from Anaconda: {e}")
            return None
    
    def _parse_package_data(self, data: Dict, channel: str) -> Dict:
        """
        Parse Anaconda API response into standardized format.
        
        Args:
            data: Raw API response
            channel: Channel name
            
        Returns:
            dict: Standardized package metadata
        """
        # Extract basic info
        package_info = {
            'name': data.get('name'),
            'summary': data.get('summary', ''),
            'description': data.get('description', ''),
            'license': data.get('license', ''),
            'home': data.get('home', ''),
            'source_url': data.get('source_url', ''),
            'channel': channel,
            'versions': [],
            'latest_version': None,
        }
        
        # Extract versions
        releases = data.get('releases', [])
        if releases:
            package_info['versions'] = releases
            package_info['latest_version'] = releases[0] if releases else None
        
        # Extract latest file info if available
        latest_files = data.get('files', [])
        if latest_files:
            latest_file = latest_files[0]
            package_info['latest_file'] = {
                'version': latest_file.get('version'),
                'size': latest_file.get('size'),
                'upload_time': latest_file.get('upload_time'),
                'attrs': latest_file.get('attrs', {}),
            }
        
        return package_info
    
    @lru_cache(maxsize=2048)
    def get_version_info(
        self,
        package_name: str,
        version: str,
        channel: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Get detailed info for a specific package version.
        
        Args:
            package_name: Package name
            version: Package version
            channel: Specific channel (or None to try all)
            
        Returns:
            dict: Version metadata or None
        """
        # First get package info to find the channel
        pkg_info = self.get_package_info(package_name, channel)
        if not pkg_info:
            return None
        
        # Use the channel from package info
        ch = pkg_info.get('channel', channel or 'conda-forge')
        
        # Check rate limit
        if not self.rate_limiter.can_make_call('anaconda'):
            return None
        
        url = f"{self.base_url}/package/{ch}/{package_name}/files"
        
        try:
            self.rate_limiter.record_call('anaconda')
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                files = response.json()
                
                # Find files for this version
                version_files = [
                    f for f in files
                    if f.get('version') == version
                ]
                
                if version_files:
                    return self._parse_version_data(
                        version_files[0],
                        package_name,
                        version,
                        ch
                    )
            
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(
                f"Error fetching version {version} for {package_name}: {e}"
            )
            return None
    
    def _parse_version_data(
        self,
        file_data: Dict,
        package_name: str,
        version: str,
        channel: str
    ) -> Dict:
        """
        Parse version-specific data.
        
        Args:
            file_data: File metadata from API
            package_name: Package name
            version: Package version
            channel: Channel name
            
        Returns:
            dict: Standardized version metadata
        """
        attrs = file_data.get('attrs', {})
        
        return {
            'name': package_name,
            'version': version,
            'channel': channel,
            'build': file_data.get('basename', '').split('-')[-1].replace('.tar.bz2', ''),
            'license': attrs.get('license', ''),
            'size': file_data.get('size', 0),
            'timestamp': file_data.get('upload_time', ''),
            'depends': attrs.get('depends', []),
            'md5': file_data.get('md5', ''),
            'sha256': file_data.get('sha256', ''),
            'subdir': attrs.get('subdir', ''),
        }
    
    def search_package(
        self,
        query: str,
        channel: Optional[str] = None
    ) -> List[Dict]:
        """
        Search for packages by name.
        
        Args:
            query: Search query
            channel: Specific channel (optional)
            
        Returns:
            list: List of matching packages
        """
        if not self.rate_limiter.can_make_call('anaconda'):
            return []
        
        url = f"{self.base_url}/search"
        params = {'q': query}
        if channel:
            params['channel'] = channel
        
        try:
            self.rate_limiter.record_call('anaconda')
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('packages', [])
            
            return []
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching for {query}: {e}")
            return []
    
    def get_rate_limit_status(self) -> Dict:
        """
        Get current rate limit status.
        
        Returns:
            dict: Rate limit usage statistics
        """
        return self.rate_limiter.get_current_usage('anaconda')
