"""
Rate Limiter for API calls

Prevents hitting rate limits on external APIs like Anaconda, npm registry, etc.
Uses time-based tracking with configurable limits per endpoint.
"""

import time
from typing import Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

from core.log_sanitizer import sanitize_sensitive

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter for API calls with per-endpoint tracking.
    
    Features:
    - Per-endpoint rate limiting
    - Configurable time windows
    - Auto-throttling when approaching limits
    - Warning logs at 80% capacity
    """
    
    def __init__(self):
        # Track calls: {endpoint: [(timestamp, timestamp, ...)]}
        self._calls: Dict[str, list] = defaultdict(list)
        
        # Default limits (calls per hour)
        self._limits = {
            'anaconda': 100,      # Anaconda API: 100/hour unauthenticated
            'npm': 2000,          # npm registry: public registry is very permissive
            'pypi': 600,          # PyPI: very generous
            'depsdev': 1000,      # deps.dev: generous with caching
            'osv': 500,           # OSV.dev: reasonable limit
            'default': 100        # Default for unknown endpoints
        }
        
        # Time window (in seconds)
        self._window = 3600  # 1 hour
        
        # Throttle threshold (percentage)
        self._throttle_threshold = 0.8  # 80%
        
    def set_limit(self, endpoint: str, limit: int, window: int = 3600):
        """
        Set custom rate limit for an endpoint.
        
        Args:
            endpoint: API endpoint identifier
            limit: Maximum calls allowed
            window: Time window in seconds (default: 3600 = 1 hour)
        """
        self._limits[endpoint] = limit
        self._window = window
        logger.debug(f"Rate limit set for {endpoint}: {limit} calls per {window}s")
    
    def _clean_old_calls(self, endpoint: str):
        """Remove calls outside the current time window."""
        if endpoint not in self._calls:
            return
        
        cutoff = time.time() - self._window
        self._calls[endpoint] = [
            timestamp for timestamp in self._calls[endpoint]
            if timestamp > cutoff
        ]
    
    def get_current_usage(self, endpoint: str) -> Dict[str, any]:
        """
        Get current usage statistics for an endpoint.
        
        Returns:
            dict: {
                'calls': int,           # Calls in current window
                'limit': int,           # Maximum allowed
                'percentage': float,    # Usage percentage
                'remaining': int,       # Calls remaining
                'reset_in': int        # Seconds until window resets
            }
        """
        self._clean_old_calls(endpoint)
        
        calls = len(self._calls[endpoint])
        limit = self._limits.get(endpoint, self._limits['default'])
        percentage = (calls / limit) * 100 if limit > 0 else 0
        remaining = max(0, limit - calls)
        
        # Calculate reset time (oldest call + window)
        reset_in = 0
        if self._calls[endpoint]:
            oldest_call = min(self._calls[endpoint])
            reset_time = oldest_call + self._window
            reset_in = max(0, int(reset_time - time.time()))
        
        return {
            'calls': calls,
            'limit': limit,
            'percentage': percentage,
            'remaining': remaining,
            'reset_in': reset_in
        }
    
    def can_make_call(self, endpoint: str) -> bool:
        """
        Check if a call can be made without exceeding rate limit.
        
        Args:
            endpoint: API endpoint identifier
            
        Returns:
            bool: True if call is allowed
        """
        usage = self.get_current_usage(endpoint)
        return usage['remaining'] > 0
    
    def should_throttle(self, endpoint: str) -> bool:
        """
        Check if throttling is recommended (approaching limit).
        
        Args:
            endpoint: API endpoint identifier
            
        Returns:
            bool: True if usage is above throttle threshold
        """
        usage = self.get_current_usage(endpoint)
        return usage['percentage'] >= (self._throttle_threshold * 100)
    
    def record_call(self, endpoint: str) -> bool:
        """
        Record an API call and check if it's allowed.
        
        Args:
            endpoint: API endpoint identifier
            
        Returns:
            bool: True if call was recorded (under limit)
        """
        self._clean_old_calls(endpoint)
        
        usage = self.get_current_usage(endpoint)
        
        # Check if at limit
        if usage['remaining'] <= 0:
            logger.warning(
                f"Rate limit exceeded for {endpoint}: "
                f"{usage['calls']}/{usage['limit']} calls used. "
                f"Reset in {usage['reset_in']}s"
            )
            return False
        
        # Record the call
        self._calls[endpoint].append(time.time())
        
        # Check if approaching limit
        new_usage = self.get_current_usage(endpoint)
        if new_usage['percentage'] >= 80:
            logger.warning(
                f"Approaching rate limit for {endpoint}: "
                f"{new_usage['calls']}/{new_usage['limit']} calls used "
                f"({new_usage['percentage']:.1f}%)"
            )
        
        return True
    
    def wait_if_needed(self, endpoint: str, max_wait: int = 60) -> bool:
        """
        Wait if rate limit is exceeded (with maximum wait time).
        
        Args:
            endpoint: API endpoint identifier
            max_wait: Maximum seconds to wait (default: 60)
            
        Returns:
            bool: True if can proceed, False if should skip
        """
        if self.can_make_call(endpoint):
            return True
        
        usage = self.get_current_usage(endpoint)
        
        # If reset would take longer than max_wait, skip the call entirely
        if usage['reset_in'] > max_wait:
            logger.error(
                f"Rate limit exceeded for {endpoint}. "
                f"Would need to wait {usage['reset_in']}s (max: {max_wait}s). "
                f"Skipping call."
            )
            return False
        
        logger.info(
            f"Rate limit reached for {endpoint}. "
            f"Waiting {usage['reset_in']}s for reset..."
        )
        time.sleep(usage['reset_in'])
        # Re-check after waiting — window may not have fully cleared
        return self.can_make_call(endpoint)
    
    def get_all_usage(self) -> Dict[str, Dict]:
        """
        Get usage statistics for all tracked endpoints.
        
        Returns:
            dict: {endpoint: usage_stats}
        """
        stats = {}
        for endpoint in self._calls.keys():
            stats[endpoint] = self.get_current_usage(endpoint)
        return stats
    
    def reset_endpoint(self, endpoint: str):
        """Reset call tracking for an endpoint."""
        if endpoint in self._calls:
            del self._calls[endpoint]
            logger.info(f"Rate limit tracking reset for {endpoint}")
    
    def reset_all(self):
        """Reset all rate limit tracking."""
        self._calls.clear()
        logger.info("All rate limit tracking reset")


# Global rate limiter instance
_global_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """
    Get the global rate limiter instance (singleton).
    
    Returns:
        RateLimiter: Global rate limiter
    """
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = RateLimiter()
    return _global_rate_limiter


# NEW: Exponential Backoff Decorator
import requests
from functools import wraps


def rate_limited_with_backoff(endpoint: str, calls_per_minute: int = 100, max_retries: int = 5):
    """
    Decorator for API calls with rate limiting and exponential backoff.
    
    Usage:
        @rate_limited_with_backoff("depsdev", calls_per_minute=100)
        def fetch_package(name, version):
            response = requests.get(url)
            return response.json()
    
    Args:
        endpoint: API endpoint identifier (e.g., "depsdev", "pypi", "npm")
        calls_per_minute: Maximum calls allowed per minute
        max_retries: Maximum retry attempts on failure (default: 5)
    
    Features:
        - Automatic rate limiting (waits between calls)
        - Exponential backoff on 429 errors (1s, 2s, 4s, 8s, 16s)
        - Automatic retry on transient failures
    """
    min_interval = 60.0 / calls_per_minute
    last_called = [0.0]  # Use list to allow modification in nested function
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Wait if needed to respect rate limit
            elapsed = time.time() - last_called[0]
            if elapsed < min_interval:
                wait_time = min_interval - elapsed
                time.sleep(wait_time)
            
            # Retry with exponential backoff on failure
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    last_called[0] = time.time()
                    return result
                    
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429:  # Rate limited by server
                        if attempt < max_retries - 1:
                            wait = 2 ** attempt  # 1s, 2s, 4s, 8s, 16s
                            logger.warning(f"[RATE LIMIT] {endpoint}: 429 error, waiting {wait}s... (attempt {attempt + 1}/{max_retries})")
                            time.sleep(wait)
                        else:
                            logger.error(f"[RATE LIMIT] {endpoint}: Max retries reached after 429 errors")
                            raise
                    else:
                        # Other HTTP errors - don't retry
                        raise
                        
                except requests.exceptions.Timeout:
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        logger.warning(f"[TIMEOUT] {endpoint}: Timeout, retrying in {wait}s... (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait)
                    else:
                        logger.error(f"[TIMEOUT] {endpoint}: Max retries reached")
                        raise
                        
                except requests.exceptions.ConnectionError:
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        logger.warning(f"[CONNECTION] {endpoint}: Connection error, retrying in {wait}s... (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait)
                    else:
                        logger.error(f"[CONNECTION] {endpoint}: Max retries reached")
                        raise
                        
                except Exception as e:
                    # Unknown error - log sanitized message and raise immediately
                    logger.error("Unexpected API error", extra={"endpoint": endpoint, "error": sanitize_sensitive(str(e))})
                    raise
            
        return wrapper
    return decorator
