"""API rate limit helpers."""

from __future__ import annotations

from typing import Dict, Any

from src.utils.rate_limiter import get_rate_limiter


def init_rate_limiter():
    """Initialize and configure the shared rate limiter."""
    limiter = get_rate_limiter()
    limiter.set_limit("github", limit=60, window=3600)
    limiter.set_limit("depsdev", limit=1000, window=3600)
    limiter.set_limit("pypi", limit=600, window=3600)
    limiter.set_limit("npm", limit=600, window=3600)
    limiter.set_limit("osv", limit=500, window=3600)
    return limiter


def get_api_rate_limit_status(rate_limiter) -> Dict[str, Any]:
    """
    Get current rate limit status for all APIs.
    Returns warnings if any API is approaching limits.
    """
    status: Dict[str, Any] = {}
    warnings = []

    # GitHub - 60/hr unauthenticated, 5000/hr with token
    gh_usage = rate_limiter.get_current_usage("github")
    status["github"] = {
        "calls_made": gh_usage["calls"],
        "limit": gh_usage["limit"],
        "remaining": gh_usage["remaining"],
        "percentage": round(gh_usage["percentage"], 1),
        "note": "60/hr without token, 5000/hr with token",
    }
    if gh_usage["percentage"] >= 80:
        warnings.append(
            f"GitHub API at {gh_usage['percentage']:.0f}% - provide token to increase limit"
        )

    # deps.dev - Google API, very generous
    depsdev_usage = rate_limiter.get_current_usage("depsdev")
    depsdev_limit = 1000
    status["depsdev"] = {
        "calls_made": depsdev_usage["calls"],
        "limit": depsdev_limit,
        "remaining": max(0, depsdev_limit - depsdev_usage["calls"]),
        "percentage": round((depsdev_usage["calls"] / depsdev_limit) * 100, 1),
        "note": "Google API, generous limits, cached locally",
    }
    if depsdev_usage["calls"] >= depsdev_limit * 0.8:
        warnings.append(
            f"deps.dev API at {(depsdev_usage['calls'] / depsdev_limit) * 100:.0f}%"
        )

    # PyPI - ~100 requests/minute, 600/hour practical limit
    pypi_usage = rate_limiter.get_current_usage("pypi")
    pypi_limit = 600
    status["pypi"] = {
        "calls_made": pypi_usage["calls"],
        "limit": pypi_limit,
        "remaining": max(0, pypi_limit - pypi_usage["calls"]),
        "percentage": round((pypi_usage["calls"] / pypi_limit) * 100, 1),
        "note": "~100/min, no auth required",
    }
    if pypi_usage["calls"] >= pypi_limit * 0.8:
        warnings.append(
            f"PyPI API at {(pypi_usage['calls'] / pypi_limit) * 100:.0f}% - slow down or wait"
        )

    # npm Registry - ~100 requests/minute, generous overall
    npm_usage = rate_limiter.get_current_usage("npm")
    npm_limit = 600
    status["npm"] = {
        "calls_made": npm_usage["calls"],
        "limit": npm_limit,
        "remaining": max(0, npm_limit - npm_usage["calls"]),
        "percentage": round((npm_usage["calls"] / npm_limit) * 100, 1),
        "note": "~100/min, no auth required",
    }
    if npm_usage["calls"] >= npm_limit * 0.8:
        warnings.append(
            f"npm Registry API at {(npm_usage['calls'] / npm_limit) * 100:.0f}% - slow down or wait"
        )

    # OSV (Google) - generous limits
    osv_usage = rate_limiter.get_current_usage("osv")
    osv_limit = 500
    status["osv"] = {
        "calls_made": osv_usage["calls"],
        "limit": osv_limit,
        "remaining": max(0, osv_limit - osv_usage["calls"]),
        "percentage": round((osv_usage["calls"] / osv_limit) * 100, 1),
        "note": "Google OSV database, generous limits",
    }
    if osv_usage["calls"] >= osv_limit * 0.8:
        warnings.append(f"OSV API at {(osv_usage['calls'] / osv_limit) * 100:.0f}%")

    return {"status": status, "warnings": warnings if warnings else None}
