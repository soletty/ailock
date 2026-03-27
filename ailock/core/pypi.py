"""PyPI API client for fetching package metadata and hashes."""

import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from packaging.version import Version

from ailock.core.constants import PYPI_API_BASE

# Default timeout for PyPI API calls (seconds)
DEFAULT_TIMEOUT = 30

# Rate limit: max requests per second
RATE_LIMIT_DELAY = 0.1


class PyPIError(Exception):
    """Raised when a PyPI API call fails."""
    pass


class PackageNotFoundError(PyPIError):
    """Raised when a package is not found on PyPI."""
    pass


class VersionNotFoundError(PyPIError):
    """Raised when a specific version is not found on PyPI."""
    pass


def _get_session() -> requests.Session:
    """Create a requests session with appropriate headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "ailock/0.1.0 (https://midnightrun.ai/ailock)",
        "Accept": "application/json",
    })
    return session


_session: Optional[requests.Session] = None


def get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = _get_session()
    return _session


def get_package_info(package: str, version: Optional[str] = None) -> Dict:
    """
    Fetch package metadata from PyPI JSON API.

    Args:
        package: Package name (e.g., "litellm")
        version: Specific version (e.g., "1.84.0"). If None, fetches latest.

    Returns:
        PyPI JSON API response dict.

    Raises:
        PackageNotFoundError: If package doesn't exist on PyPI.
        VersionNotFoundError: If specific version doesn't exist.
        PyPIError: For other API errors.
    """
    if version:
        url = f"{PYPI_API_BASE}/{quote(package)}/{quote(version)}/json"
    else:
        url = f"{PYPI_API_BASE}/{quote(package)}/json"

    try:
        resp = get_session().get(url, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        raise PyPIError(f"Network error fetching {package}: {e}") from e

    if resp.status_code == 404:
        if version:
            raise VersionNotFoundError(
                f"Package {package}=={version} not found on PyPI"
            )
        raise PackageNotFoundError(f"Package {package} not found on PyPI")

    if not resp.ok:
        raise PyPIError(
            f"PyPI API error for {package}: HTTP {resp.status_code}"
        )

    return resp.json()


def get_hashes(package: str, version: str) -> List[str]:
    """
    Get SHA256 hashes for all distribution files of a specific package version.

    Returns list of "sha256:..." strings (one per wheel/sdist file).
    """
    info = get_package_info(package, version)
    urls = info.get("urls", [])

    hashes = []
    for url_info in urls:
        digests = url_info.get("digests", {})
        sha256 = digests.get("sha256")
        if sha256:
            hashes.append(f"sha256:{sha256}")

    if not hashes:
        # Fall back to releases dict
        releases = info.get("releases", {})
        for file_info in releases.get(version, []):
            digests = file_info.get("digests", {})
            sha256 = digests.get("sha256")
            if sha256:
                hashes.append(f"sha256:{sha256}")

    return sorted(set(hashes))


def get_yanked_info(package: str, version: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a version is yanked on PyPI.

    Returns (is_yanked, reason_or_None).
    """
    try:
        info = get_package_info(package, version)
    except (PackageNotFoundError, VersionNotFoundError):
        return False, None

    urls = info.get("urls", [])
    for url_info in urls:
        if url_info.get("yanked"):
            return True, url_info.get("yanked_reason")

    return False, None


def get_latest_version(package: str) -> str:
    """Get the latest stable version of a package."""
    info = get_package_info(package)
    return info["info"]["version"]


def resolve_version(package: str, version_spec: str) -> str:
    """
    Resolve a version specifier (e.g., ">=1.0,<2.0") to a specific version.

    For now, returns the latest version if spec isn't pinned.
    For pinned specs (== or ~=), returns the exact version.
    """
    version_spec = version_spec.strip()

    # Already pinned exactly
    if version_spec.startswith("=="):
        return version_spec[2:].strip()

    # Approximate version (compatible release)
    if version_spec.startswith("~="):
        return version_spec[2:].strip()

    # Complex spec or no spec — get latest from PyPI
    return get_latest_version(package)


def batch_get_hashes(
    packages: List[Tuple[str, str]],
    on_progress=None,
) -> Dict[str, List[str]]:
    """
    Fetch hashes for multiple packages.

    Args:
        packages: List of (name, version) tuples.
        on_progress: Optional callback(name, version, success, error_msg).

    Returns:
        Dict mapping package name to list of hash strings.
    """
    results = {}

    for name, version in packages:
        try:
            hashes = get_hashes(name, version)
            results[name] = hashes
            if on_progress:
                on_progress(name, version, True, None)
        except (PyPIError, Exception) as e:
            results[name] = []
            if on_progress:
                on_progress(name, version, False, str(e))

        # Small delay to be polite to PyPI
        time.sleep(RATE_LIMIT_DELAY)

    return results
