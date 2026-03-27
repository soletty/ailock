"""Dependency resolver — parses requirements files and finds AI/LLM packages."""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion

from ailock.core.constants import AI_PACKAGES_NORMALIZED, AI_KEYWORDS

# Supported source files, in order of preference
SOURCE_FILES = [
    "requirements.txt",
    "requirements-lock.txt",
    "requirements.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
]


class ParsedPackage:
    """A package found in a requirements file."""

    def __init__(
        self,
        name: str,
        version: Optional[str] = None,
        extras: List[str] = None,
        source_file: str = "",
    ):
        self.name = name.lower().replace("_", "-")
        self.version = version
        self.extras = extras or []
        self.source_file = source_file
        self.is_ai_package = self._check_is_ai()

    def _check_is_ai(self) -> bool:
        """Check if this looks like an AI/LLM package."""
        normalized = self.name.lower().replace("_", "-").replace(".", "-")

        # Exact match in known AI packages list
        if normalized in AI_PACKAGES_NORMALIZED:
            return True

        # Keyword heuristic
        for keyword in AI_KEYWORDS:
            if keyword in normalized:
                return True

        return False

    def __repr__(self) -> str:
        v = f"=={self.version}" if self.version else ""
        return f"<ParsedPackage {self.name}{v} ai={self.is_ai_package}>"


def normalize_name(name: str) -> str:
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements_txt(content: str, source_file: str = "") -> List[ParsedPackage]:
    """Parse a requirements.txt file content."""
    packages = []

    for line in content.splitlines():
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Skip options (-r, -c, --index-url, etc.)
        if line.startswith("-"):
            continue

        # Handle inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        # Handle environment markers (e.g., "package; python_version >= '3.8'")
        if ";" in line:
            line = line[: line.index(";")].strip()

        try:
            req = Requirement(line)
            version = None

            # Extract pinned version from specifier
            for spec in req.specifier:
                if spec.operator in ("==", "~="):
                    version = spec.version
                    break

            packages.append(
                ParsedPackage(
                    name=req.name,
                    version=version,
                    extras=list(req.extras),
                    source_file=source_file,
                )
            )
        except Exception:
            # Skip unparseable lines (URLs, git+https, etc.)
            continue

    return packages


def parse_pyproject_toml(content: str, source_file: str = "") -> List[ParsedPackage]:
    """Parse a pyproject.toml file content."""
    packages = []

    try:
        if sys.version_info >= (3, 11):
            import tomllib
            data = tomllib.loads(content)
        else:
            import tomli
            data = tomli.loads(content)
    except Exception:
        return packages

    # [project.dependencies]
    deps = []
    project = data.get("project", {})
    deps.extend(project.get("dependencies", []))

    # [project.optional-dependencies]
    for group_deps in project.get("optional-dependencies", {}).values():
        deps.extend(group_deps)

    # [tool.poetry.dependencies]
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name.lower() in ("python",):
            continue
        if isinstance(spec, str):
            deps.append(f"{name}{spec}" if spec.startswith(("^", "~", ">", "<", "=", "!")) else name)
        elif isinstance(spec, dict):
            version = spec.get("version", "")
            deps.append(f"{name}{version}" if version else name)

    for dep in deps:
        if isinstance(dep, str):
            pkgs = parse_requirements_txt(dep, source_file)
            packages.extend(pkgs)

    return packages


def parse_setup_cfg(content: str, source_file: str = "") -> List[ParsedPackage]:
    """Parse setup.cfg install_requires."""
    packages = []
    in_install_requires = False

    for line in content.splitlines():
        stripped = line.strip()

        if stripped == "install_requires =":
            in_install_requires = True
            continue
        elif stripped.startswith("[") or (stripped and not line.startswith(" ") and not line.startswith("\t")):
            if in_install_requires:
                in_install_requires = False

        if in_install_requires and stripped:
            pkgs = parse_requirements_txt(stripped, source_file)
            packages.extend(pkgs)

    return packages


def discover_source_files(directory: Path = None) -> List[Path]:
    """Find all supported source files in a directory."""
    base = directory or Path(".")
    found = []

    for filename in SOURCE_FILES:
        p = base / filename
        if p.exists():
            found.append(p)

    return found


def parse_source_file(path: Path) -> List[ParsedPackage]:
    """Parse a requirements/config file and return packages."""
    content = path.read_text(encoding="utf-8")
    name = path.name.lower()
    source = str(path)

    if "requirements" in name and name.endswith(".txt"):
        return parse_requirements_txt(content, source)
    elif name == "pyproject.toml":
        return parse_pyproject_toml(content, source)
    elif name == "setup.cfg":
        return parse_setup_cfg(content, source)
    else:
        return parse_requirements_txt(content, source)


def get_installed_packages() -> Dict[str, str]:
    """
    Get currently installed packages and their versions using importlib.metadata.

    Returns dict of {normalized_name: version}.
    """
    try:
        from importlib.metadata import packages_distributions, version, PackageNotFoundError as _PNF
        import importlib.metadata as meta

        result = {}
        for dist in meta.distributions():
            name = normalize_name(dist.metadata["Name"] or "")
            ver = dist.metadata["Version"] or ""
            if name:
                result[name] = ver
        return result
    except Exception:
        return {}


def filter_ai_packages(
    packages: List[ParsedPackage],
    ai_only: bool = True,
) -> List[ParsedPackage]:
    """Filter packages to only AI/LLM ones (or all if ai_only=False)."""
    if not ai_only:
        return packages
    return [p for p in packages if p.is_ai_package]
