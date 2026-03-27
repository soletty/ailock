"""Lockfile format for ailock — read/write .ailock files."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from ailock import __version__
from ailock.core.constants import LOCKFILE_NAME


class PackageEntry:
    """A single package entry in the lockfile."""

    def __init__(
        self,
        name: str,
        version: str,
        hashes: List[str],
        source: str = "pypi",
        yanked: bool = False,
        yanked_reason: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.hashes = hashes  # List of sha256:... strings
        self.source = source
        self.yanked = yanked
        self.yanked_reason = yanked_reason

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": self.version,
            "hashes": sorted(self.hashes),
            "source": self.source,
        }
        if self.yanked:
            d["yanked"] = True
        if self.yanked_reason:
            d["yanked_reason"] = self.yanked_reason
        return d

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "PackageEntry":
        return cls(
            name=name,
            version=data["version"],
            hashes=data.get("hashes", []),
            source=data.get("source", "pypi"),
            yanked=data.get("yanked", False),
            yanked_reason=data.get("yanked_reason"),
        )


class Lockfile:
    """The .ailock lockfile — stores cryptographic hashes of AI/LLM packages."""

    SCHEMA_VERSION = "1"

    def __init__(self):
        self.schema_version: str = self.SCHEMA_VERSION
        self.ailock_version: str = __version__
        self.generated_at: Optional[str] = None
        self.packages: Dict[str, PackageEntry] = {}
        self.source_files: List[str] = []

    def add_package(self, entry: PackageEntry) -> None:
        """Add or update a package entry."""
        self.packages[entry.name.lower().replace("_", "-")] = entry

    def get_package(self, name: str) -> Optional[PackageEntry]:
        """Get a package entry by name (case-insensitive, normalised)."""
        return self.packages.get(name.lower().replace("_", "-"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ailock_version": self.ailock_version,
            "generated_at": self.generated_at or datetime.now(timezone.utc).isoformat(),
            "source_files": self.source_files,
            "packages": {
                name: entry.to_dict()
                for name, entry in sorted(self.packages.items())
            },
        }

    def write(self, path: Optional[Path] = None) -> Path:
        """Write lockfile to disk."""
        target = path or Path(LOCKFILE_NAME)
        self.generated_at = datetime.now(timezone.utc).isoformat()
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            f.write("\n")
        return target

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Lockfile":
        """Load lockfile from disk."""
        target = path or Path(LOCKFILE_NAME)
        if not target.exists():
            raise FileNotFoundError(
                f"No lockfile found at {target}. "
                "Run 'ailock generate' to create one."
            )
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)

        lf = cls()
        lf.schema_version = data.get("schema_version", "1")
        lf.ailock_version = data.get("ailock_version", "unknown")
        lf.generated_at = data.get("generated_at")
        lf.source_files = data.get("source_files", [])

        for name, pkg_data in data.get("packages", {}).items():
            lf.packages[name] = PackageEntry.from_dict(name, pkg_data)

        return lf

    @classmethod
    def exists(cls, path: Optional[Path] = None) -> bool:
        """Check if a lockfile exists."""
        target = path or Path(LOCKFILE_NAME)
        return target.exists()

    def __len__(self) -> int:
        return len(self.packages)

    def __repr__(self) -> str:
        return f"<Lockfile packages={len(self.packages)} generated_at={self.generated_at}>"
