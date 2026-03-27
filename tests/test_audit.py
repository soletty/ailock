"""Tests for audit command and known-bad database."""

import json
import tempfile
from pathlib import Path

import pytest
from ailock.commands.audit import KnownBadEntry, load_local_db, merge_databases


def test_known_bad_entry_matches_by_version():
    entry = KnownBadEntry({
        "package": "litellm",
        "version": "1.82.7",
        "hashes": [],
        "severity": "CRITICAL",
        "description": "Malicious version",
    })

    # Should match exact version
    assert entry.matches_lockfile_entry("litellm", "1.82.7", [])

    # Should not match different version
    assert not entry.matches_lockfile_entry("litellm", "1.84.0", [])


def test_known_bad_entry_case_insensitive():
    entry = KnownBadEntry({
        "package": "LiteLLM",
        "version": "1.82.7",
        "hashes": [],
        "severity": "HIGH",
        "description": "Test",
    })

    assert entry.matches_lockfile_entry("litellm", "1.82.7", [])


def test_known_bad_entry_hash_matching():
    malicious_hash = "sha256:deadbeef123"
    entry = KnownBadEntry({
        "package": "litellm",
        "version": "1.82.7",
        "hashes": [malicious_hash],
        "severity": "CRITICAL",
        "description": "Malicious",
    })

    # Should match if package has the malicious hash
    assert entry.matches_lockfile_entry("litellm", "1.82.7", [malicious_hash, "sha256:cleanone"])

    # Should not match if package has different hash
    assert not entry.matches_lockfile_entry("litellm", "1.82.7", ["sha256:cleanone"])


def test_known_bad_entry_null_version_matches_all():
    """Version=null means flag ALL versions of this package."""
    entry = KnownBadEntry({
        "package": "langchian",
        "version": None,
        "hashes": [],
        "severity": "HIGH",
        "description": "Typosquat",
    })

    assert entry.matches_lockfile_entry("langchian", "0.0.1", [])
    assert entry.matches_lockfile_entry("langchian", "99.99.99", [])
    assert not entry.matches_lockfile_entry("langchain", "0.1.0", [])


def test_load_local_db():
    """Should load the bundled known-bad database."""
    db = load_local_db()
    assert len(db) > 0

    # Should have the LiteLLM entries
    litellm_entries = [e for e in db if e.package == "litellm"]
    assert len(litellm_entries) >= 2

    versions = [e.version for e in litellm_entries]
    assert "1.82.7" in versions
    assert "1.82.8" in versions


def test_merge_databases():
    local = [
        KnownBadEntry({
            "package": "pkg-a",
            "version": "1.0",
            "hashes": ["sha256:aaa"],
            "severity": "HIGH",
            "description": "local",
        })
    ]
    remote = [
        KnownBadEntry({
            "package": "pkg-b",
            "version": "2.0",
            "hashes": ["sha256:bbb"],
            "severity": "CRITICAL",
            "description": "remote",
        })
    ]

    merged = merge_databases(local, remote)
    packages = [e.package for e in merged]
    assert "pkg-a" in packages
    assert "pkg-b" in packages


def test_merge_databases_deduplication():
    entry_data = {
        "package": "pkg-a",
        "version": "1.0",
        "hashes": ["sha256:aaa"],
        "severity": "HIGH",
        "description": "duplicate",
    }
    local = [KnownBadEntry(entry_data)]
    remote = [KnownBadEntry(entry_data)]

    merged = merge_databases(local, remote)
    assert len(merged) == 1


def test_merge_databases_none_remote():
    local = [
        KnownBadEntry({
            "package": "pkg-a",
            "version": "1.0",
            "hashes": [],
            "severity": "HIGH",
            "description": "local",
        })
    ]
    merged = merge_databases(local, None)
    assert len(merged) == 1
    assert merged[0].package == "pkg-a"
