"""Tests for dependency resolver."""

import pytest
from ailock.core.resolver import (
    parse_requirements_txt,
    parse_pyproject_toml,
    filter_ai_packages,
    normalize_name,
)


def test_parse_requirements_txt_basic():
    content = """
litellm==1.84.0
langchain==0.3.0
requests>=2.28
numpy==1.26.0
"""
    packages = parse_requirements_txt(content)
    assert len(packages) == 4
    names = [p.name for p in packages]
    assert "litellm" in names
    assert "langchain" in names


def test_parse_requirements_txt_with_extras():
    content = "litellm[proxy]==1.84.0\n"
    packages = parse_requirements_txt(content)
    assert len(packages) == 1
    assert packages[0].name == "litellm"
    assert packages[0].version == "1.84.0"


def test_parse_requirements_txt_skips_comments():
    content = """
# This is a comment
litellm==1.84.0  # inline comment
# another comment
openai==1.0.0
"""
    packages = parse_requirements_txt(content)
    assert len(packages) == 2


def test_parse_requirements_txt_skips_options():
    content = """
-r base.txt
--index-url https://pypi.org/simple
litellm==1.84.0
"""
    packages = parse_requirements_txt(content)
    assert len(packages) == 1
    assert packages[0].name == "litellm"


def test_ai_package_detection():
    content = """
litellm==1.84.0
langchain==0.3.0
openai==1.0.0
requests==2.28.0
flask==3.0.0
transformers==4.36.0
"""
    packages = parse_requirements_txt(content)
    ai_pkgs = filter_ai_packages(packages, ai_only=True)
    ai_names = [p.name for p in ai_pkgs]

    assert "litellm" in ai_names
    assert "langchain" in ai_names
    assert "openai" in ai_names
    assert "transformers" in ai_names
    # Non-AI packages should be filtered out
    assert "requests" not in ai_names
    assert "flask" not in ai_names


def test_normalize_name():
    assert normalize_name("LiteLLM") == "litellm"
    assert normalize_name("langchain_core") == "langchain-core"
    assert normalize_name("langchain.core") == "langchain-core"
    assert normalize_name("Langchain-Core") == "langchain-core"


def test_parse_pyproject_toml_basic():
    content = """
[project]
name = "myproject"
dependencies = [
    "litellm==1.84.0",
    "openai>=1.0",
]
"""
    packages = parse_pyproject_toml(content)
    names = [p.name for p in packages]
    assert "litellm" in names
    assert "openai" in names


def test_parse_requirements_txt_environment_markers():
    content = """
litellm==1.84.0; python_version >= "3.8"
openai==1.0.0
"""
    packages = parse_requirements_txt(content)
    assert len(packages) == 2
    assert packages[0].name == "litellm"
    assert packages[0].version == "1.84.0"
