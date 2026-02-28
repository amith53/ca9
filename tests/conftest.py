"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_REPO = FIXTURES_DIR / "sample_repo"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_repo():
    return SAMPLE_REPO


@pytest.fixture
def snyk_path():
    return FIXTURES_DIR / "snyk_sample.json"


@pytest.fixture
def dependabot_path():
    return FIXTURES_DIR / "dependabot_sample.json"


@pytest.fixture
def coverage_path():
    return FIXTURES_DIR / "coverage_sample.json"
