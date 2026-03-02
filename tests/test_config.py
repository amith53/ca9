"""Tests for .ca9.toml config file support."""

from __future__ import annotations

import sys

import pytest

from ca9.config import find_config, load_config


class TestFindConfig:
    def test_finds_config_in_current_dir(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('[ca9]\nrepo = "src"\n')
        result = find_config(tmp_path)
        assert result == config_file

    def test_finds_config_in_parent(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('repo = "src"\n')
        child = tmp_path / "sub" / "deep"
        child.mkdir(parents=True)
        result = find_config(child)
        assert result == config_file

    def test_returns_none_when_missing(self, tmp_path):
        child = tmp_path / "isolated"
        child.mkdir()
        result = find_config(child)
        assert result is None


class TestLoadConfig:
    @pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib requires Python 3.11+")
    def test_loads_config(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('repo = "src"\nformat = "json"\nverbose = true\n')
        result = load_config(config_file)
        assert result["repo"] == "src"
        assert result["format"] == "json"
        assert result["verbose"] is True

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib requires Python 3.11+")
    def test_loads_empty_config(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text("")
        result = load_config(config_file)
        assert result == {}
