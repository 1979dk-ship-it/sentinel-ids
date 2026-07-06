"""Shared pytest fixtures, auto-loaded for every test in this directory."""
import pytest

from db.database import init_db


@pytest.fixture
def session_factory(tmp_path):
    """A fresh, isolated SQLite database (its own file) for each test."""
    return init_db((tmp_path / "test.db").as_posix())
