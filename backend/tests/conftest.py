"""Shared pytest configuration and custom markers."""
import os
import secrets

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_db: mark test as requiring a live PostgreSQL database",
    )
    # Provide a random JWT_SECRET for tests unless CI supplies one
    os.environ.setdefault("JWT_SECRET", os.getenv("CI_JWT_SECRET", secrets.token_hex(32)))
