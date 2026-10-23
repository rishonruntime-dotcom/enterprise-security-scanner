import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest
from pathlib import Path

@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup environment variables for testing."""
    os.environ["SCANNER_ENVIRONMENT"] = "testing"
    yield
    if "SCANNER_ENVIRONMENT" in os.environ:
        del os.environ["SCANNER_ENVIRONMENT"]

@pytest.fixture
def config_dir() -> Path:
    """Return the path to the configuration directory."""
    return Path(__file__).parent.parent / "config"
