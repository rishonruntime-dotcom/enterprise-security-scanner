import os
from pathlib import Path

from scanner.config.loader import ConfigurationLoader
from scanner.config.settings import AppConfig


def test_load_testing_config(config_dir: Path):
    """Test loading the testing configuration."""
    config = ConfigurationLoader.load(config_dir)
    
    assert isinstance(config, AppConfig)
    assert config.environment == "testing"
    assert config.app_name == "Enterprise Scanner (Test)"
    assert config.scanner.max_concurrency == 1
    assert config.scanner.timeout_seconds == 5


def test_env_override(config_dir: Path):
    """Test that environment variables override yaml config."""
    os.environ["SCANNER_APP_NAME"] = "Overridden Name"
    os.environ["SCANNER_SCANNER__MAX_CONCURRENCY"] = "100"
    
    try:
        config = ConfigurationLoader.load(config_dir)
        assert config.app_name == "Overridden Name"
        assert config.scanner.max_concurrency == 100
    finally:
        del os.environ["SCANNER_APP_NAME"]
        del os.environ["SCANNER_SCANNER__MAX_CONCURRENCY"]
