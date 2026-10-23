from pathlib import Path

from scanner.di.containers import ApplicationContainer
from scanner.config.settings import AppConfig
from scanner.core.lifecycle import LifecycleManager


def test_container_resolves_config(config_dir: Path):
    """Test that the DI container can resolve the configuration."""
    container = ApplicationContainer(config_path=str(config_dir))
    
    config = container.config()
    assert isinstance(config, AppConfig)
    assert config.environment == "testing"


def test_container_resolves_lifecycle(config_dir: Path):
    """Test that the DI container can resolve the lifecycle manager."""
    container = ApplicationContainer(config_path=str(config_dir))
    
    lifecycle = container.lifecycle_manager()
    assert isinstance(lifecycle, LifecycleManager)
