import logging
from scanner.config.settings import LoggingConfig
from scanner.logging.setup import setup_logging


def test_setup_logging_no_crash():
    """Test that setup_logging executes without error."""
    config = LoggingConfig(level="DEBUG", format="json")
    setup_logging(config, "test_app")
    
    # Check that root logger has handlers
    root_logger = logging.getLogger()
    assert len(root_logger.handlers) > 0
    assert root_logger.level == logging.DEBUG
