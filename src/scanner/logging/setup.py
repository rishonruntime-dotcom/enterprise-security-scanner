import logging
import sys

import structlog
from structlog.typing import Processor

from ..config.settings import LoggingConfig


def redact_secrets(logger, log_method, event_dict):
    """Redact sensitive fields from the log event dictionary."""
    sensitive_keys = {"authorization", "cookie", "set-cookie", "password", "token", "secret"}
    for key, value in list(event_dict.items()):
        if isinstance(value, dict):
            # Shallow scan of nested dicts (like headers)
            for k, v in value.items():
                if k.lower() in sensitive_keys:
                    value[k] = "***REDACTED***"
        elif key.lower() in sensitive_keys:
            event_dict[key] = "***REDACTED***"
    return event_dict


def setup_logging(config: LoggingConfig, app_name: str) -> None:
    """Configure structlog based on the provided configuration."""
    
    # Map string level to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    log_level = level_map.get(config.level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        redact_secrets,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.dict_tracebacks,
    ]

    # Add app_name to all logs
    structlog.contextvars.bind_contextvars(app_name=app_name)

    renderer: Processor
    if config.format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # Configure stdlib logging
    handler = logging.StreamHandler(sys.stdout)
    if config.log_file:
        handler = logging.FileHandler(config.log_file)
        
    # We use structlog to format the output of the standard library logger
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Configure structlog
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
