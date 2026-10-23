class ScannerError(Exception):
    """Base exception for all scanner errors."""
    def __init__(self, message: str, error_code: str = "ERR_GENERIC"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class ConfigurationError(ScannerError):
    """Raised when there is an error in the application configuration."""
    def __init__(self, message: str):
        super().__init__(message, error_code="ERR_CONFIG")

class DependencyError(ScannerError):
    """Raised when there is an error resolving a dependency."""
    def __init__(self, message: str):
        super().__init__(message, error_code="ERR_DEPENDENCY")

class ServiceStartupError(ScannerError):
    """Raised when a service fails to start."""
    def __init__(self, message: str):
        super().__init__(message, error_code="ERR_SERVICE_STARTUP")
