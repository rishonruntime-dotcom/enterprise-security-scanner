from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

class LoggingConfig(BaseSettings):
    """Configuration for application logging."""
    level: str = Field(default="INFO", description="Logging level (e.g., DEBUG, INFO, WARNING, ERROR)")
    format: Literal["json", "text"] = Field(default="json", description="Log output format")
    log_file: str | None = Field(default=None, description="Path to log file. If None, logs to stdout.")

class ScannerConfig(BaseSettings):
    """Configuration specific to the scanning engine."""
    max_concurrency: int = Field(default=10, description="Maximum number of concurrent scans")
    timeout_seconds: int = Field(default=300, description="Default timeout for scans in seconds")

class NetworkConfig(BaseSettings):
    """Configuration for HTTP interactions."""
    default_timeout: float = Field(default=30.0, description="Default timeout for HTTP requests")
    max_connections: int = Field(default=100, description="Max concurrent connections per client pool")
    proxy_url: str | None = Field(default=None, description="Global proxy URL if any")
    proxy_username: str | None = Field(default=None)
    proxy_password: str | None = Field(default=None)


class NetworkExposureConfig(BaseSettings):
    """Configuration for network exposure analysis."""
    enabled: bool = Field(default=False, description="Enable network exposure scanning")
    timeout: float = Field(default=2.0, description="Timeout per port scan in seconds")
    concurrency: int = Field(default=100, description="Max concurrent port scans")
    banner_grab: bool = Field(default=True, description="Enable banner grabbing")
    common_ports_only: bool = Field(default=False, description="Scan only common ports (1-1024)")
    port_ranges: str = Field(default="1-1024,3000-4000,8000-9000", description="Port ranges to scan")
    skip_ports: str = Field(default="", description="Comma-separated ports to skip")

class BrowserConfig(BaseSettings):
    """Configuration for browser automation."""
    headless: bool = Field(default=True, description="Run browser in headless mode")
    timeout: float = Field(default=30000.0, description="Browser action timeout in ms")

class CrawlerConfig(BaseSettings):
    """Configuration for the web crawler."""
    max_depth: int = Field(default=3, description="Maximum crawl depth")
    max_urls: int = Field(default=1000, description="Maximum URLs to crawl per session")
    use_browser: bool = Field(default=True, description="Use browser engine for crawling instead of raw HTTP")
    concurrency: int = Field(default=5, description="Number of concurrent crawler workers")

class IntelligenceConfig(BaseSettings):
    """Configuration for the fingerprinting engine."""
    signature_file_path: str = Field(default="src/scanner/intelligence/signatures.json", description="Path to technology signatures JSON")
    confidence_threshold: int = Field(default=40, description="Minimum confidence score to report a technology")

class PassiveConfig(BaseSettings):
    """Configuration for the passive security engine."""
    plugins_package: str = Field(default="scanner.passive.plugins", description="Package path to load passive plugins from")
    enabled: bool = Field(default=True, description="Enable passive security checks")

class ActiveConfig(BaseSettings):
    """Configuration for the active security engine."""
    plugins_package: str = Field(default="scanner.active.plugins", description="Package path to load active plugins from")
    enabled: bool = Field(default=True, description="Enable active security checks")

class CorrelationConfig(BaseSettings):
    """Configuration for finding correlation and enrichment."""
    enable_deduplication: bool = Field(default=True, description="Enable duplicate finding removal")
    enable_enrichment: bool = Field(default=True, description="Enable threat intelligence enrichment")

class RiskConfig(BaseSettings):
    """Configuration for the risk scoring engine."""
    default_asset_criticality: str = Field(default="Medium", description="Default criticality for assessed assets (Low, Medium, High, MissionCritical)")

class APIConfig(BaseSettings):
    """Configuration for the REST API."""
    host: str = Field(default="0.0.0.0", description="API host bind address")
    port: int = Field(default=5000, description="API port")

class ReportingConfig(BaseSettings):
    """Configuration for report generation."""
    output_dir: str = Field(default="reports", description="Directory to store generated reports")

class AppConfig(BaseSettings):
    """Main application configuration."""
    environment: Literal["development", "testing", "production"] = Field(
        default="development", description="Application environment"
    )
    app_name: str = Field(default="Enterprise Scanner", description="Application name")
    
    # Nested configurations
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    network_exposure: NetworkExposureConfig = Field(default_factory=NetworkExposureConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
    passive: PassiveConfig = Field(default_factory=PassiveConfig)
    active: ActiveConfig = Field(default_factory=ActiveConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    # We use pydantic_settings to load from env variables prefix
    model_config = {
        "env_prefix": "SCANNER_",
        "env_nested_delimiter": "__",
    }
    
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: "PydanticBaseSettingsSource",
        env_settings: "PydanticBaseSettingsSource",
        dotenv_settings: "PydanticBaseSettingsSource",
        file_secret_settings: "PydanticBaseSettingsSource",
    ) -> tuple["PydanticBaseSettingsSource", ...]:
        # Give environment variables precedence over init kwargs (yaml data)
        return (env_settings, dotenv_settings, init_settings, file_secret_settings)
