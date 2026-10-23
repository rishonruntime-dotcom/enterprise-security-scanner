import os
from pathlib import Path
from typing import Any, Dict

import yaml
from dotenv import load_dotenv

from .settings import AppConfig

class ConfigurationLoader:
    """Loads configuration from YAML files and environment variables."""

    @staticmethod
    def load(config_path: str | Path | None = None) -> AppConfig:
        """
        Load configuration.
        
        1. Loads .env file
        2. Determines environment (development, testing, production)
        3. Loads corresponding YAML configuration if provided
        4. Overrides with Environment variables (via pydantic-settings)
        """
        # Load environment variables from .env file if it exists
        load_dotenv()
        
        # Determine environment, default to development
        env = os.getenv("SCANNER_ENVIRONMENT", "development")
        
        config_data: Dict[str, Any] = {}
        
        # Load YAML configuration if a path is provided
        if config_path:
            config_path = Path(config_path)
            env_config_path = config_path / f"{env}.yaml"
            
            if env_config_path.exists():
                with open(env_config_path, "r") as f:
                    yaml_data = yaml.safe_load(f)
                    if yaml_data:
                        config_data.update(yaml_data)
        
        return AppConfig(**config_data)

