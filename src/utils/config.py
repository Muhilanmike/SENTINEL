import yaml
import os
from src.utils.logger import setup_logger

logger = setup_logger("config")

class Config:
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance

    def load(self, config_path: str = "config.yaml"):
        if not os.path.exists(config_path):
            logger.error(f"Config file not found: {config_path}")
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r") as f:
            self._config = yaml.safe_load(f)

        logger.info(f"Configuration loaded from {config_path}")
        return self._config

    def get(self, *keys, default=None):
        if self._config is None:
            self.load()

        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value

    # Quick access properties
    @property
    def network(self):
        return self.get("network", default={})

    @property
    def snort(self):
        return self.get("snort", default={})

    @property
    def ml(self):
        return self.get("ml", default={})

    @property
    def alerts(self):
        return self.get("alerts", default={})

    @property
    def dashboard(self):
        return self.get("dashboard", default={})

    @property
    def logging(self):
        return self.get("logging", default={})


# Global config instance
config = Config()
