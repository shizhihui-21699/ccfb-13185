"""VPN 泄露自检服务。"""

from .config import AppConfig, ConfigError, load_config

__all__ = ["AppConfig", "ConfigError", "load_config"]
__version__ = "1.0.0"
