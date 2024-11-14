from .configuration import create_config
from .config_spec import Config

# Make config available as part of the conf package
config = create_config()

__all__ = ["config", "Config"]
