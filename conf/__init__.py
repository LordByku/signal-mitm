# from  . configuration import load_and_merge_configurations
from .configuration import load_and_merge_configurations

# Make config available as part of the conf package
config = load_and_merge_configurations()

__all__ = ["config"]
