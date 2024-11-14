from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel

from conf.config_spec import Config

__conf_dir = Path(__file__).resolve().parent

__constants_path = __conf_dir / "constants.yml"
__configuration_path = __conf_dir / "configuration.yml"
__config_template_path = __conf_dir / "configuration_template.yml"


def load_and_merge_configurations() -> dict:
    # Determine the directory where the script is located

    with open(__constants_path, "r") as f:
        const = yaml.safe_load(f)

    with open(__configuration_path, "r") as f:
        conf = yaml.safe_load(f)

    # Merge function for dictionaries.
    # If not specified by config, use the value present in constants
    # (that file should be safe to commit to git)
    def merge_dicts(base, defaults):
        for key, value in defaults.items():
            if isinstance(value, dict) and key in base:
                base[key] = merge_dicts(base.get(key, {}), value)
            elif key not in base:
                base[key] = value
        return base

    def config_validator(conf: dict):
        # TODO: validate the conf file. if something is wrong, error out
        if len(conf.keys()) == 0:
            raise AssertionError("Empty configuration provided!!")

    updated_config = merge_dicts(conf, const)

    config_validator(updated_config)
    return updated_config


def create_config_template(conf: BaseModel, filename: str) -> None:
    with open(filename, "w") as file:
        yaml.dump(yaml.safe_load(conf.model_dump_json()), file)


def create_config() -> Config:
    """
    Helper function to create the Config object using external configurations.

    Returns:
        Config: The main configuration object.
    """
    # Assuming load_and_merge_configurations returns a dictionary of configuration data
    config_data: dict[str, Any] = load_and_merge_configurations()
    return Config(**config_data)


if __name__ == "__main__":
    config = create_config()
    # create_config_template(config, str(__conf_dir / "configuration.example2.yml"))
    print(config.model_dump_json(indent=4))
    print(config.dhcp.model_json_schema())

__all__ = ["create_config", "load_and_merge_configurations", "create_config_template"]
