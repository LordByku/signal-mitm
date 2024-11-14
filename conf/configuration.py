from pathlib import Path

import yaml

__conf_dir = Path(__file__).resolve().parent

__constants_path = __conf_dir / "constants.yml"
__configuration_path = __conf_dir / "configuration.yml"
__config_template_path = __conf_dir / "configuration_template.yml"


def load_and_merge_configurations() -> dict:
    # Determine the directory where the script is located

    with open(__constants_path, "r") as f:
        const = yaml.safe_load(f)

    with open(__configuration_path, "r") as f:
        config = yaml.safe_load(f)

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

    updated_config = merge_dicts(config, const)
    updated_config["IGNORE_HOSTS"] = (
        rf'"{r"|".join(config.get("ignore_hosts_list", []))}"'
    )
    config_validator(updated_config)
    return updated_config


def create_config_template(template_path) -> None:
    """
    Export a full configuration template (with all the variables and constants) into a yml file.
    Args:
        template_path: where to output the file

    Returns:
    """
    with open(__constants_path, "r") as f:
        const = yaml.safe_load(f)

    with open(__config_template_path, "r") as f:
        config_template = yaml.safe_load(f)

    # Function to merge with annotations
    def merge_and_annotate(base, defaults):
        annotated = {}
        for key, value in defaults.items():
            if key in base:
                # Use the type from base if it's there
                annotated[key] = annotate_type(base[key])
            else:
                # Use the value from defaults but annotate it
                annotated[key] = (
                    annotate_type(value)
                    if not isinstance(value, dict)
                    else merge_and_annotate({}, value)
                )
        for key in base:
            if key not in annotated:
                annotated[key] = annotate_type(base[key])
        return annotated

    def annotate_type(value):
        if isinstance(value, str):
            return f"!!str {value}"
        elif isinstance(value, int):
            return f"!!int {value}"
        elif isinstance(value, float):
            return f"!!float {value}"
        elif isinstance(value, list):
            return [f"{v}" for v in value]
        elif isinstance(value, dict):
            return merge_and_annotate(value, {})
        elif isinstance(value, bool):
            return f"!!bool {value}"
        else:
            return f"!!unknown {value}"

    # Create the annotated configuration
    annotated_template = merge_and_annotate(config_template, const)

    # Write annotated configuration to the specified path
    with open(template_path, "w") as f:
        yaml.safe_dump(annotated_template, f, default_flow_style=False, version=(1, 2))

    print(f"Template configuration file created at: {template_path}")


if __name__ == "__main__":
    # Example usage within this file if needed (not relying on __main__, can be commented out)
    config = load_and_merge_configurations()

    print(f"Updated Config: {config}")
    print(f"Ignore Hosts: {config['IGNORE_HOSTS']}")

    # create_config_template(__conf_dir / "configuration.example.yml")

__all__ = ["load_and_merge_configurations", "create_config_template"]
