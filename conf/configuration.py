import yaml

# We assume configuration.yml and constants.yml in the same folder.
with open("./conf/constants.yml", 'r') as f:
    const = yaml.safe_load(f)
with open("./conf/configuration.yml", 'r') as f:
    config = yaml.safe_load(f)

# Compiles the IGNORE_HOSTS_LIST into a single string, used in some configurations.
# TODO: check if this is still fine
IGNORE_HOSTS = f'"{r"|".join(config["ignore_hosts_list"])}"'