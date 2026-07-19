import yaml


def load_config(config_path: str = "config/config.yaml") -> dict:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)
