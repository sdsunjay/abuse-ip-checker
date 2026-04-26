import os

import yaml

CONFIG_DIR = os.path.expanduser("~/.abuse-ip-checker")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml")

ENV_VAR_MAP = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "shodan": "SHODAN_API_KEY",
}


def load_config(config_path=None):
    """Load config from YAML file. Returns empty dict if file doesn't exist."""
    path = config_path or CONFIG_FILE
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_config(config, config_path=None):
    """Save config dict to YAML file. Creates directory if needed.

    Sets restrictive permissions (0600 file, 0700 dir) since this file
    holds API secrets.
    """
    path = config_path or CONFIG_FILE
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    os.chmod(path, 0o600)


def get_api_key(source_name, config_path=None):
    """Get API key for a source. Checks env var first, then config file."""
    env_var = ENV_VAR_MAP.get(source_name)
    if env_var:
        env_val = os.environ.get(env_var)
        if env_val:
            return env_val

    config = load_config(config_path)
    key = config.get("api_keys", {}).get(source_name)
    if key:
        return key

    return None


def get_all_keys(config_path=None):
    """Return dict of source_name -> key (or None) for all known sources."""
    return {name: get_api_key(name, config_path) for name in ENV_VAR_MAP}


def migrate_from_constants():
    """Migrate hardcoded API key from constants.py to config file."""
    if os.path.exists(CONFIG_FILE):
        config = load_config()
        if config.get("api_keys", {}).get("abuseipdb"):
            return  # already migrated

    try:
        constants_path = os.path.join(os.path.dirname(__file__), "constants.py")
        if not os.path.exists(constants_path):
            return
        with open(constants_path) as f:
            content = f.read()
        if "from abuse_ip_checker.config.config import" in content:
            return  # already migrated to shim
        for line in content.splitlines():
            if line.startswith("API_KEY") and "=" in line:
                key = line.split("=", 1)[1].strip().strip("'\"")
                if key and key != "None" and not key.startswith("from "):
                    config = load_config()
                    if "api_keys" not in config:
                        config["api_keys"] = {}
                    config["api_keys"]["abuseipdb"] = key
                    save_config(config)
                    print(f"Migrated AbuseIPDB API key to {CONFIG_FILE}")
                    with open(constants_path, "w") as f:
                        f.write(
                            'from abuse_ip_checker.config.config import get_api_key\n\nAPI_KEY = get_api_key("abuseipdb")\n'
                        )
                    print("Updated constants.py to use config.py")
                    return
    except Exception as e:
        print(f"Warning: Could not migrate API key: {e}")
