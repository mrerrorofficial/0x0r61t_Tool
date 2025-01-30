# core/config.py

import json

CONFIG_PATH = "config.json"

def load_config(file_path=CONFIG_PATH):
    """Load configuration from a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)
