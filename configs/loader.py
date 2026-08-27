"""
Central config loader. Every module should import get_config()
instead of hardcoding values — this is what makes thresholds and
ports changeable without touching module code.
"""
import yaml
from pathlib import Path
from functools import lru_cache

CONFIG_PATH = Path(__file__).parent / "base.yaml"


@lru_cache
def get_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    cfg = get_config()
    print(f"Agent will run on {cfg['agent']['host']}:{cfg['agent']['port']}")
