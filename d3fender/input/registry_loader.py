import json
from functools import lru_cache
from importlib import resources

@lru_cache(maxsize=1)
def load_capability_registry() -> dict:
    # assuming capabilities.json is inside d3fender/resources/capabilities.json
    with resources.files("d3fender.resources").joinpath("capabilities.json").open("r", encoding="utf-8") as f:
        return json.load(f)

@lru_cache(maxsize=1)
def load_controls_registry() -> dict:
    # assuming controls.json is inside d3fender/resources/controls.json
    with resources.files("d3fender.resources").joinpath("controls.json").open("r", encoding="utf-8") as f:
        return json.load(f)