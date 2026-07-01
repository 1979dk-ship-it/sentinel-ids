"""Entry point for the web dashboard: run with `python -m ui.web`.

Loads runtime config (the same config/config.yaml the core uses) and starts
the uvicorn ASGI server. Must be run from the project root so the relative
config path and the `ui.web` package import both resolve.
"""
import uvicorn
import yaml

from ui.web.server import create_app


def _load_config(path: str = "config/config.yaml") -> dict:
    """Loads runtime configuration parameters."""
    with open(path) as f:
        return yaml.safe_load(f)


def main() -> None:
    config = _load_config()
    web = config["web"]
    app = create_app(config)
    uvicorn.run(app, host=web["host"], port=web["port"])


if __name__ == "__main__":
    main()
