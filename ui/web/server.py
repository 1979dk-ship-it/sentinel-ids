"""FastAPI server for the SENTINEL web dashboard.

Runs as its own process (`python -m ui.web`), fully decoupled from the
capture core. The core (main.py) writes alerts to SQLite; this server only
*reads* them. Nothing here touches the detectors, the packet queue, or the TUI.

This file is the application factory. The actual server launch lives in
__main__.py, so create_app() stays importable (e.g. for tests) without the
side effect of binding a port.
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    """Builds the FastAPI application.

    For now it only serves the static dashboard page. The WebSocket endpoint
    and the database broadcaster are added in the next step.
    """
    app = FastAPI(title="SENTINEL IDS Dashboard")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        """Serves the dashboard page."""
        return FileResponse(STATIC_DIR / "index.html")

    return app
