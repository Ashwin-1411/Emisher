"""FastAPI application factory."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. Taking ``settings`` as a parameter keeps tests independent of the env."""
    settings = settings or get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = FastAPI(title="Phishing Email Analyzer", version="0.1.0")
    app.state.settings = settings

    # Strict CORS: only the listed origins (the extension's chrome-extension://<id>) are allowed.
    # An empty list means no cross-origin browser access at all, which is the safe default.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Token", "Content-Type"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Liveness probe. Deliberately unauthenticated and free of any dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
