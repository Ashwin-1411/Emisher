"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import Settings, get_settings
from app.services import Services, build_services


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    """Build the app.

    Both arguments exist for tests: pass ``services`` to inject fake DNS / mocked HTTP /
    in-memory cache instead of the production wiring.
    """
    settings = settings or (services.settings if services else get_settings())
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.services = services or build_services(settings)
        yield
        await app.state.services.http.aclose()
        await app.state.services.cache.close()

    app = FastAPI(title="Phishing Email Analyzer", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings

    # Strict CORS: only the listed origins (the extension's chrome-extension://<id>) are allowed.
    # An empty list means no cross-origin browser access at all, which is the safe default.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Token", "Content-Type"],
    )
    app.include_router(router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Liveness probe. Deliberately unauthenticated and free of any dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
