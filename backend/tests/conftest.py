"""Shared fixtures. Nothing here touches the network or needs API keys."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from helpers import StaticResolver

from app.cache import MemoryCache
from app.config import Settings
from app.main import create_app
from app.scoring import load_rules
from app.services import Services

TOKEN = "test-token"


def _no_network(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"Unexpected network call to {request.url}")


def make_settings(**overrides) -> Settings:
    base = {"api_tokens": TOKEN, "cache_backend": "memory", "rate_limit_per_minute": 1000}
    base.update(overrides)
    return Settings(_env_file=None, **base)


def make_services(settings: Settings | None = None, handler=_no_network, resolver=None) -> Services:
    from app.api.ratelimit import RateLimiter
    from app.api.store import ReportStore

    settings = settings or make_settings()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Services(
        settings=settings,
        resolver=resolver or StaticResolver(),
        http=http,
        cache=MemoryCache(),
        ruleset=load_rules(
            settings.scoring_rules_path,
            settings.score_suspicious_threshold,
            settings.score_phishing_threshold,
        ),
        reports=ReportStore(settings.report_ttl_seconds, settings.report_store_max),
        limiter=RateLimiter(settings.rate_limit_per_minute),
    )


@pytest.fixture
def services() -> Services:
    return make_services()


@pytest.fixture
def client(services: Services):
    app = create_app(services.settings, services)
    with TestClient(app, headers={"X-API-Token": TOKEN}) as c:
        yield c
