from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_health_returns_ok() -> None:
    client = TestClient(create_app(Settings(_env_file=None)))
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_csv_settings_are_split() -> None:
    s = Settings(_env_file=None, api_tokens="a, b ,c", cors_allowed_origins="chrome-extension://x")
    assert s.api_tokens == ["a", "b", "c"]
    assert s.cors_allowed_origins == ["chrome-extension://x"]
