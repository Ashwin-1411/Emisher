import pytest
from helpers import StaticResolver

from app.cache import MemoryCache, SqliteCache, url_key
from app.enrichment.asn import lookup_asn


@pytest.fixture(params=["memory", "sqlite"])
def cache(request, tmp_path):
    return MemoryCache() if request.param == "memory" else SqliteCache(str(tmp_path / "c.sqlite3"))


async def test_set_get_delete(cache) -> None:
    assert await cache.get("k") is None
    await cache.set("k", {"a": [1, 2]}, ttl_seconds=60)
    assert await cache.get("k") == {"a": [1, 2]}
    await cache.delete("k")
    assert await cache.get("k") is None


async def test_expiry(cache) -> None:
    await cache.set("k", 1, ttl_seconds=-1)  # already expired
    assert await cache.get("k") is None


async def test_sqlite_persists_across_instances(tmp_path) -> None:
    path = str(tmp_path / "persist.sqlite3")
    first = SqliteCache(path)
    await first.set("k", "v", 60)
    await first.close()
    second = SqliteCache(path)
    assert await second.get("k") == "v"
    await second.close()


def test_url_key_stores_only_a_hash() -> None:
    key = url_key("vt:url", "https://evil.example/?token=secret")
    assert "secret" not in key and "evil" not in key and key.startswith("vt:url:")
    assert len(key.split(":")[-1]) == 64


def test_asn_lookup_via_cymru_dns() -> None:
    resolver = StaticResolver(
        {"TXT": {"8.8.8.8.origin.asn.cymru.com": ["15169 | 8.8.8.0/24 | US | arin | 2023-12-28"]}}
    )
    assert lookup_asn(resolver, "8.8.8.8") == ("AS15169", "US")
    assert lookup_asn(resolver, "10.0.0.1") == ("", "")  # private: never queried
    assert lookup_asn(resolver, "1.1.1.1") == ("", "")
