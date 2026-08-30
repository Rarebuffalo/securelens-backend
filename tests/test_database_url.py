from app.config import Settings


def test_neon_postgres_url_normalization():
    s = Settings(
        database_url="postgresql://user:pass@ep-cool-fog-12345.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=disable"
    )
    normalized = s.async_database_url
    assert normalized.startswith("postgresql+asyncpg://")
    assert "ssl=require" in normalized
    assert "sslmode" not in normalized
    assert "channel_binding" not in normalized


def test_supabase_postgres_url_normalization():
    s = Settings(
        database_url="postgres://postgres:pass@db.xyz.supabase.co:5432/postgres?sslmode=require"
    )
    normalized = s.async_database_url
    assert normalized.startswith("postgresql+asyncpg://")
    assert "ssl=require" in normalized
    assert "sslmode" not in normalized


def test_local_docker_postgres_url():
    s = Settings(
        database_url="postgresql+asyncpg://securelens:securelens@localhost:5433/securelens"
    )
    assert s.async_database_url == "postgresql+asyncpg://securelens:securelens@localhost:5433/securelens"


def test_sqlite_url_preserved():
    s = Settings(database_url="sqlite+aiosqlite:///:memory:")
    assert s.async_database_url == "sqlite+aiosqlite:///:memory:"
