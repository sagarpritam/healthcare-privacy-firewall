"""
Healthcare Privacy Firewall — Database Engine & Session Management
Uses async SQLAlchemy with asyncpg for PostgreSQL.
Gracefully degrades when DB drivers are not installed.
"""

import os
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://firewall_user:firewall_pass@localhost:5432/healthcare_firewall",
)
DATABASE_SYNC_URL = os.getenv(
    "DATABASE_SYNC_URL",
    "postgresql+psycopg2://firewall_user:firewall_pass@localhost:5432/healthcare_firewall",
)

# Lazy initialization — only created when first accessed
_async_engine = None
_sync_engine = None
_AsyncSessionLocal = None
_SyncSessionLocal = None

try:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()
except ImportError:
    Base = None

def _get_async_engine():
    global _async_engine
    if _async_engine is None:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            # Attempt to connect to Postgres natively
            try:
                _async_engine = create_async_engine(
                    DATABASE_URL,
                    echo=False,
                    pool_size=20,
                    max_overflow=10,
                    pool_pre_ping=True,
                )
            except Exception as e:
                logger.warning(f"Failed to connect to PG natively, falling back to local SQLite async DB: {e}")
                _async_engine = create_async_engine(
                    "sqlite+aiosqlite:///./firewall_local.db",
                    echo=False,
                    connect_args={"check_same_thread": False}
                )
        except Exception as e:
            logger.error(f"Could not create async DB engine at all: {e}")
            return None
    return _async_engine


def _get_async_session_factory():
    global _AsyncSessionLocal
    if _AsyncSessionLocal is None:
        engine = _get_async_engine()
        if engine is None:
            return None
        try:
            from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
            _AsyncSessionLocal = async_sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
        except Exception as e:
            logger.warning(f"Could not create async session factory: {e}")
            return None
    return _AsyncSessionLocal


def _get_sync_engine():
    global _sync_engine
    if _sync_engine is None:
        try:
            from sqlalchemy import create_engine
            try:
                _sync_engine = create_engine(
                    DATABASE_SYNC_URL,
                    echo=False,
                    pool_size=10,
                    max_overflow=5,
                    pool_pre_ping=True,
                )
            except Exception as e:
                logger.warning(f"Failed to connect to PG natively, falling back to local SQLite sync DB: {e}")
                _sync_engine = create_engine(
                    "sqlite:///./firewall_local.db",
                    echo=False,
                    connect_args={"check_same_thread": False}
                )
        except Exception as e:
            logger.error(f"Could not create sync DB engine at all: {e}")
            return None
    return _sync_engine


def _get_sync_session_factory():
    global _SyncSessionLocal
    if _SyncSessionLocal is None:
        engine = _get_sync_engine()
        if engine is None:
            return None
        try:
            from sqlalchemy.orm import sessionmaker
            _SyncSessionLocal = sessionmaker(bind=engine)
        except Exception as e:
            logger.warning(f"Could not create sync session factory: {e}")
            return None
    return _SyncSessionLocal


async def get_async_session():
    """Dependency for FastAPI routes."""
    factory = _get_async_session_factory()
    if factory is None:
        raise RuntimeError("Database not available")
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_session():
    """Get a synchronous session for workers."""
    factory = _get_sync_session_factory()
    if factory is None:
        raise RuntimeError("Database not available")
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def init_db():
    """Create all tables (for development). Use Alembic in production."""
    engine = _get_async_engine()
    if engine is None:
        logger.warning("Cannot init DB — async engine not available")
        return
    if Base is None:
        logger.warning("Cannot init DB — SQLAlchemy not available")
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Dispose engine connections on shutdown."""
    if _async_engine:
        await _async_engine.dispose()
