"""SQLAlchemy configuration and session management."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Use SQLite for M2 as specified. Can be overridden via env var.
DATABASE_URL = os.getenv("AGENTTRUST_DB_URL", "sqlite:///./agenttrust.db")

def _sqlite_connect_args(database_url: str) -> dict:
    return {"check_same_thread": False} if "sqlite" in database_url else {}


def build_engine(database_url: str | None = None):
    url = database_url or DATABASE_URL
    return create_engine(url, connect_args=_sqlite_connect_args(url))


engine = build_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def build_session_factory(database_url: str | None = None):
    local_engine = build_engine(database_url)
    return sessionmaker(autocommit=False, autoflush=False, bind=local_engine), local_engine


def init_db(local_engine=None) -> None:
    """Create all known tables if they do not exist."""
    from agenttrust.db import schema  # noqa: F401

    target_engine = local_engine or engine
    Base.metadata.create_all(bind=target_engine)
    inspector = inspect(target_engine)
    if "approval_requests" in inspector.get_table_names():
        existing = {column["name"] for column in inspector.get_columns("approval_requests")}
        with target_engine.begin() as connection:
            if "approver_public_key" not in existing:
                connection.execute(
                    text("ALTER TABLE approval_requests ADD COLUMN approver_public_key VARCHAR")
                )
            if "decision_signature" not in existing:
                connection.execute(
                    text("ALTER TABLE approval_requests ADD COLUMN decision_signature VARCHAR")
                )

def get_db():
    """FastAPI dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
