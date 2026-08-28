"""Database transaction boundary for coordinated application writes."""

from __future__ import annotations

from sqlalchemy.orm import Session


class DatabaseUnitOfWork:
    """Commit coordinated writes together, rolling them back on failure."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def __enter__(self) -> "DatabaseUnitOfWork":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if exc_type is not None:
            self.db.rollback()
            return False
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return False
