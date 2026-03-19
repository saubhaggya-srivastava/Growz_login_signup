"""Database session management with dependency injection for FastAPI."""
from typing import Generator
from sqlalchemy.orm import Session
from db.base import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session.
    
    This function creates a new SQLAlchemy session for each request,
    yields it to the route handler, and ensures it's closed after use.
    
    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """
    Get a database session for use outside of FastAPI dependency injection.
    
    Note: When using this function, you must manually close the session
    by calling session.close() when done.
    
    Returns:
        Session: SQLAlchemy database session
    """
    return SessionLocal()