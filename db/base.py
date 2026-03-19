"""SQLAlchemy base configuration with database engine and session factory."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from core.config import settings

# Create database engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,  # Verify connections before using them
    pool_size=5,  # Number of connections to maintain
    max_overflow=10,  # Maximum number of connections to create beyond pool_size
    echo=False,  # Set to True for SQL query logging during development
)

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Create declarative base for models
Base = declarative_base()
