"""
Centralized dependency injection setup for FastAPI authentication system.

This module provides a centralized location for all dependency injection functions
used throughout the application. It implements the FastAPI dependency injection
pattern with proper service lifecycle management and testability.

Key Features:
- Centralized dependency management
- Clean service factory functions
- Proper dependency hierarchy
- Easy testing and mocking
- Consistent service instantiation

Requirements: 11.5
"""

import logging
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from db.session import get_db
from services.auth_service import AuthService
from services.otp_service import OTPService
from services.token_service import TokenService
from services.email_service import EmailService, create_email_service


logger = logging.getLogger(__name__)


# Database Dependencies
def get_database_session() -> Session:
    """
    Get database session dependency.
    
    This is an alias for get_db() from db.session for consistency
    with the centralized dependency injection pattern.
    
    Returns:
        Session: SQLAlchemy database session
        
    Note:
        This function delegates to get_db() which handles proper
        session lifecycle (creation, yielding, cleanup).
    """
    return get_db()


# Service Dependencies
def get_email_service() -> EmailService:
    """
    Get email service instance.
    
    Creates and returns an email service instance based on the
    configured email provider (SMTP, SendGrid, AWS SES, etc.).
    
    Returns:
        EmailService: Configured email service instance
        
    Note:
        The actual implementation is determined by the EMAIL_PROVIDER
        configuration setting. This factory pattern allows easy
        swapping of email providers without code changes.
    """
    try:
        email_service = create_email_service()
        logger.debug(f"Created email service: {type(email_service).__name__}")
        return email_service
    except Exception as e:
        logger.error(f"Failed to create email service: {e}")
        raise


def get_token_service(
    db: Annotated[Session, Depends(get_db)]
) -> TokenService:
    """
    Get token service with database dependency.
    
    Creates a TokenService instance with the required database session
    dependency. Handles JWT access tokens, refresh tokens, and
    verification tokens.
    
    Args:
        db: SQLAlchemy database session (injected)
        
    Returns:
        TokenService: Token service instance with database session
        
    Dependencies:
        - Database session for token storage and validation
    """
    try:
        token_service = TokenService(db)
        logger.debug("Created token service with database session")
        return token_service
    except Exception as e:
        logger.error(f"Failed to create token service: {e}")
        raise


def get_otp_service(
    db: Annotated[Session, Depends(get_db)],
    email_service: Annotated[EmailService, Depends(get_email_service)]
) -> OTPService:
    """
    Get OTP service with database and email service dependencies.
    
    Creates an OTPService instance with the required database session
    and email service dependencies. Handles OTP generation, validation,
    and lifecycle management.
    
    Args:
        db: SQLAlchemy database session (injected)
        email_service: Email service for sending OTPs (injected)
        
    Returns:
        OTPService: OTP service instance with all dependencies
        
    Dependencies:
        - Database session for OTP storage and validation
        - Email service for sending OTP codes
    """
    try:
        otp_service = OTPService(db, email_service)
        logger.debug("Created OTP service with database and email service")
        return otp_service
    except Exception as e:
        logger.error(f"Failed to create OTP service: {e}")
        raise


def get_auth_service(
    db: Annotated[Session, Depends(get_db)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)]
) -> AuthService:
    """
    Get authentication service with all required dependencies.
    
    Creates an AuthService instance with the complete dependency tree:
    database session, OTP service, and token service. This is the main
    service that orchestrates authentication workflows.
    
    Args:
        db: SQLAlchemy database session (injected)
        otp_service: OTP service for verification workflows (injected)
        token_service: Token service for JWT management (injected)
        
    Returns:
        AuthService: Authentication service instance with all dependencies
        
    Dependencies:
        - Database session for user and account management
        - OTP service for registration verification
        - Token service for authentication tokens
        
    Note:
        This service sits at the top of the dependency hierarchy and
        orchestrates the complete authentication workflow including
        registration, login, and token management.
    """
    try:
        auth_service = AuthService(db, otp_service, token_service)
        logger.debug("Created auth service with all dependencies")
        return auth_service
    except Exception as e:
        logger.error(f"Failed to create auth service: {e}")
        raise


# Convenience type aliases for dependency injection
DatabaseSession = Annotated[Session, Depends(get_db)]
EmailServiceDep = Annotated[EmailService, Depends(get_email_service)]
TokenServiceDep = Annotated[TokenService, Depends(get_token_service)]
OTPServiceDep = Annotated[OTPService, Depends(get_otp_service)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


# Testing Dependencies (for easy mocking in tests)
class DependencyOverrides:
    """
    Utility class for overriding dependencies in tests.
    
    This class provides a clean way to override dependencies for testing
    purposes without modifying the main dependency injection setup.
    
    Example usage in tests:
        app.dependency_overrides[get_email_service] = lambda: MockEmailService()
        app.dependency_overrides[get_db] = lambda: mock_db_session
    """
    
    @staticmethod
    def override_email_service(mock_service: EmailService):
        """Override email service with mock implementation."""
        return lambda: mock_service
    
    @staticmethod
    def override_database_session(mock_session: Session):
        """Override database session with mock implementation."""
        return lambda: mock_session
    
    @staticmethod
    def override_token_service(mock_service: TokenService):
        """Override token service with mock implementation."""
        return lambda: mock_service
    
    @staticmethod
    def override_otp_service(mock_service: OTPService):
        """Override OTP service with mock implementation."""
        return lambda: mock_service
    
    @staticmethod
    def override_auth_service(mock_service: AuthService):
        """Override auth service with mock implementation."""
        return lambda: mock_service


# Dependency validation (for development/debugging)
def validate_dependencies():
    """
    Validate that all dependencies can be created successfully.
    
    This function can be called during application startup to ensure
    all dependencies are properly configured and can be instantiated.
    
    Raises:
        Exception: If any dependency fails to be created
        
    Note:
        This is primarily for development and debugging purposes.
        In production, dependency issues will be caught when the
        first request is made.
    """
    try:
        # Test email service creation
        email_service = get_email_service()
        logger.info(f"Email service validation passed: {type(email_service).__name__}")
        
        # Note: We can't easily test database-dependent services here
        # without a database connection, but the factory functions
        # themselves can be validated for import and basic structure
        
        logger.info("Dependency validation completed successfully")
        
    except Exception as e:
        logger.error(f"Dependency validation failed: {e}")
        raise


# Export commonly used dependencies for easy importing
__all__ = [
    # Core dependency functions
    "get_db",
    "get_database_session",
    "get_email_service",
    "get_token_service",
    "get_otp_service",
    "get_auth_service",
    
    # Type aliases for dependency injection
    "DatabaseSession",
    "EmailServiceDep",
    "TokenServiceDep",
    "OTPServiceDep",
    "AuthServiceDep",
    
    # Testing utilities
    "DependencyOverrides",
    "validate_dependencies",
]