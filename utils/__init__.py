"""Utility functions and helpers."""

from .exceptions import (
    AuthSystemException,
    InvalidCredentialsError,
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenError,
    RateLimitExceededError,
    OTPExpiredError,
    OTPAlreadyUsedError,
    VerificationTokenExpiredError,
    EmailDeliveryError,
    UserInactiveError,
    UserNotVerifiedError,
)

from .exception_handlers import (
    create_error_response,
    register_exception_handlers,
    EXCEPTION_HANDLERS,
)

__all__ = [
    # Exceptions
    "AuthSystemException",
    "InvalidCredentialsError",
    "TokenExpiredError",
    "TokenRevokedError",
    "InvalidTokenError",
    "RateLimitExceededError",
    "OTPExpiredError",
    "OTPAlreadyUsedError",
    "VerificationTokenExpiredError",
    "EmailDeliveryError",
    "UserInactiveError",
    "UserNotVerifiedError",
    
    # Exception handlers
    "create_error_response",
    "register_exception_handlers",
    "EXCEPTION_HANDLERS",
]
