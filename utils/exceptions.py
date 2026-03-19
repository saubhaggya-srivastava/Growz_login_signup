"""Custom exception classes for the FastAPI authentication system.

This module defines a hierarchy of custom exceptions that provide structured
error handling throughout the authentication system. All exceptions inherit
from AuthSystemException base class and are designed to work with FastAPI
exception handlers.
"""


class AuthSystemException(Exception):
    """Base exception for all authentication system errors.
    
    This is the root exception class that all other auth system exceptions
    inherit from. It provides a common interface for handling auth-related
    errors and enables consistent error handling patterns.
    """
    
    def __init__(self, message: str = "Authentication system error"):
        self.message = message
        super().__init__(self.message)


class InvalidCredentialsError(AuthSystemException):
    """Raised for any authentication failure.
    
    This exception is used for all authentication failures including:
    - Invalid email/password combinations
    - Invalid OTP codes
    - Invalid verification tokens
    - Inactive or unverified user accounts
    
    Note: This generic exception helps prevent account enumeration attacks
    by providing the same error type for different failure scenarios.
    """
    
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message)


class TokenExpiredError(AuthSystemException):
    """Raised when a token has expired.
    
    This exception is raised when:
    - JWT access tokens have expired
    - JWT refresh tokens have expired
    - Verification tokens have expired
    - OTP codes have expired (though OTPExpiredError is more specific)
    """
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)


class TokenRevokedError(AuthSystemException):
    """Raised when a token has been revoked.
    
    This exception is raised when:
    - Refresh tokens have been explicitly revoked
    - Tokens are invalidated due to logout
    - Tokens are revoked for security reasons
    """
    
    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(message)


class InvalidTokenError(AuthSystemException):
    """Raised when a token is malformed or invalid.
    
    This exception is raised when:
    - JWT tokens have invalid signatures
    - JWT tokens are malformed
    - Tokens have invalid structure or format
    - Token type validation fails (e.g., refresh token used as access token)
    """
    
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)


class RateLimitExceededError(AuthSystemException):
    """Raised when rate limit is exceeded.
    
    This exception is raised when:
    - Too many login attempts from the same email
    - Too many OTP requests from the same email
    - Any other rate-limited operation is exceeded
    """
    
    def __init__(self, message: str = "Rate limit exceeded. Please try again later."):
        super().__init__(message)


class OTPExpiredError(AuthSystemException):
    """Raised when OTP has expired.
    
    This exception is raised specifically when:
    - OTP codes have passed their expiration time (typically 5 minutes)
    - Verification is attempted on expired OTP codes
    """
    
    def __init__(self, message: str = "OTP has expired"):
        super().__init__(message)


class OTPAlreadyUsedError(AuthSystemException):
    """Raised when OTP has already been used.
    
    This exception is raised when:
    - An OTP code that was previously verified is used again
    - Prevents OTP replay attacks
    """
    
    def __init__(self, message: str = "OTP has already been used"):
        super().__init__(message)


class VerificationTokenExpiredError(AuthSystemException):
    """Raised when verification token has expired.
    
    This exception is raised when:
    - Verification tokens have passed their expiration time (typically 10 minutes)
    - Password setting is attempted with expired verification token
    """
    
    def __init__(self, message: str = "Verification token has expired"):
        super().__init__(message)


class EmailDeliveryError(AuthSystemException):
    """Raised when email cannot be sent.
    
    This exception is raised when:
    - SMTP server is unavailable
    - Email service API calls fail
    - Network issues prevent email delivery
    - Invalid email configuration
    
    Note: This exception should be caught and handled gracefully to prevent
    exposing email service internals to users.
    """
    
    def __init__(self, message: str = "Email delivery failed"):
        super().__init__(message)


# Additional exceptions for future extensibility
class UserInactiveError(AuthSystemException):
    """Raised when user account is inactive.
    
    This exception is raised when:
    - User account has been deactivated (is_active=False)
    - Should be mapped to InvalidCredentialsError in API layer for security
    """
    
    def __init__(self, message: str = "User account is inactive"):
        super().__init__(message)


class UserNotVerifiedError(AuthSystemException):
    """Raised when user account is not verified.
    
    This exception is raised when:
    - User account has not completed email verification (is_verified=False)
    - Should be mapped to InvalidCredentialsError in API layer for security
    """
    
    def __init__(self, message: str = "User account is not verified"):
        super().__init__(message)