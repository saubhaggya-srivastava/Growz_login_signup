"""Exception handlers for the FastAPI authentication system.

This module provides comprehensive exception handlers that convert custom exceptions
into proper HTTP responses with appropriate status codes and consistent error formatting.
The handlers implement security best practices by using generic error messages to
prevent information leakage and account enumeration attacks.
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import ValidationError
import logging
from typing import Dict, Any

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

# Configure logger for exception handling
logger = logging.getLogger(__name__)


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: Dict[str, Any] = None
) -> JSONResponse:
    """Create a consistent error response format.
    
    Args:
        status_code: HTTP status code
        error_code: Internal error code for client handling
        message: User-friendly error message
        details: Optional additional error details
        
    Returns:
        JSONResponse with consistent error format
    """
    error_content = {
        "error": {
            "code": error_code,
            "message": message,
        }
    }
    
    if details:
        error_content["error"]["details"] = details
        
    return JSONResponse(
        status_code=status_code,
        content=error_content
    )


async def auth_system_exception_handler(request: Request, exc: AuthSystemException) -> JSONResponse:
    """Handle base AuthSystemException and its subclasses.
    
    This is a catch-all handler for any AuthSystemException that doesn't have
    a more specific handler. Maps to HTTP 500 with generic message.
    """
    logger.error(f"Unhandled AuthSystemException: {exc.__class__.__name__}: {exc.message}")
    
    return create_error_response(
        status_code=500,
        error_code="INTERNAL_ERROR",
        message="An internal error occurred. Please try again later."
    )


async def invalid_credentials_exception_handler(request: Request, exc: InvalidCredentialsError) -> JSONResponse:
    """Handle InvalidCredentialsError.
    
    Maps authentication errors to HTTP 401 with generic message to prevent
    account enumeration attacks. This includes invalid email/password,
    inactive accounts, and unverified accounts.
    """
    logger.warning(f"Authentication failed: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="AUTHENTICATION_FAILED",
        message="Invalid credentials. Please check your email and password."
    )


async def user_inactive_exception_handler(request: Request, exc: UserInactiveError) -> JSONResponse:
    """Handle UserInactiveError.
    
    Maps to HTTP 401 with generic message to prevent account enumeration.
    Should not reveal that the account exists but is inactive.
    """
    logger.warning(f"Inactive user login attempt: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="AUTHENTICATION_FAILED",
        message="Invalid credentials. Please check your email and password."
    )


async def user_not_verified_exception_handler(request: Request, exc: UserNotVerifiedError) -> JSONResponse:
    """Handle UserNotVerifiedError.
    
    Maps to HTTP 401 with generic message to prevent account enumeration.
    Should not reveal that the account exists but is not verified.
    """
    logger.warning(f"Unverified user login attempt: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="AUTHENTICATION_FAILED",
        message="Invalid credentials. Please check your email and password."
    )


async def token_expired_exception_handler(request: Request, exc: TokenExpiredError) -> JSONResponse:
    """Handle TokenExpiredError.
    
    Maps token expiration errors to HTTP 401. Used for JWT access tokens,
    refresh tokens, and verification tokens.
    """
    logger.info(f"Token expired: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="TOKEN_EXPIRED",
        message="Token has expired. Please authenticate again."
    )


async def token_revoked_exception_handler(request: Request, exc: TokenRevokedError) -> JSONResponse:
    """Handle TokenRevokedError.
    
    Maps token revocation errors to HTTP 401. Used when refresh tokens
    have been explicitly revoked.
    """
    logger.info(f"Token revoked: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="TOKEN_REVOKED",
        message="Token has been revoked. Please authenticate again."
    )


async def invalid_token_exception_handler(request: Request, exc: InvalidTokenError) -> JSONResponse:
    """Handle InvalidTokenError.
    
    Maps invalid token errors to HTTP 401. Used for malformed JWT tokens,
    invalid signatures, or tokens with invalid structure.
    """
    logger.warning(f"Invalid token: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="INVALID_TOKEN",
        message="Invalid token. Please authenticate again."
    )


async def rate_limit_exceeded_exception_handler(request: Request, exc: RateLimitExceededError) -> JSONResponse:
    """Handle RateLimitExceededError.
    
    Maps rate limit violations to HTTP 429. Used for login attempts,
    OTP requests, and other rate-limited operations.
    """
    logger.warning(f"Rate limit exceeded: {exc.message}")
    
    return create_error_response(
        status_code=429,
        error_code="RATE_LIMIT_EXCEEDED",
        message="Too many requests. Please try again later."
    )


async def otp_expired_exception_handler(request: Request, exc: OTPExpiredError) -> JSONResponse:
    """Handle OTPExpiredError.
    
    Maps OTP expiration to HTTP 401. OTP codes typically expire after 5 minutes.
    """
    logger.info(f"OTP expired: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="OTP_EXPIRED",
        message="OTP has expired. Please request a new one."
    )


async def otp_already_used_exception_handler(request: Request, exc: OTPAlreadyUsedError) -> JSONResponse:
    """Handle OTPAlreadyUsedError.
    
    Maps OTP reuse attempts to HTTP 401. Prevents OTP replay attacks.
    """
    logger.warning(f"OTP reuse attempt: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="OTP_ALREADY_USED",
        message="OTP has already been used. Please request a new one."
    )


async def verification_token_expired_exception_handler(request: Request, exc: VerificationTokenExpiredError) -> JSONResponse:
    """Handle VerificationTokenExpiredError.
    
    Maps verification token expiration to HTTP 401. Verification tokens
    typically expire after 10 minutes.
    """
    logger.info(f"Verification token expired: {exc.message}")
    
    return create_error_response(
        status_code=401,
        error_code="VERIFICATION_TOKEN_EXPIRED",
        message="Verification token has expired. Please verify your OTP again."
    )


async def email_delivery_exception_handler(request: Request, exc: EmailDeliveryError) -> JSONResponse:
    """Handle EmailDeliveryError.
    
    Maps email delivery failures to HTTP 500. Should not expose email
    service internals to prevent information leakage.
    """
    logger.error(f"Email delivery failed: {exc.message}")
    
    return create_error_response(
        status_code=500,
        error_code="EMAIL_DELIVERY_ERROR",
        message="Unable to send email. Please try again later."
    )


async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """Handle Pydantic ValidationError.
    
    Maps validation errors to HTTP 422 with detailed field-level errors.
    This provides helpful feedback for client applications.
    """
    logger.info(f"Validation error: {exc}")
    
    # Extract field-level validation errors
    validation_errors = []
    for error in exc.errors():
        field_path = " -> ".join(str(loc) for loc in error["loc"])
        validation_errors.append({
            "field": field_path,
            "message": error["msg"],
            "type": error["type"]
        })
    
    return create_error_response(
        status_code=422,
        error_code="VALIDATION_ERROR",
        message="Validation failed. Please check your input.",
        details={"validation_errors": validation_errors}
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle FastAPI HTTPException.
    
    Converts FastAPI HTTPException to our consistent error format.
    Preserves the original status code and message.
    """
    logger.info(f"HTTP exception: {exc.status_code} - {exc.detail}")
    
    return create_error_response(
        status_code=exc.status_code,
        error_code="HTTP_ERROR",
        message=exc.detail if isinstance(exc.detail, str) else "An error occurred."
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle generic Python exceptions.
    
    Maps unexpected exceptions to HTTP 500 without exposing internals.
    This is the final catch-all handler for any unhandled exceptions.
    """
    logger.error(f"Unhandled exception: {exc.__class__.__name__}: {str(exc)}", exc_info=True)
    
    return create_error_response(
        status_code=500,
        error_code="INTERNAL_ERROR",
        message="An internal error occurred. Please try again later."
    )


# Exception handler mapping for FastAPI app registration
EXCEPTION_HANDLERS = {
    # Custom authentication exceptions
    InvalidCredentialsError: invalid_credentials_exception_handler,
    UserInactiveError: user_inactive_exception_handler,
    UserNotVerifiedError: user_not_verified_exception_handler,
    
    # Token-related exceptions
    TokenExpiredError: token_expired_exception_handler,
    TokenRevokedError: token_revoked_exception_handler,
    InvalidTokenError: invalid_token_exception_handler,
    
    # Rate limiting exceptions
    RateLimitExceededError: rate_limit_exceeded_exception_handler,
    
    # OTP-related exceptions
    OTPExpiredError: otp_expired_exception_handler,
    OTPAlreadyUsedError: otp_already_used_exception_handler,
    
    # Verification token exceptions
    VerificationTokenExpiredError: verification_token_expired_exception_handler,
    
    # Email service exceptions
    EmailDeliveryError: email_delivery_exception_handler,
    
    # Base exception (catch-all for custom exceptions)
    AuthSystemException: auth_system_exception_handler,
    
    # FastAPI and Pydantic exceptions
    ValidationError: validation_exception_handler,
    HTTPException: http_exception_handler,
    
    # Generic Python exceptions (final catch-all)
    Exception: generic_exception_handler,
}


def register_exception_handlers(app):
    """Register all exception handlers with the FastAPI application.
    
    Args:
        app: FastAPI application instance
    """
    for exception_class, handler in EXCEPTION_HANDLERS.items():
        app.add_exception_handler(exception_class, handler)
    
    logger.info("Exception handlers registered successfully")