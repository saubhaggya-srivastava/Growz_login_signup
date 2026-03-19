"""
Authentication routes for FastAPI application.

This module implements all authentication endpoints including:
- OTP-based registration workflow
- Password-based login
- Token refresh and logout
- Proper error handling and validation

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.10, 11.1, 11.2, 11.3, 11.5
"""

import logging

from fastapi import APIRouter, HTTPException, status

from dependencies import (
    AuthServiceDep,
    TokenServiceDep,
)
from schemas.auth import (
    SendOTPRequest,
    SendOTPResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
    SetPasswordRequest,
    SetPasswordResponse,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    LogoutRequest,
    LogoutResponse,
)
from utils.exceptions import (
    InvalidCredentialsError,
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenError,
    RateLimitExceededError,
)


logger = logging.getLogger(__name__)

# Create router with prefix and tags
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/send-otp", response_model=SendOTPResponse, status_code=status.HTTP_200_OK)
async def send_otp(
    request: SendOTPRequest,
    auth_service: AuthServiceDep
) -> SendOTPResponse:
    """
    Send OTP to email address for registration.
    
    This endpoint initiates the registration process by sending an OTP
    to the provided email address. Returns a generic success message
    to prevent account enumeration attacks.
    
    Args:
        request: Request containing email address
        auth_service: Injected authentication service
        
    Returns:
        SendOTPResponse: Generic success message
        
    Raises:
        HTTPException: 429 if rate limit exceeded
        HTTPException: 500 for internal server errors
        
    Requirements: 8.1, 5.1, 5.2
    """
    try:
        # Delegate to auth service
        success = await auth_service.initiate_registration(request.email)
        
        # Always return generic success message (account enumeration protection)
        return SendOTPResponse(
            message="If the email exists, an OTP has been sent"
        )
        
    except RateLimitExceededError as e:
        logger.warning(f"Rate limit exceeded for OTP request: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error sending OTP to {request.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/verify-otp", response_model=VerifyOTPResponse, status_code=status.HTTP_200_OK)
async def verify_otp(
    request: VerifyOTPRequest,
    auth_service: AuthServiceDep
) -> VerifyOTPResponse:
    """
    Verify OTP and receive verification token.
    
    This endpoint verifies the OTP sent to the email address and returns
    a verification token that can be used to set a password and complete
    the registration process.
    
    Args:
        request: Request containing email and OTP
        auth_service: Injected authentication service
        
    Returns:
        VerifyOTPResponse: Verification token and success message
        
    Raises:
        HTTPException: 400 for invalid OTP
        HTTPException: 429 if rate limit exceeded
        HTTPException: 500 for internal server errors
        
    Requirements: 8.2, 1.6, 1.7, 1.8
    """
    try:
        # Verify OTP and get verification token
        verification_token = await auth_service.verify_otp_and_issue_token(
            request.email, request.otp
        )
        
        if not verification_token:
            logger.warning(f"Invalid OTP verification attempt for: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        return VerifyOTPResponse(
            verification_token=verification_token,
            message="OTP verified successfully"
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except RateLimitExceededError as e:
        logger.warning(f"Rate limit exceeded for OTP verification: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error verifying OTP for {request.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/set-password", response_model=SetPasswordResponse, status_code=status.HTTP_201_CREATED)
async def set_password(
    request: SetPasswordRequest,
    auth_service: AuthServiceDep
) -> SetPasswordResponse:
    """
    Set password and complete user registration.
    
    This endpoint completes the registration process by setting a password
    for the user account. Requires a valid verification token obtained from
    the OTP verification step.
    
    Args:
        request: Request containing email, password, and verification token
        auth_service: Injected authentication service
        
    Returns:
        SetPasswordResponse: Success message
        
    Raises:
        HTTPException: 400 for invalid verification token or existing user
        HTTPException: 500 for internal server errors
        
    Requirements: 8.3, 1.10, 1.11, 1.12, 1.13, 1.14, 1.15
    """
    try:
        # Complete registration with password
        user = await auth_service.complete_registration(
            request.email, request.password, request.verification_token
        )
        
        if not user:
            logger.warning(f"Failed to complete registration for: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token or user already exists"
            )
        
        logger.info(f"User registration completed successfully: {request.email}")
        return SetPasswordResponse(
            message="Account created successfully"
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error setting password for {request.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    request: LoginRequest,
    auth_service: AuthServiceDep
) -> LoginResponse:
    """
    Login with email and password.
    
    This endpoint authenticates a user with email and password credentials
    and returns access and refresh tokens for subsequent API access.
    
    Args:
        request: Request containing email and password
        auth_service: Injected authentication service
        
    Returns:
        LoginResponse: Access token, refresh token, and token type
        
    Raises:
        HTTPException: 401 for invalid credentials
        HTTPException: 429 if rate limit exceeded
        HTTPException: 500 for internal server errors
        
    Requirements: 8.4, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9
    """
    try:
        # Attempt login
        tokens = await auth_service.login(request.email, request.password)
        
        if not tokens:
            logger.warning(f"Failed login attempt for: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        access_token, refresh_token = tokens
        
        logger.info(f"Successful login for: {request.email}")
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except RateLimitExceededError as e:
        logger.warning(f"Rate limit exceeded for login: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except InvalidCredentialsError:
        logger.warning(f"Invalid credentials for login: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    except Exception as e:
        logger.error(f"Error during login for {request.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/refresh", response_model=RefreshTokenResponse, status_code=status.HTTP_200_OK)
async def refresh_token(
    request: RefreshTokenRequest,
    token_service: TokenServiceDep
) -> RefreshTokenResponse:
    """
    Refresh access token using refresh token.
    
    This endpoint allows clients to obtain a new access token using a valid
    refresh token. Implements token rotation for enhanced security.
    
    Args:
        request: Request containing refresh token
        token_service: Injected token service
        
    Returns:
        RefreshTokenResponse: New access token, refresh token, and token type
        
    Raises:
        HTTPException: 401 for invalid, expired, or revoked tokens
        HTTPException: 500 for internal server errors
        
    Requirements: 8.5, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
    """
    try:
        # Verify refresh token and get user ID
        user_id = token_service.verify_refresh_token(request.refresh_token)
        
        if not user_id:
            logger.warning("Invalid refresh token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Rotate refresh token (revoke old, create new)
        new_refresh_token = token_service.rotate_refresh_token(request.refresh_token)
        
        if not new_refresh_token:
            logger.error("Failed to rotate refresh token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Create new access token
        new_access_token = token_service.create_access_token(user_id)
        
        logger.info(f"Token refresh successful for user_id: {user_id}")
        return RefreshTokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer"
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except (TokenExpiredError, TokenRevokedError, InvalidTokenError) as e:
        logger.warning(f"Token validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/logout", response_model=LogoutResponse, status_code=status.HTTP_200_OK)
async def logout(
    request: LogoutRequest,
    token_service: TokenServiceDep
) -> LogoutResponse:
    """
    Logout and revoke refresh token.
    
    This endpoint logs out a user by revoking their refresh token,
    preventing further use for token refresh operations.
    
    Args:
        request: Request containing refresh token to revoke
        token_service: Injected token service
        
    Returns:
        LogoutResponse: Success message
        
    Raises:
        HTTPException: 400 for invalid token
        HTTPException: 500 for internal server errors
        
    Requirements: 8.6, 4.5, 14.8, 14.11
    """
    try:
        # Revoke refresh token
        success = token_service.revoke_refresh_token(request.refresh_token)
        
        if not success:
            logger.warning("Failed to revoke refresh token during logout")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid refresh token"
            )
        
        logger.info("User logged out successfully")
        return LogoutResponse(
            message="Logged out successfully"
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )