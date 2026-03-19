"""Pydantic schemas for request/response validation."""

from .auth import (
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

__all__ = [
    "SendOTPRequest",
    "SendOTPResponse",
    "VerifyOTPRequest",
    "VerifyOTPResponse",
    "SetPasswordRequest",
    "SetPasswordResponse",
    "LoginRequest",
    "LoginResponse",
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "LogoutRequest",
    "LogoutResponse",
]
