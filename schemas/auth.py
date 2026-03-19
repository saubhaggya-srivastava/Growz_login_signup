"""Authentication request/response schemas using Pydantic."""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional


class SendOTPRequest(BaseModel):
    """Request schema for sending OTP to email."""
    email: EmailStr = Field(..., description="Email address to send OTP to")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class SendOTPResponse(BaseModel):
    """Response schema for OTP send request."""
    message: str = Field(..., description="Generic success message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "If the email exists, an OTP has been sent"
            }
        }


class VerifyOTPRequest(BaseModel):
    """Request schema for OTP verification."""
    email: EmailStr = Field(..., description="Email address associated with the OTP")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")
    
    @validator('otp')
    def validate_otp_format(cls, v):
        """Validate OTP is exactly 6 digits."""
        if not v.isdigit():
            raise ValueError('OTP must contain only digits')
        if len(v) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "otp": "123456"
            }
        }


class VerifyOTPResponse(BaseModel):
    """Response schema for OTP verification."""
    verification_token: str = Field(..., description="Temporary token for password setting")
    message: str = Field(..., description="Success message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "verification_token": "abc123def456",
                "message": "OTP verified successfully"
            }
        }


class SetPasswordRequest(BaseModel):
    """Request schema for setting password after OTP verification."""
    email: EmailStr = Field(..., description="Email address for the account")
    password: str = Field(..., min_length=8, description="Password with minimum 8 characters")
    verification_token: str = Field(..., description="Token received from OTP verification")
    
    @validator('password')
    def validate_password_length(cls, v):
        """Validate password meets minimum length requirement."""
        from core.config import settings
        min_length = settings.password_min_length
        if len(v) < min_length:
            raise ValueError(f'Password must be at least {min_length} characters long')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123",
                "verification_token": "abc123def456"
            }
        }


class SetPasswordResponse(BaseModel):
    """Response schema for password setting."""
    message: str = Field(..., description="Success message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Account created successfully"
            }
        }


class LoginRequest(BaseModel):
    """Request schema for user login."""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123"
            }
        }


class LoginResponse(BaseModel):
    """Response schema for successful login."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer"
            }
        }


class RefreshTokenRequest(BaseModel):
    """Request schema for token refresh."""
    refresh_token: str = Field(..., description="Valid refresh token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }


class RefreshTokenResponse(BaseModel):
    """Response schema for token refresh."""
    access_token: str = Field(..., description="New JWT access token")
    refresh_token: str = Field(..., description="New JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer"
            }
        }


class LogoutRequest(BaseModel):
    """Request schema for user logout."""
    refresh_token: str = Field(..., description="Refresh token to revoke")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }


class LogoutResponse(BaseModel):
    """Response schema for logout."""
    message: str = Field(..., description="Success message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Logged out successfully"
            }
        }