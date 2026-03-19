"""Security utilities for hashing and JWT token management."""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import bcrypt
from jose import JWTError, jwt

from .config import settings


# Password Hashing Functions

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt with configured rounds.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hashed password as string
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against
        
    Returns:
        True if password matches, False otherwise
    """
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)


# Token Hashing Functions

def hash_token(token: str) -> str:
    """
    Hash a token (OTP, verification token, refresh token) using appropriate method.
    
    Uses bcrypt for short tokens (<= 72 bytes) and SHA-256 for long tokens (like JWTs).
    This handles the bcrypt 72-byte limitation while maintaining security.
    
    Args:
        token: Plain text token to hash
        
    Returns:
        Hashed token as string
    """
    token_bytes = token.encode('utf-8')
    
    # If token is too long for bcrypt (>72 bytes), use SHA-256
    if len(token_bytes) > 72:
        # Use SHA-256 for long tokens (like JWT refresh tokens)
        return hashlib.sha256(token_bytes).hexdigest()
    
    # Use bcrypt for short tokens (OTP, verification tokens, etc.)
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    hashed = bcrypt.hashpw(token_bytes, salt)
    return hashed.decode('utf-8')

    # OLD CODE (commented out for easy revert):
    # token_bytes = token.encode('utf-8')
    # salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    # hashed = bcrypt.hashpw(token_bytes, salt)
    # return hashed.decode('utf-8')


def verify_token(plain_token: str, hashed_token: str) -> bool:
    """
    Verify a token against its hash using appropriate method.
    
    Automatically detects if the hash was created with bcrypt or SHA-256
    and uses the appropriate verification method.
    
    Args:
        plain_token: Plain text token to verify
        hashed_token: Hashed token to compare against
        
    Returns:
        True if token matches, False otherwise
    """
    token_bytes = plain_token.encode('utf-8')
    
    # Check if this is a SHA-256 hash (64 hex characters)
    if len(hashed_token) == 64 and all(c in '0123456789abcdef' for c in hashed_token.lower()):
        # This is a SHA-256 hash, verify using SHA-256
        computed_hash = hashlib.sha256(token_bytes).hexdigest()
        return computed_hash == hashed_token
    
    # This is a bcrypt hash, verify using bcrypt
    try:
        hashed_bytes = hashed_token.encode('utf-8')
        return bcrypt.checkpw(token_bytes, hashed_bytes)
    except Exception:
        return False

    # OLD CODE (commented out for easy revert):
    # token_bytes = plain_token.encode('utf-8')
    # hashed_bytes = hashed_token.encode('utf-8')
    # return bcrypt.checkpw(token_bytes, hashed_bytes)


# JWT Token Functions

def create_access_token(user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with standardized claims.
    
    Args:
        user_id: User identifier to include in token
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token as string
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }
    
    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def create_refresh_token(user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT refresh token with standardized claims.
    
    Args:
        user_id: User identifier to include in token
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token as string
    """
    if expires_delta is None:
        expires_delta = timedelta(days=settings.refresh_token_expire_days)
    
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    }
    
    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError:
        return None


def validate_token_type(payload: Dict[str, Any], expected_type: str) -> bool:
    """
    Validate that a JWT token has the expected type.
    
    Args:
        payload: Decoded JWT payload
        expected_type: Expected token type ("access" or "refresh")
        
    Returns:
        True if token type matches, False otherwise
    """
    return payload.get("type") == expected_type


# Random Token Generation

def generate_random_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of token in bytes (default 32)
        
    Returns:
        Random token as hex string
    """
    return secrets.token_hex(length)


def generate_random_otp() -> str:
    """
    Generate a cryptographically secure 6-digit OTP code.
    
    Returns:
        6-digit OTP as string
    """
    return str(secrets.randbelow(1000000)).zfill(settings.otp_length)
