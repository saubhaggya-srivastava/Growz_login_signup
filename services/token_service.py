"""
Token service for JWT and refresh token management.

This service handles the complete token lifecycle including:
- JWT access token creation and validation
- JWT refresh token creation and validation
- Verification token creation and validation with hashing
- Refresh token storage with hashed values
- Token rotation for enhanced security
- Token revocation for logout

Requirements: 1.8, 1.9, 1.10, 2.6, 2.7, 2.12, 2.13, 4.1, 4.2, 4.3, 4.4, 4.5, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8, 14.9
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

from core.config import settings
from core.security import (
    create_access_token as create_jwt_access_token,
    create_refresh_token as create_jwt_refresh_token,
    decode_jwt_token,
    validate_token_type,
    generate_random_token,
    hash_token,
    verify_token
)
from models.verification_token import VerificationToken
from models.refresh_token import RefreshToken


logger = logging.getLogger(__name__)


class TokenService:
    """
    Service for managing JWT tokens, verification tokens, and refresh tokens.
    
    This service provides comprehensive token management including:
    - JWT access token generation (30 min expiry)
    - JWT refresh token generation (7 day expiry) with server-side storage
    - Verification token generation (10 min expiry) with hashing
    - Token validation and verification
    - Refresh token rotation for enhanced security
    - Token revocation for logout
    - Cleanup of expired tokens
    
    Key Security Features:
    - All tokens stored as hashes (never plain text)
    - JWT tokens with standardized claims (sub, exp, iat, type)
    - Server-side refresh token validation and revocation
    - Token rotation to limit exposure window
    - Proper expiration and revocation checking
    """
    
    def __init__(self, db: Session):
        """
        Initialize token service with database session.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def create_access_token(self, user_id: int) -> str:
        """
        Create JWT access token with 30-minute expiration.
        
        Creates a stateless JWT access token with standardized claims:
        - sub: user ID
        - exp: expiration timestamp
        - iat: issued at timestamp
        - type: "access"
        
        Args:
            user_id: User identifier to include in token
            
        Returns:
            str: Encoded JWT access token
            
        Requirements: 2.6, 2.11, 2.12
        """
        try:
            expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
            access_token = create_jwt_access_token(user_id, expires_delta)
            
            logger.debug(f"Created access token for user_id: {user_id}")
            return access_token
            
        except Exception as e:
            logger.error(f"Error creating access token for user_id {user_id}: {e}")
            raise
    
    def create_refresh_token(self, user_id: int, device_info: Optional[str] = None, ip_address: Optional[str] = None) -> str:
        """
        Create JWT refresh token with 7-day expiration and store hashed version.
        
        Creates a JWT refresh token and stores a hashed version in the database
        for server-side validation, revocation, and rotation. The token includes
        standardized claims and optional device/IP tracking.
        
        Args:
            user_id: User identifier to include in token
            device_info: Optional device information for tracking
            ip_address: Optional IP address for security monitoring
            
        Returns:
            str: Encoded JWT refresh token (plain text for client)
            
        Requirements: 2.7, 2.13, 14.3, 14.4, 14.5
        """
        try:
            expires_delta = timedelta(days=settings.refresh_token_expire_days)
            refresh_token = create_jwt_refresh_token(user_id, expires_delta)
            
            # Hash the refresh token before storing
            token_hash = hash_token(refresh_token)
            
            # Calculate expiration time
            expires_at = datetime.utcnow() + expires_delta
            
            # Create and store refresh token record
            refresh_token_record = RefreshToken(
                user_id=user_id,
                token_hash=token_hash,
                expires_at=expires_at,
                is_revoked=False,
                device_info=device_info,
                ip_address=ip_address
            )
            
            self.db.add(refresh_token_record)
            self.db.commit()
            
            logger.debug(f"Created and stored refresh token for user_id: {user_id}")
            return refresh_token
            
        except Exception as e:
            logger.error(f"Error creating refresh token for user_id {user_id}: {e}")
            self.db.rollback()
            raise
    
    def create_verification_token(self, email: str) -> str:
        """
        Create verification token with 10-minute expiration and hash storage.
        
        Creates a cryptographically random verification token, hashes it,
        and stores it in the database. This token is issued after successful
        OTP verification and is required for password setting.
        
        Args:
            email: Email address to associate with token
            
        Returns:
            str: Plain text verification token (for client)
            
        Requirements: 1.8, 1.9
        """
        try:
            # Generate cryptographically random token
            verification_token = generate_random_token(32)
            
            # Hash the token before storage
            token_hash = hash_token(verification_token)
            
            # Calculate expiration time (10 minutes)
            expires_at = datetime.utcnow() + timedelta(minutes=settings.verification_token_expire_minutes)
            
            # Create and store verification token record
            token_record = VerificationToken(
                email=email.lower().strip(),
                token_hash=token_hash,
                expires_at=expires_at
            )
            
            self.db.add(token_record)
            self.db.commit()
            
            logger.debug(f"Created verification token for email: {email}")
            return verification_token
            
        except Exception as e:
            logger.error(f"Error creating verification token for email {email}: {e}")
            self.db.rollback()
            raise
    
    def verify_verification_token(self, email: str, token: str) -> bool:
        """
        Verify verification token with hash comparison.
        
        Validates a verification token by:
        1. Finding the token record for the email
        2. Checking expiration
        3. Comparing hash of provided token with stored hash
        4. Removing the token after successful verification (single use)
        
        Args:
            email: Email address associated with token
            token: Plain text verification token to verify
            
        Returns:
            bool: True if token is valid, False otherwise
            
        Requirements: 1.10, 1.11
        """
        try:
            normalized_email = email.lower().strip()
            
            # Find the verification token record
            token_record = (
                self.db.query(VerificationToken)
                .filter(
                    and_(
                        VerificationToken.email == normalized_email,
                        VerificationToken.expires_at > datetime.utcnow()
                    )
                )
                .first()
            )
            
            if not token_record:
                logger.warning(f"No valid verification token found for email: {normalized_email}")
                return False
            
            # Verify token against hash
            if not verify_token(token, token_record.token_hash):
                logger.warning(f"Invalid verification token provided for email: {normalized_email}")
                return False
            
            # Remove the token after successful verification (single use)
            self.db.delete(token_record)
            self.db.commit()
            
            logger.info(f"Verification token verified successfully for email: {normalized_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying verification token for email {email}: {e}")
            self.db.rollback()
            return False
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verify refresh token with hash validation, expiration check, and revocation check.
        
        Validates a refresh token by:
        1. Decoding JWT to get user_id
        2. Validating JWT signature and expiration
        3. Checking token type is "refresh"
        4. Finding stored token record by hash
        5. Checking server-side expiration
        6. Checking revocation status
        
        Args:
            token: JWT refresh token to verify
            
        Returns:
            Optional[int]: User ID if token is valid, None otherwise
            
        Requirements: 4.4, 14.6, 14.7
        """
        try:
            # Decode JWT token
            payload = decode_jwt_token(token)
            if not payload:
                logger.warning("Invalid JWT refresh token format")
                return None
            
            # Validate token type
            if not validate_token_type(payload, "refresh"):
                logger.warning("Token is not a refresh token")
                return None
            
            # Extract user_id from payload
            user_id = int(payload.get("sub"))
            
            # Hash the token to find stored record
            token_hash = hash_token(token)
            
            # Find the refresh token record
            token_record = (
                self.db.query(RefreshToken)
                .filter(
                    and_(
                        RefreshToken.token_hash == token_hash,
                        RefreshToken.user_id == user_id,
                        RefreshToken.expires_at > datetime.utcnow(),
                        RefreshToken.is_revoked == False
                    )
                )
                .first()
            )
            
            if not token_record:
                logger.warning(f"No valid refresh token record found for user_id: {user_id}")
                return None
            
            logger.debug(f"Refresh token verified successfully for user_id: {user_id}")
            return user_id
            
        except Exception as e:
            logger.error(f"Error verifying refresh token: {e}")
            return None
    
    def revoke_refresh_token(self, token: str) -> bool:
        """
        Revoke refresh token for logout.
        
        Marks a refresh token as revoked in the database, preventing
        its future use. Used for logout functionality.
        
        Args:
            token: JWT refresh token to revoke
            
        Returns:
            bool: True if token was revoked successfully, False otherwise
            
        Requirements: 4.5, 14.8
        """
        try:
            # Hash the token to find stored record
            token_hash = hash_token(token)
            
            # Find and revoke the token
            token_record = (
                self.db.query(RefreshToken)
                .filter(RefreshToken.token_hash == token_hash)
                .first()
            )
            
            if not token_record:
                logger.warning("Refresh token not found for revocation")
                return False
            
            # Mark as revoked
            token_record.is_revoked = True
            self.db.commit()
            
            logger.info(f"Refresh token revoked for user_id: {token_record.user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error revoking refresh token: {e}")
            self.db.rollback()
            return False
    
    def rotate_refresh_token(self, old_token: str, device_info: Optional[str] = None, ip_address: Optional[str] = None) -> Optional[str]:
        """
        Rotate refresh token for enhanced security.
        
        Implements token rotation by:
        1. Verifying the old token is valid
        2. Revoking the old token
        3. Creating a new refresh token
        4. Using database transaction for atomicity
        
        Args:
            old_token: Current refresh token to rotate
            device_info: Optional device information for new token
            ip_address: Optional IP address for new token
            
        Returns:
            Optional[str]: New refresh token if rotation succeeds, None otherwise
            
        Requirements: 4.1, 4.2, 14.9
        """
        try:
            # Verify the old token is valid
            user_id = self.verify_refresh_token(old_token)
            if not user_id:
                logger.warning("Cannot rotate invalid refresh token")
                return None
            
            # Begin transaction for atomic operation
            # Revoke the old token
            old_token_hash = hash_token(old_token)
            old_token_record = (
                self.db.query(RefreshToken)
                .filter(RefreshToken.token_hash == old_token_hash)
                .first()
            )
            
            if old_token_record:
                old_token_record.is_revoked = True
            
            # Create new refresh token
            new_token = self.create_refresh_token(user_id, device_info, ip_address)
            
            logger.info(f"Refresh token rotated successfully for user_id: {user_id}")
            return new_token
            
        except Exception as e:
            logger.error(f"Error rotating refresh token: {e}")
            self.db.rollback()
            return None
    
    def cleanup_expired_tokens(self) -> int:
        """
        Remove expired verification and refresh tokens from database.
        
        Performs periodic cleanup of expired token records to prevent
        database bloat and maintain performance.
        
        Returns:
            int: Total number of expired tokens removed
        """
        try:
            # Clean up expired verification tokens
            expired_verification_count = (
                self.db.query(VerificationToken)
                .filter(VerificationToken.expires_at <= datetime.utcnow())
                .delete()
            )
            
            # Clean up expired refresh tokens
            expired_refresh_count = (
                self.db.query(RefreshToken)
                .filter(RefreshToken.expires_at <= datetime.utcnow())
                .delete()
            )
            
            self.db.commit()
            
            total_cleaned = expired_verification_count + expired_refresh_count
            
            if total_cleaned > 0:
                logger.info(f"Cleaned up {expired_verification_count} verification tokens and {expired_refresh_count} refresh tokens")
            
            return total_cleaned
            
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {e}")
            self.db.rollback()
            return 0