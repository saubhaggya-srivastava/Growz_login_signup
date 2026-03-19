"""
OTP service for one-time password generation, validation, and lifecycle management.

This service handles the complete OTP workflow including:
- Cryptographically secure OTP generation
- OTP hashing and storage
- Email delivery integration
- OTP validation with race condition protection
- Expired OTP cleanup
- Previous OTP invalidation

Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 3.2, 3.3, 3.5, 3.7
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

from core.config import settings
from core.security import generate_random_otp, hash_token, verify_token
from models.otp import OTP
from .email_service import EmailService


logger = logging.getLogger(__name__)


class OTPService:
    """
    Service for managing OTP (One-Time Password) operations.
    
    This service provides secure OTP generation, validation, and lifecycle
    management with proper race condition protection and cleanup mechanisms.
    
    Key Features:
    - Cryptographically secure OTP generation
    - Hashed storage (never plain text)
    - Latest-only validation logic
    - Previous OTP invalidation
    - Automatic expiration (5 minutes)
    - Periodic cleanup of expired records
    """
    
    def __init__(self, db: Session, email_service: EmailService):
        """
        Initialize OTP service with database session and email service.
        
        Args:
            db: SQLAlchemy database session
            email_service: Email service for sending OTPs
        """
        self.db = db
        self.email_service = email_service
    
    async def generate_and_send_otp(self, email: str) -> bool:
        """
        Generate a new OTP, invalidate previous ones, hash and store it, then send via email.
        
        This method implements the complete OTP generation workflow:
        1. Normalize email address
        2. Invalidate any previous unused OTPs for this email
        3. Generate cryptographically secure OTP
        4. Hash the OTP before storage
        5. Store OTP record with 5-minute expiration
        6. Send OTP via email service
        
        Args:
            email: Email address to send OTP to (will be normalized)
            
        Returns:
            bool: True if OTP was generated and email sent successfully, False otherwise
            
        Requirements: 1.2, 1.3, 1.4, 3.5, 3.6
        """
        try:
            # Normalize email (lowercase, trimmed)
            normalized_email = email.lower().strip()
            
            # Invalidate previous unused OTPs for this email
            await self.invalidate_previous_otps(normalized_email)
            
            # Generate cryptographically secure OTP
            otp_code = generate_random_otp()
            
            # Hash OTP before storage
            hashed_otp = hash_token(otp_code)
            
            # Calculate expiration time (5 minutes from now)
            expires_at = datetime.utcnow() + timedelta(minutes=settings.otp_expire_minutes)
            
            # Create and store OTP record
            otp_record = OTP(
                email=normalized_email,
                otp_code=hashed_otp,
                expires_at=expires_at,
                is_used=False
            )
            
            self.db.add(otp_record)
            self.db.commit()
            
            # Send OTP via email
            email_sent = await self.email_service.send_otp_email(normalized_email, otp_code)
            
            if email_sent:
                logger.info(f"OTP generated and sent successfully for email: {normalized_email}")
                return True
            else:
                logger.error(f"Failed to send OTP email for: {normalized_email}")
                # Note: We don't delete the OTP record even if email fails
                # This prevents timing attacks and the OTP will expire naturally
                return False
                
        except Exception as e:
            logger.error(f"Error generating and sending OTP for {email}: {e}")
            self.db.rollback()
            return False
    
    async def verify_otp(self, email: str, otp: str) -> bool:
        """
        Verify OTP against the latest stored hash for the email.
        
        This method implements secure OTP verification with race condition protection:
        1. Normalize email address
        2. Find the latest unused, non-expired OTP for this email
        3. Verify OTP against hashed value
        4. Mark OTP as used if verification succeeds
        5. Use database transaction for atomicity
        
        Args:
            email: Email address (will be normalized)
            otp: Plain text OTP to verify
            
        Returns:
            bool: True if OTP is valid and verification succeeds, False otherwise
            
        Requirements: 1.6, 1.7, 3.2, 3.3
        """
        try:
            # Normalize email
            normalized_email = email.lower().strip()
            
            # Find the latest unused, non-expired OTP for this email
            # Using latest-only logic for race condition protection
            latest_otp = (
                self.db.query(OTP)
                .filter(
                    and_(
                        OTP.email == normalized_email,
                        OTP.is_used == False,
                        OTP.expires_at > datetime.utcnow()
                    )
                )
                .order_by(desc(OTP.created_at))
                .first()
            )
            
            if not latest_otp:
                logger.warning(f"No valid OTP found for email: {normalized_email}")
                return False
            
            # Verify OTP against hashed value
            if not verify_token(otp, latest_otp.otp_code):
                logger.warning(f"Invalid OTP provided for email: {normalized_email}")
                return False
            
            # Mark OTP as used (prevents reuse)
            latest_otp.is_used = True
            self.db.commit()
            
            logger.info(f"OTP verified successfully for email: {normalized_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying OTP for {email}: {e}")
            self.db.rollback()
            return False
    
    async def invalidate_previous_otps(self, email: str) -> None:
        """
        Invalidate all previous unused OTPs for the given email.
        
        This method marks all unused OTPs for an email as used, ensuring
        that only the latest OTP can be used for verification.
        
        Args:
            email: Email address (should already be normalized)
            
        Requirements: 3.5
        """
        try:
            # Mark all unused OTPs for this email as used
            self.db.query(OTP).filter(
                and_(
                    OTP.email == email,
                    OTP.is_used == False
                )
            ).update({"is_used": True})
            
            self.db.commit()
            logger.debug(f"Invalidated previous OTPs for email: {email}")
            
        except Exception as e:
            logger.error(f"Error invalidating previous OTPs for {email}: {e}")
            self.db.rollback()
    
    async def cleanup_expired_otps(self) -> int:
        """
        Remove expired OTP records from the database.
        
        This method performs periodic cleanup of expired OTP records to
        prevent database bloat and maintain performance.
        
        Returns:
            int: Number of expired OTP records removed
            
        Requirements: 3.7
        """
        try:
            # Delete all expired OTP records
            expired_count = (
                self.db.query(OTP)
                .filter(OTP.expires_at <= datetime.utcnow())
                .delete()
            )
            
            self.db.commit()
            
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired OTP records")
            
            return expired_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired OTPs: {e}")
            self.db.rollback()
            return 0
    
    def _normalize_email(self, email: str) -> str:
        """
        Normalize email address to lowercase and trimmed.
        
        Args:
            email: Raw email address
            
        Returns:
            str: Normalized email address
        """
        return email.lower().strip()