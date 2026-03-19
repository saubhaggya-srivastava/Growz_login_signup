"""
Authentication service for user registration and login workflows.

This service orchestrates the complete authentication flows including:
- Email-based user registration with OTP verification
- Password-based user login with token generation
- User account management and validation
- Integration with OTP and token services
- Atomic transaction handling for user creation

Requirements: 1.1, 1.8, 1.10, 1.11, 1.12, 1.13, 1.14, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 5.1, 5.4, 5.5, 7.18
"""

import logging
from typing import Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_

from core.config import settings
from core.security import hash_password, verify_password
from models.user import User
from models.auth_account import AuthAccount
from .otp_service import OTPService
from .token_service import TokenService


logger = logging.getLogger(__name__)


class AuthService:
    """
    Service for managing authentication workflows and user account operations.
    
    This service orchestrates the complete authentication flows including:
    - Multi-step email registration (OTP → verification token → password setting)
    - Password-based login with comprehensive validation
    - User account status verification
    - Integration with OTP and token services
    - Atomic database transactions for data consistency
    - Account enumeration protection through generic responses
    
    Key Security Features:
    - Email normalization for consistent lookups
    - Generic error messages to prevent account enumeration
    - User status validation (is_active, is_verified)
    - Password verification with bcrypt
    - Atomic transactions for user creation
    - Integration with rate limiting and audit logging
    """
    
    def __init__(self, db: Session, otp_service: OTPService, token_service: TokenService):
        """
        Initialize authentication service with required dependencies.
        
        Args:
            db: SQLAlchemy database session
            otp_service: OTP service for verification workflows
            token_service: Token service for JWT and verification token management
        """
        self.db = db
        self.otp_service = otp_service
        self.token_service = token_service
    
    def normalize_email(self, email: str) -> str:
        """
        Normalize email address to lowercase and trimmed format.
        
        Ensures consistent email handling across all authentication operations
        by converting to lowercase and removing leading/trailing whitespace.
        
        Args:
            email: Raw email address
            
        Returns:
            str: Normalized email address (lowercase, trimmed)
            
        Requirements: 1.1, 2.1, 7.18
        """
        return email.lower().strip()
    
    async def initiate_registration(self, email: str) -> bool:
        """
        Initiate user registration by sending OTP to email address.
        
        This method starts the registration workflow by delegating OTP generation
        and sending to the OTP service. Always returns True to prevent account
        enumeration attacks - actual success/failure is not revealed to the client.
        
        Args:
            email: Email address for registration (will be normalized)
            
        Returns:
            bool: Always True (account enumeration protection)
            
        Requirements: 1.2, 1.3, 1.4, 5.1, 5.2
        """
        try:
            normalized_email = self.normalize_email(email)
            
            # Delegate to OTP service for generation and sending
            await self.otp_service.generate_and_send_otp(normalized_email)
            
            # Always return True for account enumeration protection
            # Actual success/failure is logged but not exposed to client
            logger.info(f"Registration initiated for email: {normalized_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error initiating registration for {email}: {e}")
            # Still return True to prevent information leakage
            return True
    
    async def verify_otp_and_issue_token(self, email: str, otp: str) -> Optional[str]:
        """
        Verify OTP and issue verification token for password setting.
        
        This method handles the second step of registration by:
        1. Delegating OTP verification to OTP service
        2. Generating verification token if OTP is valid
        3. Returning verification token for password setting step
        
        Args:
            email: Email address (will be normalized)
            otp: OTP code to verify
            
        Returns:
            Optional[str]: Verification token if OTP is valid, None otherwise
            
        Requirements: 1.6, 1.7, 1.8, 1.9
        """
        try:
            normalized_email = self.normalize_email(email)
            
            # Verify OTP through OTP service
            otp_valid = await self.otp_service.verify_otp(normalized_email, otp)
            
            if not otp_valid:
                logger.warning(f"Invalid OTP verification attempt for email: {normalized_email}")
                return None
            
            # Generate verification token for password setting
            verification_token = self.token_service.create_verification_token(normalized_email)
            
            logger.info(f"OTP verified and verification token issued for email: {normalized_email}")
            return verification_token
            
        except Exception as e:
            logger.error(f"Error verifying OTP and issuing token for {email}: {e}")
            return None
    
    async def complete_registration(self, email: str, password: str, verification_token: str) -> Optional[User]:
        """
        Complete user registration by creating User and AuthAccount records.
        
        This method handles the final step of registration with atomic transaction:
        1. Verify verification token is valid
        2. Check if user already exists (prevent duplicates)
        3. Hash password using bcrypt
        4. Create User record with verified status
        5. Create AuthAccount record with email provider
        6. Use database transaction for atomicity
        
        Args:
            email: Email address (will be normalized)
            password: Plain text password to hash and store
            verification_token: Verification token from OTP verification step
            
        Returns:
            Optional[User]: Created User object if successful, None otherwise
            
        Requirements: 1.10, 1.11, 1.12, 1.13, 1.14, 1.15
        """
        try:
            normalized_email = self.normalize_email(email)
            
            # Verify verification token
            token_valid = self.token_service.verify_verification_token(normalized_email, verification_token)
            if not token_valid:
                logger.warning(f"Invalid verification token for email: {normalized_email}")
                return None
            
            # Check if user already exists
            existing_user = (
                self.db.query(User)
                .filter(User.email == normalized_email)
                .first()
            )
            
            if existing_user:
                logger.warning(f"User already exists for email: {normalized_email}")
                return None
            
            # Hash password
            password_hash = hash_password(password)
            
            # Begin atomic transaction for user creation
            try:
                # Create User record
                user = User(
                    email=normalized_email,
                    is_active=True,
                    is_verified=True  # Email is verified through OTP process
                )
                self.db.add(user)
                self.db.flush()  # Get user.id for AuthAccount
                
                # Create AuthAccount record for email provider
                auth_account = AuthAccount(
                    user_id=user.id,
                    provider="email",
                    provider_id=normalized_email,
                    password_hash=password_hash
                )
                self.db.add(auth_account)
                
                # Commit transaction
                self.db.commit()
                
                logger.info(f"User registration completed successfully for email: {normalized_email}")
                return user
                
            except Exception as e:
                self.db.rollback()
                logger.error(f"Database error during user creation for {normalized_email}: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Error completing registration for {email}: {e}")
            return None
    
    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user credentials and return User object if valid.
        
        This method performs comprehensive authentication validation:
        1. Normalize email address
        2. Find user by email
        3. Find email provider AuthAccount
        4. Verify password against stored hash
        5. Check user is active and verified
        6. Return User object if all checks pass
        
        Args:
            email: Email address (will be normalized)
            password: Plain text password to verify
            
        Returns:
            Optional[User]: User object if authentication succeeds, None otherwise
            
        Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.10
        """
        try:
            normalized_email = self.normalize_email(email)
            
            # Find user by email
            user = (
                self.db.query(User)
                .filter(User.email == normalized_email)
                .first()
            )
            
            if not user:
                logger.warning(f"Authentication attempt for non-existent user: {normalized_email}")
                return None
            
            # Check user status
            if not user.is_active:
                logger.warning(f"Authentication attempt for inactive user: {normalized_email}")
                return None
            
            if not user.is_verified:
                logger.warning(f"Authentication attempt for unverified user: {normalized_email}")
                return None
            
            # Find email provider AuthAccount
            auth_account = (
                self.db.query(AuthAccount)
                .filter(
                    and_(
                        AuthAccount.user_id == user.id,
                        AuthAccount.provider == "email",
                        AuthAccount.provider_id == normalized_email
                    )
                )
                .first()
            )
            
            if not auth_account or not auth_account.password_hash:
                logger.warning(f"No email auth account found for user: {normalized_email}")
                return None
            
            # Verify password
            if not verify_password(password, auth_account.password_hash):
                logger.warning(f"Invalid password for user: {normalized_email}")
                return None
            
            logger.info(f"User authenticated successfully: {normalized_email}")
            return user
            
        except Exception as e:
            logger.error(f"Error authenticating user {email}: {e}")
            return None
    
    async def login(self, email: str, password: str) -> Optional[Tuple[str, str]]:
        """
        Login user and return access and refresh tokens.
        
        This method orchestrates the complete login workflow:
        1. Authenticate user credentials
        2. Generate access token (30 minutes)
        3. Generate refresh token (7 days)
        4. Return both tokens for client use
        
        Args:
            email: Email address
            password: Plain text password
            
        Returns:
            Optional[Tuple[str, str]]: (access_token, refresh_token) if login succeeds, None otherwise
            
        Requirements: 2.6, 2.7, 2.8, 2.11, 2.12, 2.13
        """
        try:
            # Authenticate user
            user = await self.authenticate_user(email, password)
            if not user:
                # Return None for any authentication failure (generic error)
                return None
            
            # Generate access token
            access_token = self.token_service.create_access_token(user.id)
            
            # Generate refresh token
            refresh_token = self.token_service.create_refresh_token(user.id)
            
            logger.info(f"Login successful for user: {user.email}")
            return (access_token, refresh_token)
            
        except Exception as e:
            logger.error(f"Error during login for {email}: {e}")
            return None