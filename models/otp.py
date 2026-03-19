"""OTP model for one-time password verification."""
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column
from db.base import Base


class OTP(Base):
    """
    OTP model for storing one-time passwords used in email verification.
    
    OTPs are hashed before storage for security and have a 5-minute expiration.
    Each OTP can only be used once and previous unused OTPs are invalidated
    when a new OTP is requested for the same email.
    """
    __tablename__ = "otps"
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Email field with index for efficient lookup
    email: Mapped[str] = mapped_column(
        String(255), 
        index=True, 
        nullable=False
    )
    
    # Hashed OTP code (never stored in plain text)
    otp_code: Mapped[str] = mapped_column(
        String(255), 
        nullable=False
    )
    
    # Expiration timestamp with index for efficient cleanup queries
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False, 
        index=True
    )
    
    # Usage flag to prevent OTP reuse
    is_used: Mapped[bool] = mapped_column(
        Boolean, 
        default=False, 
        nullable=False
    )
    
    # Creation timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    def __repr__(self) -> str:
        return f"<OTP(id={self.id}, email='{self.email}', expires_at={self.expires_at}, is_used={self.is_used})>"