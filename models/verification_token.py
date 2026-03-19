"""VerificationToken model for temporary verification tokens."""
from datetime import datetime
from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from db.base import Base


class VerificationToken(Base):
    """
    VerificationToken model for storing temporary verification tokens.
    
    These tokens are issued after successful OTP verification and are required
    for password setting to complete registration. Tokens are hashed before
    storage for security and have a 10-minute expiration.
    """
    __tablename__ = "verification_tokens"
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Email field for token association
    email: Mapped[str] = mapped_column(
        String(255), 
        nullable=False
    )
    
    # Hashed token (never stored in plain text) - renamed from 'token' to 'token_hash'
    # for security clarity as specified in the task requirements
    token_hash: Mapped[str] = mapped_column(
        String(255), 
        unique=True, 
        index=True, 
        nullable=False
    )
    
    # Expiration timestamp with index for efficient cleanup queries
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False, 
        index=True
    )
    
    # Creation timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    def __repr__(self) -> str:
        return f"<VerificationToken(id={self.id}, email='{self.email}', expires_at={self.expires_at})>"