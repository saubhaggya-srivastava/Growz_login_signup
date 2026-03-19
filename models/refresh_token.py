"""RefreshToken model for server-side refresh token management."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.base import Base


class RefreshToken(Base):
    """
    RefreshToken model for storing and managing refresh tokens server-side.
    
    Refresh tokens are stored in hashed form for security and enable session
    management, revocation, and token rotation. Each token is associated with
    a user and can optionally track device and IP information for enhanced
    security monitoring.
    """
    __tablename__ = "refresh_tokens"
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Foreign key to User with index for efficient user token queries
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Hashed refresh token (never stored in plain text) with unique index
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
    
    # Revocation flag for logout and token rotation
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, 
        default=False, 
        nullable=False
    )
    
    # Optional device information for session tracking
    device_info: Mapped[Optional[str]] = mapped_column(
        String(255), 
        nullable=True
    )
    
    # Optional IP address for security monitoring
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 addresses can be up to 45 characters
        nullable=True
    )
    
    # Creation timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    # Relationship back to User
    user: Mapped["User"] = relationship(
        "User",
        back_populates="refresh_tokens"
    )
    
    def __repr__(self) -> str:
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at}, is_revoked={self.is_revoked})>"