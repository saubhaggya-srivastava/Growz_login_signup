"""AuthAccount model for multi-provider authentication."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.base import Base


class AuthAccount(Base):
    """
    AuthAccount model linking Users to specific authentication providers.
    
    This model enables multi-provider authentication by storing provider-specific
    credentials and identifiers. Each User can have multiple AuthAccount records
    for different authentication methods (email, OAuth, Apple ID, etc.).
    """
    __tablename__ = "auth_accounts"
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Foreign key to User
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    
    # Provider identification
    provider: Mapped[str] = mapped_column(
        String(50), 
        index=True, 
        nullable=False
    )
    
    provider_id: Mapped[str] = mapped_column(
        String(255), 
        index=True, 
        nullable=False
    )
    
    # Password hash (nullable for passwordless providers like OAuth)
    password_hash: Mapped[Optional[str]] = mapped_column(
        String(255), 
        nullable=True
    )
    
    # Timestamp field
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    # Relationship back to User
    user: Mapped["User"] = relationship(
        "User",
        back_populates="auth_accounts"
    )
    
    # Table constraints
    __table_args__ = (
        UniqueConstraint(
            'provider', 
            'provider_id', 
            name='uq_auth_account_provider_provider_id'
        ),
    )
    
    def __repr__(self) -> str:
        return f"<AuthAccount(id={self.id}, user_id={self.user_id}, provider='{self.provider}', provider_id='{self.provider_id}')>"