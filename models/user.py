"""User model for the authentication system."""
from datetime import datetime
from typing import List
from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.base import Base


class User(Base):
    """
    User model representing a registered account in the system.
    
    A User can have multiple authentication providers through Auth_Account records
    and multiple refresh tokens for session management.
    """
    __tablename__ = "users"
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Email field with unique constraint and index
    email: Mapped[str] = mapped_column(
        String(255), 
        unique=True, 
        index=True, 
        nullable=False
    )
    
    # Account status fields
    is_active: Mapped[bool] = mapped_column(
        Boolean, 
        default=True, 
        nullable=False
    )
    
    is_verified: Mapped[bool] = mapped_column(
        Boolean, 
        default=False, 
        nullable=False
    )
    
    # Timestamp field
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    # Relationships
    auth_accounts: Mapped[List["AuthAccount"]] = relationship(
        "AuthAccount",
        back_populates="user", 
        cascade="all, delete-orphan"
    )
    
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user", 
        cascade="all, delete-orphan"
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', is_active={self.is_active}, is_verified={self.is_verified})>"