"""Configuration management using Pydantic Settings."""
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Database Configuration
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/fastapi_auth",
        alias="DATABASE_URL"
    )
    
    # JWT Configuration
    jwt_secret_key: str = Field(..., alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # OTP Configuration
    otp_expire_minutes: int = Field(default=5, alias="OTP_EXPIRE_MINUTES")
    otp_length: int = Field(default=6, alias="OTP_LENGTH")
    
    # Verification Token Configuration
    verification_token_expire_minutes: int = Field(default=10, alias="VERIFICATION_TOKEN_EXPIRE_MINUTES")
    
    # Rate Limiting Configuration
    otp_rate_limit_per_email: int = Field(default=3, alias="OTP_RATE_LIMIT_PER_EMAIL")
    login_rate_limit_per_email: int = Field(default=5, alias="LOGIN_RATE_LIMIT_PER_EMAIL")
    
    # Email Configuration
    email_provider: str = Field(default="smtp", alias="EMAIL_PROVIDER")
    smtp_host: str = Field(default="smtp.gmail.com", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_username: str = Field(default="", alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    email_from_name: str = Field(default="Authentication System", alias="EMAIL_FROM_NAME")
    sendgrid_api_key: str = Field(default="", alias="SENDGRID_API_KEY")
    aws_region: str = Field(default="", alias="AWS_REGION")
    
    # Security Configuration
    bcrypt_rounds: int = Field(default=12, alias="BCRYPT_ROUNDS")
    password_min_length: int = Field(default=8, alias="PASSWORD_MIN_LENGTH")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
