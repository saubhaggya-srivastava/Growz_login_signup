"""
Email service interface for the FastAPI authentication system.

This module provides an abstract interface for email sending functionality,
allowing different email providers to be plugged in without changing the
core authentication logic.

Requirements: 12.1, 12.2, 12.3
"""

import logging
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from core.config import settings


logger = logging.getLogger(__name__)


class EmailService(ABC):
    """
    Abstract base class for email service implementations.
    
    This interface defines the contract for email sending functionality
    in the authentication system. Implementations can use different
    email providers (SMTP, SendGrid, AWS SES, etc.) while maintaining
    the same interface.
    """
    
    @abstractmethod
    async def send_otp_email(self, to_email: str, otp_code: str) -> bool:
        """
        Send an OTP (One-Time Password) email to the specified address.
        
        Args:
            to_email (str): The recipient's email address
            otp_code (str): The 6-digit OTP code to send
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
            
        Raises:
            EmailDeliveryError: If email delivery fails due to provider issues
            
        Note:
            - The implementation should handle email formatting and templating
            - Error logging should be handled by the implementation
            - The method should not expose sensitive provider details in exceptions
        """
        pass
    
    @abstractmethod
    async def send_password_reset_email(self, to_email: str, reset_link: str) -> bool:
        """
        Send a password reset email to the specified address.
        
        This method is for future extensibility when password reset functionality
        is implemented.
        
        Args:
            to_email (str): The recipient's email address
            reset_link (str): The password reset link to include in the email
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
            
        Raises:
            EmailDeliveryError: If email delivery fails due to provider issues
            
        Note:
            - This is a future feature placeholder
            - The implementation should handle email formatting and templating
            - Error logging should be handled by the implementation
        """
        pass


class SMTPEmailService(EmailService):
    """
    SMTP implementation of the EmailService interface.
    
    This implementation uses SMTP to send emails through configured
    email providers like Gmail, Outlook, or custom SMTP servers.
    
    Requirements: 12.4, 12.5
    """
    
    def __init__(self, 
                 smtp_host: Optional[str] = None,
                 smtp_port: Optional[int] = None,
                 smtp_username: Optional[str] = None,
                 smtp_password: Optional[str] = None,
                 smtp_use_tls: Optional[bool] = None,
                 email_from_name: Optional[str] = None):
        """
        Initialize SMTP email service with configuration.
        
        Args:
            smtp_host: SMTP server hostname (defaults to settings)
            smtp_port: SMTP server port (defaults to settings)
            smtp_username: SMTP username (defaults to settings)
            smtp_password: SMTP password (defaults to settings)
            smtp_use_tls: Whether to use TLS encryption (defaults to settings)
            email_from_name: Display name for sender (defaults to settings)
        """
        self.smtp_host = smtp_host or settings.smtp_host
        self.smtp_port = smtp_port or settings.smtp_port
        self.smtp_username = smtp_username or settings.smtp_username
        self.smtp_password = smtp_password or settings.smtp_password
        self.smtp_use_tls = smtp_use_tls if smtp_use_tls is not None else settings.smtp_use_tls
        self.email_from_name = email_from_name or settings.email_from_name
        
        # Validate required configuration
        if not all([self.smtp_host, self.smtp_port, self.smtp_username, self.smtp_password]):
            logger.warning("SMTP configuration incomplete. Email sending may fail.")
    
    async def send_otp_email(self, to_email: str, otp_code: str) -> bool:
        """
        Send an OTP email via SMTP.
        
        Args:
            to_email: Recipient's email address
            otp_code: 6-digit OTP code to send
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Create email message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Your Verification Code"
            message["From"] = f"{self.email_from_name} <{self.smtp_username}>"
            message["To"] = to_email
            
            # Create HTML and text versions of the email
            text_content = self._create_otp_text_content(otp_code)
            html_content = self._create_otp_html_content(otp_code)
            
            # Attach both versions
            text_part = MIMEText(text_content, "plain")
            html_part = MIMEText(html_content, "html")
            
            message.attach(text_part)
            message.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()  # Enable TLS encryption
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(message)
            
            logger.info(f"OTP email sent successfully to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP recipients refused for {to_email}: {e}")
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"SMTP server disconnected: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error occurred: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending OTP email to {to_email}: {e}")
            return False
    
    async def send_password_reset_email(self, to_email: str, reset_link: str) -> bool:
        """
        Send a password reset email via SMTP.
        
        Args:
            to_email: Recipient's email address
            reset_link: Password reset link to include
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Create email message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Password Reset Request"
            message["From"] = f"{self.email_from_name} <{self.smtp_username}>"
            message["To"] = to_email
            
            # Create HTML and text versions of the email
            text_content = self._create_reset_text_content(reset_link)
            html_content = self._create_reset_html_content(reset_link)
            
            # Attach both versions
            text_part = MIMEText(text_content, "plain")
            html_part = MIMEText(html_content, "html")
            
            message.attach(text_part)
            message.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()  # Enable TLS encryption
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(message)
            
            logger.info(f"Password reset email sent successfully to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP recipients refused for {to_email}: {e}")
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"SMTP server disconnected: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error occurred: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending password reset email to {to_email}: {e}")
            return False
    
    def _create_otp_text_content(self, otp_code: str) -> str:
        """Create plain text content for OTP email."""
        return f"""
Your Verification Code

Hello,

Your verification code is: {otp_code}

This code will expire in {settings.otp_expire_minutes} minutes.

If you didn't request this code, please ignore this email.

Best regards,
The Authentication Team
        """.strip()
    
    def _create_otp_html_content(self, otp_code: str) -> str:
        """Create HTML content for OTP email."""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Your Verification Code</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }}
        .otp-code {{ 
            font-size: 32px; 
            font-weight: bold; 
            color: #007bff; 
            text-align: center; 
            padding: 20px; 
            background-color: #f8f9fa; 
            border-radius: 5px; 
            margin: 20px 0; 
            letter-spacing: 5px;
        }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Your Verification Code</h1>
        </div>
        
        <p>Hello,</p>
        
        <p>Your verification code is:</p>
        
        <div class="otp-code">{otp_code}</div>
        
        <p>This code will expire in <strong>{settings.otp_expire_minutes} minutes</strong>.</p>
        
        <p>If you didn't request this code, please ignore this email.</p>
        
        <div class="footer">
            <p>Best regards,<br>The Authentication Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()
    
    def _create_reset_text_content(self, reset_link: str) -> str:
        """Create plain text content for password reset email."""
        return f"""
Password Reset Request

Hello,

You have requested to reset your password. Click the link below to reset your password:

{reset_link}

This link will expire in 30 minutes.

If you didn't request this password reset, please ignore this email.

Best regards,
The Authentication Team
        """.strip()
    
    def _create_reset_html_content(self, reset_link: str) -> str:
        """Create HTML content for password reset email."""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Password Reset Request</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }}
        .button {{ 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 20px 0; 
        }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        
        <p>Hello,</p>
        
        <p>You have requested to reset your password. Click the button below to reset your password:</p>
        
        <p style="text-align: center;">
            <a href="{reset_link}" class="button">Reset Password</a>
        </p>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all;">{reset_link}</p>
        
        <p>This link will expire in <strong>30 minutes</strong>.</p>
        
        <p>If you didn't request this password reset, please ignore this email.</p>
        
        <div class="footer">
            <p>Best regards,<br>The Authentication Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()


# Factory function to create email service based on configuration
def create_email_service() -> EmailService:
    """
    Create an email service instance based on configuration.
    
    Returns:
        EmailService: Configured email service instance
    """
    if settings.email_provider.lower() == "smtp":
        return SMTPEmailService()
    else:
        # For now, default to SMTP. Future implementations can add other providers
        logger.warning(f"Unknown email provider '{settings.email_provider}', defaulting to SMTP")
        return SMTPEmailService()