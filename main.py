"""
FastAPI Authentication System - Main Application

This is the main entry point for the FastAPI authentication system.
It initializes the FastAPI application, registers routes, middleware,
exception handlers, and configures the database connection.

Requirements: 11.1, 11.2, 11.3
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from core.config import settings
from db.base import engine, Base
from routes import auth_router
from utils.exception_handlers import register_exception_handlers

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events for the FastAPI application.
    Creates database tables on startup and performs cleanup on shutdown.
    """
    # Startup
    logger.info("Starting FastAPI Authentication System...")
    
    # Create database tables
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down FastAPI Authentication System...")
    
    # Close database connections
    try:
        engine.dispose()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")
    
    logger.info("Application shutdown complete")


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        FastAPI: Configured FastAPI application instance
    """
    # Create FastAPI application with metadata
    app = FastAPI(
        title="FastAPI Authentication System",
        description="Production-grade authentication system with email-based signup, OTP verification, and JWT tokens",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )
    
    # Add rate limiting middleware
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    
    # Add trusted host middleware for production security
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure appropriately for production
    )
    
    # Register exception handlers
    register_exception_handlers(app)
    
    # Register routers
    app.include_router(auth_router)
    
    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        """
        Health check endpoint.
        
        Returns:
            dict: Application health status
        """
        return {
            "status": "healthy",
            "service": "FastAPI Authentication System",
            "version": "1.0.0"
        }
    
    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        """
        Root endpoint with API information.
        
        Returns:
            dict: API information and available endpoints
        """
        return {
            "message": "FastAPI Authentication System",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health",
            "auth_endpoints": {
                "send_otp": "POST /auth/send-otp",
                "verify_otp": "POST /auth/verify-otp", 
                "set_password": "POST /auth/set-password",
                "login": "POST /auth/login",
                "refresh": "POST /auth/refresh",
                "logout": "POST /auth/logout"
            }
        }
    
    logger.info("FastAPI application configured successfully")
    return app


# Create the application instance
app = create_application()


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Set to False in production
        log_level="info"
    )