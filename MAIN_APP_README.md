# FastAPI Authentication System - Main Application

## Overview

This is the main entry point for the FastAPI Authentication System. The `main.py` file creates and configures a production-ready FastAPI application with comprehensive authentication features.

## Features

### 🔐 Authentication System
- Email-based user registration with OTP verification
- Password-based login with JWT tokens
- Refresh token rotation for enhanced security
- Secure logout with token revocation

### 🛡️ Security Features
- **Rate Limiting**: Prevents brute force attacks on login and OTP endpoints
- **CORS Middleware**: Configurable cross-origin resource sharing
- **Trusted Host Middleware**: Protection against host header attacks
- **Exception Handling**: Comprehensive error handling with security-conscious responses
- **Password Hashing**: bcrypt with configurable rounds
- **Token Security**: JWT with proper expiration and type validation

### 📊 Monitoring & Health
- Health check endpoint (`/health`)
- Comprehensive logging with structured format
- Application lifecycle management
- Database connection monitoring

### 🏗️ Architecture
- **Clean Architecture**: Separation of concerns with layers
- **Dependency Injection**: FastAPI's built-in DI system
- **Database Integration**: SQLAlchemy ORM with Alembic migrations
- **Configuration Management**: Environment-based settings with Pydantic

## Application Structure

```
main.py                 # Main FastAPI application
├── Lifespan Management # Startup/shutdown handling
├── Middleware Stack    # CORS, Rate Limiting, Security
├── Exception Handlers  # Centralized error handling
├── Route Registration  # Authentication endpoints
└── Health Endpoints    # Monitoring and status
```

## Endpoints

### Core Endpoints
- `GET /` - API information and endpoint listing
- `GET /health` - Health check for monitoring
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation (ReDoc)

### Authentication Endpoints
- `POST /auth/send-otp` - Send OTP for registration
- `POST /auth/verify-otp` - Verify OTP and get verification token
- `POST /auth/set-password` - Complete registration with password
- `POST /auth/login` - Login with email/password
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout and revoke tokens

## Configuration

The application uses environment variables for configuration. Required variables:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/fastapi_auth

# JWT Security
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# OTP Configuration
OTP_EXPIRE_MINUTES=5
OTP_LENGTH=6

# Rate Limiting
OTP_RATE_LIMIT_PER_EMAIL=3
LOGIN_RATE_LIMIT_PER_EMAIL=5

# Email Configuration (choose provider)
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## Running the Application

### Method 1: Direct Python
```bash
python main.py
```

### Method 2: Using Uvicorn
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Method 3: Using the Runner Script
```bash
python run_app.py
```

## Middleware Stack

The application includes several middleware layers for security and functionality:

1. **SlowAPI Middleware**: Rate limiting based on IP address
2. **CORS Middleware**: Cross-origin request handling
3. **Trusted Host Middleware**: Host header validation
4. **Exception Handlers**: Centralized error processing

## Database Integration

The application automatically:
- Creates database tables on startup using SQLAlchemy metadata
- Manages database connections with connection pooling
- Handles database cleanup on shutdown
- Supports database migrations via Alembic

## Security Considerations

### Production Deployment
- Set `allow_origins` in CORS middleware to specific domains
- Configure `allowed_hosts` in TrustedHost middleware
- Use HTTPS in production
- Set appropriate rate limits
- Use strong JWT secret keys
- Configure database connection limits

### Environment Variables
- Never commit `.env` files to version control
- Use strong, unique JWT secret keys
- Rotate secrets regularly
- Use database connection strings with authentication

## Monitoring

### Health Check
The `/health` endpoint provides:
```json
{
  "status": "healthy",
  "service": "FastAPI Authentication System",
  "version": "1.0.0"
}
```

### Logging
The application logs:
- Application startup/shutdown events
- Database connection status
- Authentication attempts (without sensitive data)
- Rate limiting violations
- Error conditions

## Development

### Testing the Application
```bash
python test_main.py
```

### API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

### Development Mode
Set `reload=True` in uvicorn configuration for auto-reload on file changes.

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Check Python path and module structure

2. **Database Connection Errors**
   - Verify DATABASE_URL is correct
   - Ensure database server is running
   - Check database credentials and permissions

3. **JWT Errors**
   - Ensure JWT_SECRET_KEY is set
   - Verify JWT_ALGORITHM is supported

4. **Rate Limiting Issues**
   - Check slowapi installation
   - Verify rate limit configuration

### Debug Mode
Enable SQL query logging by setting `echo=True` in the database engine configuration.

## Requirements Compliance

This implementation satisfies the following requirements:
- **11.1**: Clean architecture with separated layers
- **11.2**: Thin route handlers with service delegation  
- **11.3**: Dependency injection for database sessions
- **8.1-8.6**: All required API endpoints
- **9.1-9.11**: Security best practices
- **7.1-7.2**: SQLAlchemy ORM and Alembic migrations

## Next Steps

After running the main application:
1. Test all authentication endpoints
2. Configure production environment variables
3. Set up database migrations
4. Configure email service provider
5. Set up monitoring and logging
6. Deploy with proper security configurations