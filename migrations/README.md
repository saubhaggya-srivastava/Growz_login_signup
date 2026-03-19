# Database Migrations

This directory contains Alembic database migrations for the FastAPI Authentication System.

## Setup

1. Ensure you have a PostgreSQL database running
2. Set the `DATABASE_URL` environment variable in your `.env` file:
   ```
   DATABASE_URL=postgresql://username:password@localhost:5432/database_name
   ```

## Running Migrations

To apply all migrations to your database:
```bash
alembic upgrade head
```

To downgrade to a specific revision:
```bash
alembic downgrade <revision_id>
```

To see current migration status:
```bash
alembic current
```

To see migration history:
```bash
alembic history
```

## Initial Migration

The initial migration (`54ef71530326_initial_migration_with_all_models.py`) creates all the required tables:

- **users**: Main user accounts with email, verification status, and activity status
- **auth_accounts**: Multi-provider authentication records linking users to providers
- **otps**: One-time passwords for email verification (hashed storage)
- **verification_tokens**: Temporary tokens issued after OTP verification (hashed storage)
- **refresh_tokens**: Server-side refresh token management (hashed storage)

## Indexes and Constraints

The migration includes all necessary indexes for performance:
- Unique constraints on emails and provider combinations
- Foreign key relationships with CASCADE delete
- Indexes on frequently queried fields (email, provider, expires_at, etc.)

## Security Features

- All sensitive tokens (OTPs, verification tokens, refresh tokens) are stored as hashes
- Foreign key constraints ensure referential integrity
- Proper cascade deletes prevent orphaned records