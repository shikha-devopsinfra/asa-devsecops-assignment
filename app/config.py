import os
import secrets


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("SECRET_KEY must be set in production")
    SECRET_KEY = secrets.token_urlsafe(32)

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

DB_USER = os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

NOTIFY_SERVICE_URL = os.getenv(
    "NOTIFY_SERVICE_URL",
    "http://localhost:3001",
)

PUBLIC_BASE_URL = os.getenv(
    "PUBLIC_BASE_URL",
    "http://localhost:8000",
)