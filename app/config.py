import os
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings:
    APP_NAME = os.getenv("APP_NAME", "KMS-IAM")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/kms-iam.db")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    MASTER_KEY_PATH = os.getenv("MASTER_KEY_PATH", "./data/master.key")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "./data/audit.log")

settings = Settings()