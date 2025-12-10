# config.py (deliberately insecure)
import os

DB_USER = "vulnmart"
DB_PASS = "vulnmart123"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"  # used in seed data
HARD_CODED_FLAG = "FLAG{hardcoded_creds_config}"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "devsecret")
    DATABASE = os.environ.get("DATABASE_URL", "vulnmart.db")