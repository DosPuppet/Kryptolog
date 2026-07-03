import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Single source of truth for the database URL. Defaults to the local Postgres
# from docker-compose.yml; point DATABASE_URL elsewhere (or at sqlite:///...)
# to override. Alembic (alembic/env.py) imports this same value.
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog",
)

# check_same_thread is SQLite-only; pool_pre_ping recovers dropped connections.
connect_args = (
    {"check_same_thread": False}
    if SQLALCHEMY_DATABASE_URL.startswith("sqlite")
    else {}
)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args, pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
