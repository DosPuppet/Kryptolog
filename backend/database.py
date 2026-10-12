import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from utils.dotenv import read_dotenv_value

# Single source of truth for the database URL; Alembic (alembic/env.py) imports
# this same value. The environment wins (start scripts, CI, the test suite);
# otherwise backend/.env, which is where the generated compose password lives —
# so a bare `alembic check` or `python generate_invites.py` keeps working without
# exporting anything. The last fallback carries NO password: the compose Postgres
# no longer has a well-known one (audit 2026-10-12 K-01), and a connection that
# fails clearly beats one that quietly tries `kryptolog:kryptolog`.
SQLALCHEMY_DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or read_dotenv_value("DATABASE_URL")
    or "postgresql+psycopg://kryptolog@localhost:5432/kryptolog"
)

# check_same_thread is SQLite-only; pool_pre_ping recovers dropped connections.
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
