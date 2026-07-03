"""Alembic environment configuration.

Imports the SQLAlchemy models and database engine from the Kryptolog backend
so that autogenerate can detect schema changes.
"""
import sys
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Ensure the backend root is on sys.path so we can import models/database
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import the application's Base metadata for autogenerate support
from models import Base
target_metadata = Base.metadata

# Alembic Config object
config = context.config

# The app's DATABASE_URL is the single source of truth — override whatever
# placeholder alembic.ini carries so the app engine and Alembic always target
# the same database (incl. the startup upgrade in main.py).
from database import SQLALCHEMY_DATABASE_URL
config.set_main_option("sqlalchemy.url", SQLALCHEMY_DATABASE_URL)

# Batch mode is only needed for SQLite's limited ALTER TABLE; on Postgres it
# must be off so migrations execute plain DDL.
is_sqlite = SQLALCHEMY_DATABASE_URL.startswith("sqlite")

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL (no Engine needed).
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=is_sqlite,  # SQLite-only ALTER TABLE workaround
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=is_sqlite,  # SQLite-only ALTER TABLE workaround
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
