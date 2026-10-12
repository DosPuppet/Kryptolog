"""INSERT … ON CONFLICT for whichever database the engine talks to.

Both supported dialects spell it the same way through SQLAlchemy, but each
needs its own `insert` construct. Two callers need an upsert against a unique
constraint (grants, audit 2026-09-23 F-1; conversation clears), and a
read-then-write in their place is the race those constraints exist to close.
"""

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session


def insert_for(db: Session):
    return sqlite_insert if db.get_bind().dialect.name == "sqlite" else pg_insert
