"""normalize existing usernames to NFKC

Revision ID: f6a7b8c9d0e5
Revises: e5f6a7b8c9d4
Create Date: 2026-09-03 09:00:00.000000

security/usernames.py now normalizes to NFKC on write (audit M-9), so that
`ａlice` in fullwidth and `alice` are the same name rather than two accounts
that render identically in a recipient list.

Rows written before that are still in whatever form they arrived in, and the
uniqueness comparison only holds if every stored value is in the same form —
otherwise a normalized new name and an un-normalized old one can differ as
strings while rendering identically, which is exactly the state the fix exists
to prevent.

Whitespace is collapsed here too, matching normalize_username: leading, trailing
and repeated spaces are invisible in every client that renders the name.

Deliberately NOT applied retroactively: the script-mixing rule. A name that
would be refused on write today does not violate any constraint, and renaming
somebody's display name is an operator decision, not a migration's. Such names
are reported below so an operator can act on them, and any later write to that
account has to satisfy the new rule.
"""
import unicodedata
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e5'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _normalize(value: str) -> str:
    """The storage-shape half of security.usernames.normalize_username.

    Inlined rather than imported: a migration has to keep doing what it did the
    day it was written, and application code moves.
    """
    return " ".join(unicodedata.normalize("NFKC", value).split())


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT address, username FROM users WHERE username IS NOT NULL"
    )).fetchall()

    changes = {}       # address -> new username
    final = {}         # lower(new username) -> [address, ...]
    for row in rows:
        normalized = _normalize(row.username)
        if normalized != row.username:
            changes[row.address] = normalized
        final.setdefault((normalized or row.username).lower(), []).append(row.address)

    # Normalizing can MERGE two previously-distinct names ("ａlice" and "alice"),
    # which the functional unique index would then reject mid-update. Detect it
    # first and name the exact rows, rather than failing halfway through with a
    # constraint error that says nothing useful.
    collisions = {name: addrs for name, addrs in final.items() if len(addrs) > 1}
    if collisions:
        detail = "; ".join(
            f"{name!r} held by {', '.join(addrs)}" for name, addrs in sorted(collisions.items())
        )
        raise RuntimeError(
            "Cannot normalize usernames: these names collide once normalized — "
            f"{detail}. Rename all but one holder of each "
            "(UPDATE users SET username = ... WHERE address = ...), then re-run "
            "this migration."
        )

    for address, username in changes.items():
        conn.execute(
            sa.text("UPDATE users SET username = :u WHERE address = :a"),
            {"u": username, "a": address},
        )


def downgrade() -> None:
    """Downgrade schema.

    Nothing to undo: the normalized form is a strictly better version of the
    same name, and the originals are not recoverable from it.
    """
