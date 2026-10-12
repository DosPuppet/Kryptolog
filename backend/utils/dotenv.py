"""Read one value from backend/.env, as data.

The compose services stopped having a well-known password (audit 2026-10-12
K-01), and the two developer commands that never went through a start script —
`pytest` and `alembic` — had been relying on the default URL that carried it.
They now look in backend/.env, which is where scripts/init_env.sh put the real
one.

Deliberately minimal and never executing anything, in the spirit of
scripts/load_env.sh (audit L-14): `KEY=VALUE`, an optional `export ` prefix and
one layer of surrounding quotes. No expansion, no escapes, no multi-line values.
The environment always wins; this is only consulted when it has nothing.
"""

import os

DOTENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")


def read_dotenv_value(key: str, path: str = DOTENV_PATH) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("export "):
                    line = line[len("export ") :].lstrip()
                name, sep, value = line.partition("=")
                if sep and name.strip() == key:
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                        value = value[1:-1]
                    return value or None
    except OSError:
        return None
    return None
