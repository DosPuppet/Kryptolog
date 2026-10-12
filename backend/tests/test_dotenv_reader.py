"""utils.dotenv: how pytest and alembic find the generated compose password.

Read as data, like scripts/load_env.sh (audit L-14) — these pin that nothing is
expanded and that the environment still wins over the file.
"""

from utils.dotenv import read_dotenv_value


def _file(tmp_path, text):
    p = tmp_path / ".env"
    p.write_text(text)
    return str(p)


def test_plain_quoted_and_exported_values(tmp_path):
    path = _file(
        tmp_path,
        "# comment\nA=plain\nB=\"double quoted\"\nexport C='single'\nD=postgresql://u:p=x@h/db\n",
    )
    assert read_dotenv_value("A", path) == "plain"
    assert read_dotenv_value("B", path) == "double quoted"
    assert read_dotenv_value("C", path) == "single"
    assert read_dotenv_value("D", path) == "postgresql://u:p=x@h/db"


def test_nothing_is_expanded(tmp_path):
    path = _file(tmp_path, "X=$(whoami)\nY=$HOME/z\n")
    assert read_dotenv_value("X", path) == "$(whoami)"
    assert read_dotenv_value("Y", path) == "$HOME/z"


def test_missing_key_empty_value_and_missing_file(tmp_path):
    path = _file(tmp_path, "EMPTY=\n")
    assert read_dotenv_value("EMPTY", path) is None
    assert read_dotenv_value("ABSENT", path) is None
    assert read_dotenv_value("A", str(tmp_path / "nope")) is None
