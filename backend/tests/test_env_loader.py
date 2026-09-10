"""The .env file is parsed as data, never executed (audit L-14).

`start_all.sh` and `backend/run_dev.sh` used to load configuration with
`set -a; source .env; set +a`, which RUNS the file as bash. An env file is not
code — it holds a secret pasted from generate_server_keys.py, a connection
string from a secret manager, whatever a deploy pipeline wrote — so a `$(...)`
anywhere in it executed with the whole stack about to start.

These tests live under backend/tests because pytest is the only test harness in
the repo; there is no shell CI job. They exercise scripts/load_env.sh at the
repo root, not the backend app, and they are the reason nobody can quietly
"simplify" that parser back into a `source`.
"""

import subprocess
from pathlib import Path

import pytest

LOADER = Path(__file__).resolve().parents[2] / "scripts" / "load_env.sh"


def load(env_text, tmp_path, want=()):
    """Parse `env_text` with the real loader; return the requested variables."""
    env_file = tmp_path / ".env"
    env_file.write_text(env_text)
    script = f"source {LOADER}; kryptolog_load_env {env_file};\n"
    # NUL-separated so values containing spaces or newlines survive the trip.
    script += "".join(f'printf "%s\\0" "${{{name}-<unset>}}";\n' for name in want)
    proc = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    values = proc.stdout.split("\0")[:-1] if want else []
    return dict(zip(want, values)), proc.stderr


def test_loader_exists():
    assert LOADER.is_file(), f"{LOADER} is missing; both startup scripts source it"


def test_command_substitution_is_not_executed(tmp_path):
    """The finding itself: a payload in a value must never run."""
    marker = tmp_path / "executed"
    values, _ = load(
        f"KRYPTOLOG_JWT_SECRET=$(touch {marker})\n", tmp_path, ["KRYPTOLOG_JWT_SECRET"]
    )
    assert not marker.exists(), "the .env payload EXECUTED — L-14 has regressed"
    assert values["KRYPTOLOG_JWT_SECRET"] == f"$(touch {marker})"


def test_backticks_are_not_executed(tmp_path):
    marker = tmp_path / "executed"
    values, _ = load(f"SECRET=`touch {marker}`\n", tmp_path, ["SECRET"])
    assert not marker.exists(), "backtick substitution EXECUTED — L-14 has regressed"
    assert values["SECRET"] == f"`touch {marker}`"


def test_trailing_command_is_not_executed(tmp_path):
    marker = tmp_path / "executed"
    values, _ = load(f"SECRET=value; touch {marker}\n", tmp_path, ["SECRET"])
    assert not marker.exists(), "a trailing command EXECUTED — L-14 has regressed"
    assert values["SECRET"] == f"value; touch {marker}"


def test_no_variable_interpolation(tmp_path):
    """`source` would expand $HOME here. A value is 8 literal characters."""
    values, _ = load('KEY="$HOME/x"\n', tmp_path, ["KEY"])
    assert values["KEY"] == "$HOME/x"


def test_angle_bracket_placeholder_loads_instead_of_redirecting(tmp_path):
    """The placeholder shipped in .env.example is not even hostile.

    Under `source`, `VAPID_PUBLIC_KEY=<your-vapid-public-key>` is a redirection
    and aborts the whole file with a syntax error.
    """
    values, _ = load(
        "VAPID_PUBLIC_KEY=<your-vapid-public-key>\nAFTER=reached\n",
        tmp_path,
        ["VAPID_PUBLIC_KEY", "AFTER"],
    )
    assert values["VAPID_PUBLIC_KEY"] == "<your-vapid-public-key>"
    assert values["AFTER"] == "reached", "parsing stopped at the placeholder line"


@pytest.mark.parametrize(
    "line,expected",
    [
        (
            "DB=postgresql+psycopg://u:p@localhost:5432/kryptolog",
            "postgresql+psycopg://u:p@localhost:5432/kryptolog",
        ),
        ("B64=aGVsbG8td29ybGQ=", "aGVsbG8td29ybGQ="),  # '=' inside the value
        ("HASH=postgres://user:pa#ss@host", "postgres://user:pa#ss@host"),  # bare '#' kept
        ("INLINE=real # comment", "real"),  # ' #' is a comment
        ('DQ="spaced "', "spaced "),  # quoted: verbatim
        ("SQ='single $HOME'", "single $HOME"),
        ('HASHQ="#notacomment"', "#notacomment"),
        ("export EXPORTED=works", "works"),
        ("  INDENTED=trimmed  ", "trimmed"),
        ("EMPTY=", ""),
    ],
)
def test_real_world_values_round_trip(line, expected, tmp_path):
    """The formats the shipped .env.example actually uses must be unchanged."""
    name = line.replace("export ", "").strip().split("=")[0]
    values, _ = load(line + "\n", tmp_path, [name])
    assert values[name] == expected


def test_value_on_a_final_line_without_a_newline(tmp_path):
    values, _ = load("LAST=tail", tmp_path, ["LAST"])
    assert values["LAST"] == "tail"


def test_malformed_lines_are_reported_and_skipped(tmp_path):
    """A bad line must not abort the file — the good ones after it still load."""
    values, stderr = load(
        "BAD-NAME=nope\n=nokey\nnoequals\nGOOD=loaded\n",
        tmp_path,
        ["GOOD", "BAD_NAME"],
    )
    assert values["GOOD"] == "loaded"
    assert values["BAD_NAME"] == "<unset>"
    assert stderr.count("skipped") == 3, stderr


def test_startup_scripts_do_not_source_the_env_file():
    """Guard the call sites too: the parser only helps if it is what runs.

    Comments are stripped first — both scripts quote the old `source ... .env`
    line to explain what it allowed through, and that explanation is the part
    worth keeping.
    """
    root = Path(__file__).resolve().parents[2]
    for script in (root / "start_all.sh", root / "backend" / "run_dev.sh"):
        code = "\n".join(
            line for line in script.read_text().splitlines() if not line.lstrip().startswith("#")
        )
        assert "kryptolog_load_env" in code, f"{script.name} no longer uses the parser"
        for forbidden in ("source .env", "source backend/.env", ". .env"):
            assert forbidden not in code, f"{script.name} executes the env file again"
