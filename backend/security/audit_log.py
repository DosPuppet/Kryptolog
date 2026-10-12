"""Security audit trail: one JSON line per security-relevant event.

Nothing security-relevant was logged at all (audit 2026-09-11 M-3): not a login,
not a failed one, not a key change, a share, a revocation, a workflow decision
or a refused request. Only uvicorn's access log existed, with no way to tie a
line to a request. So there was nothing to detect an incident with and nothing
to reconstruct one from afterwards.

Every event is a single JSON object on the `kryptolog.audit` logger, which
propagates nowhere else, so a deployment can ship this stream to its SIEM
without the rest of the application log (`KRYPTOLOG_AUDIT_LOG` writes it to a
file instead of stderr). Fields:

    ts          UTC, ISO 8601 with offset
    event       dotted name, e.g. "auth.login", "secret.share", "http.denied"
    outcome     "ok" or "refused"
    actor       the acting identity, shortened (see `short`)
    ip          the client as uvicorn resolved it (dependencies.client_ip)
    request_id  the X-Request-ID this response carried
    ...         event-specific fields

What is NEVER logged: content, ciphertext, wrapped keys, signatures, tokens,
usernames, or a full address. An address is a 2 624-character public key; the
first 16 hex characters identify it for an investigator without turning the
log into a copy of the directory.
"""

import json
import logging
import os
import sys

from utils.clock import to_wire_utc, utcnow_naive

audit_logger = logging.getLogger("kryptolog.audit")

ADDRESS_PREFIX = 16


def short(address: str | None) -> str | None:
    return address.lower()[:ADDRESS_PREFIX] if address else None


def configure() -> None:
    """Give the audit logger its own handler, emitting the JSON lines as-is.

    Idempotent. `propagate = False` keeps these lines out of the root handler,
    which would prefix them and interleave them with debugging output.
    """
    if getattr(audit_logger, "_kryptolog_configured", False):
        return
    path = os.getenv("KRYPTOLOG_AUDIT_LOG")
    handler = logging.FileHandler(path) if path else logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_logger._kryptolog_configured = True


def audit_event(event: str, *, request=None, actor=None, outcome: str = "ok", **fields) -> None:
    """Record one security event. Never raises: an audit failure must not turn
    into a failed login or a refused share."""
    try:
        record = {
            "ts": to_wire_utc(utcnow_naive()),
            "event": event,
            "outcome": outcome,
            "actor": short(actor),
        }
        if request is not None:
            from dependencies import client_ip

            record["ip"] = client_ip(request)
            record["request_id"] = getattr(request.state, "request_id", None)
        record.update(fields)
        audit_logger.info(json.dumps(record, default=str, separators=(",", ":")))
    except Exception:  # pragma: no cover - last-resort guard
        logging.getLogger("kryptolog.main").exception("audit event %s could not be recorded", event)
