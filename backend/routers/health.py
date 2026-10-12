"""Liveness of what a request depends on, for a load balancer or a supervisor.

There was no health endpoint at all (audit 2026-10-12, operations): a process
whose database had gone away, or whose fan-out listener had died (2026-09-23
M-2), kept answering `/` with 200 and kept getting traffic.

Unauthenticated by necessity — probes do not log in — so it says which check
failed and nothing else: no versions, no hostnames, no error text.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from websocket_manager import manager

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    """200 when every dependency answers, 503 naming the ones that do not.

    `realtime` is "local" when no Redis is configured: a single process
    delivers in memory, which is healthy for that deployment. In shared mode it
    is "ok" only while this worker is actually reading the fan-out channel.
    """
    checks = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "down"

    if manager.shared:
        try:
            manager._redis_sync.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "down"
        checks["realtime"] = "ok" if manager.listening else "down"
    else:
        checks["realtime"] = "local"

    healthy = all(v in ("ok", "local") for v in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "degraded", "checks": checks},
    )
