"""Azure SQL activity logging for the VIHTRN duty calculation service.

Design notes
------------
* **Never blocks the request path.** ``log_event`` only puts a small dataclass
  on an in-memory queue and returns. A background daemon thread owns the
  database connection and drains that queue in batches. A slow or sleeping
  database can therefore never delay the response back to CargoWise, and can
  never turn a successful duty calculation into a 500.

* **Fails open.** Every database error is caught, counted and logged to stdout.
  If Azure SQL is unreachable the app keeps calculating duty and pushing to
  CargoWise; only the audit rows are lost, and the drop is recorded in the
  process log so it is visible in Render's log stream.

* **pymssql, not pyodbc.** Render's native Python runtime gives you no root, so
  you cannot ``apt-get install msodbcsql18``. pymssql ships manylinux wheels
  with FreeTDS statically linked, so it installs from requirements.txt with no
  system packages. (If you later move to a Docker deploy or to Azure Container
  Apps, pyodbc + managed identity becomes the better choice.)

* **Serverless auto-pause is expected.** The free General Purpose Serverless
  tier pauses the database when idle; the first connection afterwards can take
  30-60 seconds or fail outright. The writer retries with backoff and a long
  login timeout instead of treating that as an error.

Environment variables
---------------------
SQL_SERVER        e.g. db-server-link-hv-08.database.windows.net
SQL_DATABASE      e.g. db-server-link-hv
SQL_USERNAME      e.g. vih_duty_app
SQL_PASSWORD      the password for that login
SQL_LOG_ENABLED   "false" to disable logging entirely (default "true")
SQL_LOG_QUEUE_MAX max queued rows before new ones are dropped (default 10000)
SQL_LOG_BATCH     rows per INSERT batch (default 50)
"""

from __future__ import annotations

import atexit
import hashlib
import logging
import os
import queue
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

logger = logging.getLogger("vih_duty_calculation.db")

try:
    import pymssql
except ImportError:  # pragma: no cover - surfaced at startup instead
    pymssql = None


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

SQL_SERVER = os.environ.get("SQL_SERVER", "")
SQL_DATABASE = os.environ.get("SQL_DATABASE", "")
SQL_USERNAME = os.environ.get("SQL_USERNAME", "")
SQL_PASSWORD = os.environ.get("SQL_PASSWORD", "")

SQL_LOG_ENABLED = os.environ.get("SQL_LOG_ENABLED", "true").lower() not in {"false", "0", "no"}
QUEUE_MAX = int(os.environ.get("SQL_LOG_QUEUE_MAX", "10000"))
BATCH_SIZE = int(os.environ.get("SQL_LOG_BATCH", "50"))

# How long the writer waits to accumulate a batch before flushing what it has.
FLUSH_INTERVAL_SEC = 2.0

# Connection retry policy. The long ceiling exists for serverless auto-resume.
CONNECT_MAX_ATTEMPTS = 5
CONNECT_BACKOFF_SEC = [2, 5, 15, 30, 60]
LOGIN_TIMEOUT_SEC = 60
QUERY_TIMEOUT_SEC = 30

# After a non-retryable failure (bad credentials, Entra-only auth, wrong
# database) the writer stops trying. It re-tests once after this cooldown so
# that fixing the setting in Azure heals the app on its own, without a redeploy,
# while still not hammering the server with bad logins in the meantime.
FATAL_RETRY_COOLDOWN_SEC = int(os.environ.get("SQL_LOG_FATAL_COOLDOWN", "60"))

# Failures that retrying cannot fix. Retrying these wastes ~52s of backoff and
# repeatedly throws bad logins at Azure, so the writer stops on the first one and
# reports what actually needs changing.
def _firewall_hint(exc: Exception) -> str:
    """Name the exact address Azure rejected, so it can be pasted into a rule."""
    match = re.search(r"IP address '([0-9A-Fa-f:.]+)'", str(exc))
    address = f"'{match.group(1)}'" if match else "this service's outbound address"
    return (
        f"The Azure SQL firewall is blocking {address}. Add it - plus the other "
        "outbound addresses listed under Render -> Connect -> Outbound, since the "
        "one used can vary - at db-server-link-hv-08 -> Networking -> Firewall "
        "rules. Azure notes the change can take up to 5 minutes to take effect."
    )


_FATAL_PATTERNS = (
    (
        # Error 40615. Azure's gateway answers the TCP connection and rejects at
        # login, so a blocked address produces an explicit error, NOT a timeout.
        "is not allowed to access the server",
        _firewall_hint,
    ),
    (
        "azure active directory only authentication is enabled",
        "The server has 'Microsoft Entra authentication only' ENABLED, so SQL "
        "logins are rejected regardless of the password. Either uncheck it "
        "(Portal -> db-server-link-hv-08 -> Settings -> Microsoft Entra ID), or "
        "switch the app to an Entra service principal with pyodbc.",
    ),
    (
        "login failed for user",
        "Credentials rejected. Check SQL_PASSWORD holds the password only - not "
        "the surrounding N'...' from the CREATE USER statement - and that the "
        "user exists in db-server-link-hv.",
    ),
    (
        "cannot open database",
        "SQL_DATABASE must be the database name (db-server-link-hv), not a table.",
    ),
    (
        "password did not match",
        "Credentials rejected. Verify SQL_PASSWORD.",
    ),
)


def _fatal_reason(exc: Exception) -> Optional[str]:
    """Return an actionable hint if this error will never resolve by retrying."""
    text = str(exc).lower()
    for pattern, hint in _FATAL_PATTERNS:
        if pattern in text:
            return hint(exc) if callable(hint) else hint
    return None


# Identifies which Render instance wrote the row; useful once you scale to >1.
INSTANCE_ID = (
    os.environ.get("RENDER_INSTANCE_ID")
    or os.environ.get("HOSTNAME")
    or socket.gethostname()
)[:64]

_INSERT_SQL = """
INSERT INTO dbo.XusActivityLog
    (CorrelationId, Stage, Status, EventUtc, ElapsedMs,
     ShipmentNumber, CompanyCode, EnterpriseId, ServerId,
     DutyAmount, DutyLineCount, CwHttpStatus,
     PayloadBytes, PayloadSha256,
     ErrorType, ErrorDetail, ClientIp, InstanceId)
VALUES (%s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s,
        %s, %s,
        %s, %s, %s, %s)
"""


# --------------------------------------------------------------------------
# Event record
# --------------------------------------------------------------------------

@dataclass
class LogEvent:
    correlation_id: uuid.UUID
    stage: str
    status: str
    event_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    elapsed_ms: Optional[int] = None
    shipment_number: Optional[str] = None
    company_code: Optional[str] = None
    enterprise_id: Optional[str] = None
    server_id: Optional[str] = None
    duty_amount: Optional[Decimal] = None
    duty_line_count: Optional[int] = None
    cw_http_status: Optional[int] = None
    payload_bytes: Optional[int] = None
    payload_sha256: Optional[str] = None
    error_type: Optional[str] = None
    error_detail: Optional[str] = None
    client_ip: Optional[str] = None

    def to_row(self) -> tuple:
        return (
            str(self.correlation_id),
            self.stage,
            self.status,
            # pymssql wants a naive datetime for DATETIME2.
            self.event_utc.replace(tzinfo=None),
            self.elapsed_ms,
            _trim(self.shipment_number, 50),
            _trim(self.company_code, 20),
            _trim(self.enterprise_id, 20),
            _trim(self.server_id, 20),
            self.duty_amount,
            self.duty_line_count,
            self.cw_http_status,
            self.payload_bytes,
            self.payload_sha256,
            _trim(self.error_type, 100),
            _trim(self.error_detail, 2000),
            _trim(self.client_ip, 45),
            INSTANCE_ID,
        )


def _trim(value: Optional[str], limit: int) -> Optional[str]:
    """Truncate to the column width so a long message never fails the INSERT."""
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def sha256_of(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# Writer thread
# --------------------------------------------------------------------------

class _Writer(threading.Thread):
    def __init__(self) -> None:
        super().__init__(name="xus-log-writer", daemon=True)
        self.queue: "queue.Queue[Optional[LogEvent]]" = queue.Queue(maxsize=QUEUE_MAX)
        self._stop_evt = threading.Event()
        self._conn = None
        self.dropped = 0
        self.written = 0
        # Set once a non-retryable failure is seen; pauses connect attempts until
        # FATAL_RETRY_COOLDOWN_SEC has passed, then allows one more try.
        self.fatal_reason: Optional[str] = None
        self.fatal_at: float = 0.0

    # -- connection handling -------------------------------------------------

    def _connect(self):
        last_error = None
        for attempt in range(CONNECT_MAX_ATTEMPTS):
            if self._stop_evt.is_set():
                return None
            try:
                conn = pymssql.connect(
                    server=SQL_SERVER,
                    user=SQL_USERNAME,
                    password=SQL_PASSWORD,
                    database=SQL_DATABASE,
                    port=1433,
                    login_timeout=LOGIN_TIMEOUT_SEC,
                    timeout=QUERY_TIMEOUT_SEC,
                    tds_version="7.4",
                    autocommit=False,
                    charset="UTF-8",
                )
                if attempt:
                    logger.info("SQL log connection established after %d retries", attempt)
                return conn
            except Exception as exc:  # noqa: BLE001 - fail open
                last_error = exc
                # Configuration and credential problems never fix themselves.
                # Stop immediately rather than retrying into a wall.
                hint = _fatal_reason(exc)
                if hint:
                    self.fatal_reason = hint
                    self.fatal_at = time.monotonic()
                    logger.error(
                        "Azure SQL activity logging PAUSED - this will not resolve "
                        "by retrying.\n  Error: %s\n  Fix: %s\n  Will re-test in "
                        "%d minutes; restart the service to retry immediately.",
                        exc, hint, FATAL_RETRY_COOLDOWN_SEC // 60,
                    )
                    return None

                delay = CONNECT_BACKOFF_SEC[min(attempt, len(CONNECT_BACKOFF_SEC) - 1)]
                logger.warning(
                    "SQL log connect attempt %d/%d failed (%s). "
                    "Retrying in %ds - the serverless database may be resuming.",
                    attempt + 1, CONNECT_MAX_ATTEMPTS, exc, delay,
                )
                if self._stop_evt.wait(delay):
                    return None
        logger.error("SQL log connection failed permanently: %s", last_error)
        return None

    def _ensure_conn(self) -> bool:
        if self._conn is not None:
            return True
        if self.fatal_reason:
            # Misconfigured. Stay quiet until the cooldown expires, then re-test
            # once so that fixing it in Azure recovers without a redeploy.
            if time.monotonic() - self.fatal_at < FATAL_RETRY_COOLDOWN_SEC:
                return False
            logger.info("Re-testing Azure SQL connection after cooldown")
            self.fatal_reason = None
        self._conn = self._connect()
        if self._conn is not None and self.fatal_reason is None:
            logger.info("Azure SQL activity logging recovered")
        return self._conn is not None

    def _discard_conn(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    # -- main loop -----------------------------------------------------------

    def run(self) -> None:
        while not self._stop_evt.is_set():
            batch = self._collect_batch()
            if batch:
                self._write(batch)
        # Drain whatever is left at shutdown.
        final = self._collect_batch(block=False)
        if final:
            self._write(final)
        self._discard_conn()

    def _collect_batch(self, block: bool = True) -> list:
        batch: list = []
        deadline = time.monotonic() + FLUSH_INTERVAL_SEC
        while len(batch) < BATCH_SIZE:
            remaining = deadline - time.monotonic()
            if block and remaining > 0:
                try:
                    item = self.queue.get(timeout=remaining)
                except queue.Empty:
                    break
            else:
                try:
                    item = self.queue.get_nowait()
                except queue.Empty:
                    break
            if item is None:  # shutdown sentinel
                self._stop_evt.set()
                break
            batch.append(item)
        return batch

    def _write(self, batch: list) -> None:
        rows = []
        for event in batch:
            try:
                rows.append(event.to_row())
            except Exception as exc:  # noqa: BLE001 - a bad row must not kill the batch
                logger.error("Skipping malformed log event: %s", exc)
        if not rows:
            return

        for attempt in range(2):  # one retry on a stale connection
            if not self._ensure_conn():
                self.dropped += len(rows)
                logger.error("Dropped %d activity log rows - no database connection", len(rows))
                return
            try:
                cursor = self._conn.cursor()
                cursor.executemany(_INSERT_SQL, rows)
                self._conn.commit()
                cursor.close()
                self.written += len(rows)
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("SQL log write failed (attempt %d): %s", attempt + 1, exc)
                self._discard_conn()

        self.dropped += len(rows)
        logger.error("Dropped %d activity log rows after write failures", len(rows))

    def shutdown(self, timeout: float = 10.0) -> None:
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            self._stop_evt.set()
        self.join(timeout=timeout)


_writer: Optional[_Writer] = None
_writer_lock = threading.Lock()
_disabled_reason: Optional[str] = None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def start() -> None:
    """Start the background writer. Safe to call once, at application startup."""
    global _writer, _disabled_reason

    if not SQL_LOG_ENABLED:
        _disabled_reason = "SQL_LOG_ENABLED is false"
        logger.info("Azure SQL activity logging disabled by configuration")
        return

    if pymssql is None:
        _disabled_reason = "pymssql is not installed"
        logger.error("Azure SQL activity logging disabled: pymssql is not installed")
        return

    missing = [
        name for name, value in (
            ("SQL_SERVER", SQL_SERVER),
            ("SQL_DATABASE", SQL_DATABASE),
            ("SQL_USERNAME", SQL_USERNAME),
            ("SQL_PASSWORD", SQL_PASSWORD),
        ) if not value
    ]
    if missing:
        _disabled_reason = f"missing environment variables: {', '.join(missing)}"
        logger.error("Azure SQL activity logging disabled: %s", _disabled_reason)
        return

    with _writer_lock:
        if _writer is None:
            _writer = _Writer()
            _writer.start()
            atexit.register(stop)
            logger.info(
                "Azure SQL activity logging started (server=%s db=%s instance=%s)",
                SQL_SERVER, SQL_DATABASE, INSTANCE_ID,
            )


def stop() -> None:
    """Flush and stop the writer. Call at application shutdown."""
    global _writer
    with _writer_lock:
        if _writer is not None:
            _writer.shutdown()
            logger.info(
                "Azure SQL activity logging stopped (written=%d dropped=%d)",
                _writer.written, _writer.dropped,
            )
            _writer = None


def log_event(event: LogEvent) -> None:
    """Queue one activity row. Non-blocking; never raises."""
    if _writer is None:
        return
    try:
        _writer.queue.put_nowait(event)
    except queue.Full:
        _writer.dropped += 1
        logger.warning("Activity log queue full (%d) - dropping event", QUEUE_MAX)
    except Exception as exc:  # noqa: BLE001 - logging must never break the request
        logger.error("Failed to queue activity log event: %s", exc)


def health() -> dict:
    """Small status blob for the health endpoint."""
    if _writer is None:
        return {"enabled": False, "reason": _disabled_reason or "not started"}
    status = {
        "enabled": True,
        "queued": _writer.queue.qsize(),
        "written": _writer.written,
        "dropped": _writer.dropped,
        "connected": _writer._conn is not None,
    }
    if _writer.fatal_reason:
        status["enabled"] = False
        status["reason"] = _writer.fatal_reason
        status["retry_in_seconds"] = max(
            0, int(FATAL_RETRY_COOLDOWN_SEC - (time.monotonic() - _writer.fatal_at))
        )
    return status


# --------------------------------------------------------------------------
# Diagnostics
# --------------------------------------------------------------------------

def diagnose() -> dict:
    """Run the connection checks and report which stage fails, and why.

    Blocking - call from a worker thread, not the event loop. Used by both
    ``test_sql_connection.py`` and the ``/admin/dbcheck`` endpoint (the latter
    matters on Render's free tier, which has no shell).

    Stops at the first failure and returns hints aimed at that specific cause,
    because the raw driver errors for "firewall", "wrong password" and
    "Entra-only auth is on" are easy to mistake for each other.
    """
    steps: list[dict] = []

    def record(name: str, ok: bool, detail: str, hints: Optional[list] = None) -> dict:
        step = {"step": len(steps) + 1, "name": name, "ok": ok, "detail": detail}
        if hints:
            step["hints"] = hints
        steps.append(step)
        return step

    def done() -> dict:
        return {"ok": all(s["ok"] for s in steps), "steps": steps}

    # -- 1. configuration ---------------------------------------------------
    missing = [
        n for n, v in (("SQL_SERVER", SQL_SERVER), ("SQL_DATABASE", SQL_DATABASE),
                       ("SQL_USERNAME", SQL_USERNAME), ("SQL_PASSWORD", SQL_PASSWORD))
        if not v
    ]
    if missing:
        record("configuration", False, f"missing: {', '.join(missing)}",
               ["Set these under Render -> your service -> Environment."])
        return done()

    notes = []
    if SQL_PASSWORD.startswith(("N'", "n'")) or (
            SQL_PASSWORD.startswith("'") and SQL_PASSWORD.endswith("'")):
        notes.append(
            "SQL_PASSWORD looks like a T-SQL literal (N'...'). The N prefix and "
            "quotes are syntax, not part of the password - store the inner text only."
        )
    if "." in SQL_DATABASE and SQL_DATABASE.lower().startswith("dbo."):
        notes.append(
            f"SQL_DATABASE is '{SQL_DATABASE}', which looks like a table name. "
            "It should be the database, e.g. 'db-server-link-hv'."
        )
    record("configuration", True,
           f"server={SQL_SERVER} database={SQL_DATABASE} username={SQL_USERNAME} "
           f"password={'*' * 8} ({len(SQL_PASSWORD)} chars)",
           notes or None)

    # -- 2. driver ----------------------------------------------------------
    if pymssql is None:
        record("driver", False, "pymssql is not installed",
               ["Add 'pymssql>=2.3.0' to requirements.txt and redeploy."])
        return done()
    record("driver", True, f"pymssql {getattr(pymssql, '__version__', 'unknown')}")

    # -- 3. TCP reachability ------------------------------------------------
    started = time.monotonic()
    try:
        with socket.create_connection((SQL_SERVER, 1433), timeout=20):
            pass
        record("tcp", True, f"port 1433 open ({(time.monotonic() - started) * 1000:.0f} ms)")
    except socket.timeout:
        record("tcp", False, "timed out connecting to port 1433", [
            "Note this is NOT the usual symptom of an IP firewall block - Azure "
            "answers those at login with error 40615, which shows up at the login "
            "step below, not here.",
            "A timeout here points at egress being blocked before Azure, or public "
            "network access being disabled on the server entirely.",
        ])
        return done()
    except socket.gaierror:
        record("tcp", False, f"cannot resolve '{SQL_SERVER}'",
               ["Expected db-server-link-hv-08.database.windows.net"])
        return done()
    except Exception as exc:  # noqa: BLE001
        record("tcp", False, f"socket error: {exc}")
        return done()

    # -- 4. login -----------------------------------------------------------
    started = time.monotonic()
    conn = None
    try:
        conn = pymssql.connect(
            server=SQL_SERVER, user=SQL_USERNAME, password=SQL_PASSWORD,
            database=SQL_DATABASE, port=1433, login_timeout=90, timeout=30,
            tds_version="7.4", autocommit=False, charset="UTF-8",
        )
        record("login", True, f"connected ({(time.monotonic() - started) * 1000:.0f} ms)")
    except Exception as exc:  # noqa: BLE001
        text = str(exc).lower()
        elapsed = time.monotonic() - started
        if "is not allowed to access the server" in text:
            hints = [_firewall_hint(exc),
                     "'Allow Azure services' does NOT cover Render - it is not an "
                     "Azure service."]
        elif "login failed" in text:
            hints = [
                "If 'Microsoft Entra authentication only' is ENABLED on the server, "
                "SQL logins are blocked entirely - uncheck it, or switch to a service "
                "principal with pyodbc.",
                "Otherwise verify the password has no surrounding N'...' quoting.",
                "Confirm the user exists in the right database: SELECT name FROM "
                "sys.database_principals WHERE name = 'vih_duty_app';",
            ]
        elif "cannot open database" in text:
            hints = [f"SQL_DATABASE is '{SQL_DATABASE}'. It must be the database name "
                     f"(db-server-link-hv), not a table."]
        elif elapsed > 45:
            hints = ["The serverless database was probably paused and is resuming. "
                     "Try again in ~60s; the app retries automatically."]
        else:
            hints = []
        record("login", False, str(exc), hints or None)
        return done()

    # -- 5. write -----------------------------------------------------------
    correlation_id = uuid.uuid4()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO dbo.XusActivityLog "
            "(CorrelationId, Stage, Status, EventUtc, ErrorDetail, InstanceId) "
            "VALUES (%s, 'Health', 'Processed', %s, %s, %s)",
            (str(correlation_id), datetime.now(timezone.utc).replace(tzinfo=None),
             "connection test via diagnose()", INSTANCE_ID),
        )
        conn.commit()
        cursor.close()
        record("insert", True, f"test row written, CorrelationId={correlation_id}",
               ["Remove test rows when finished: "
                "DELETE FROM dbo.XusActivityLog WHERE Stage = 'Health';"])
    except Exception as exc:  # noqa: BLE001
        text = str(exc).lower()
        if "invalid object name" in text:
            hints = ["Run sql/01_create_log_table.sql against db-server-link-hv."]
        elif "invalid column name" in text:
            hints = ["The table does not match what the app inserts. Drop it and "
                     "re-run the delivered sql/01_create_log_table.sql."]
        elif "permission" in text or "denied" in text:
            hints = ["GRANT INSERT ON dbo.XusActivityLog TO vih_duty_app;"]
        else:
            hints = []
        record("insert", False, str(exc), hints or None)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    return done()
