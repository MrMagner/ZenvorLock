from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from app_utils.logger import logger
from security.protected_state import ProtectedStateError, get_integrity_key

AUDIT_HEAD_SETTING_KEY = "security_logs_head_hmac"


class AuditIntegrityError(RuntimeError):
    """Raised when the audit trail has been modified outside the app."""


def _sanitize_details(details: str) -> str:
    cleaned = " ".join(str(details or "").split())
    return cleaned[:240]


def _normalize_event_type(event_type: str) -> str:
    return str(event_type or "").strip()[:64]


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical_event(
    previous_mac: str,
    event_type: str,
    details: str,
    timestamp: str,
) -> bytes:
    payload = {
        "details": details,
        "event_type": event_type,
        "previous_mac": previous_mac,
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _calculate_entry_mac(
    previous_mac: str,
    event_type: str,
    details: str,
    timestamp: str,
) -> str:
    key = get_integrity_key()
    payload = _canonical_event(previous_mac, event_type, details, timestamp)
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _read_head_mac(conn) -> str | None:
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ? LIMIT 1",
        (AUDIT_HEAD_SETTING_KEY,),
    ).fetchone()
    if row is None:
        return None
    return str(row["value"] or "").strip().lower()


def _write_head_mac(conn, mac: str) -> None:
    conn.execute(
        """
        INSERT INTO settings(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (AUDIT_HEAD_SETTING_KEY, mac),
    )


def _read_audit_rows(conn) -> list[object]:
    return conn.execute(
        """
        SELECT id, event_type, details, timestamp, entry_mac
        FROM security_logs
        ORDER BY id
        """
    ).fetchall()


def refresh_audit_integrity(conn) -> str:
    previous_mac = ""

    for row in _read_audit_rows(conn):
        event_type = _normalize_event_type(row["event_type"])
        details = _sanitize_details(row["details"])
        timestamp = str(row["timestamp"] or "").strip()
        entry_mac = _calculate_entry_mac(previous_mac, event_type, details, timestamp)
        conn.execute(
            "UPDATE security_logs SET entry_mac = ? WHERE id = ?",
            (entry_mac, int(row["id"])),
        )
        previous_mac = entry_mac

    _write_head_mac(conn, previous_mac)
    return previous_mac


def verify_audit_integrity(conn) -> None:
    rows = _read_audit_rows(conn)
    stored_head = _read_head_mac(conn)

    if not rows:
        if stored_head in {None, ""}:
            _write_head_mac(conn, "")
            return
        raise AuditIntegrityError("Audit log integrity state is inconsistent.")

    if stored_head is None:
        if all(not str(row["entry_mac"] or "").strip() for row in rows):
            refresh_audit_integrity(conn)
            return
        raise AuditIntegrityError("Audit log integrity state is missing.")

    previous_mac = ""
    for row in rows:
        event_type = _normalize_event_type(row["event_type"])
        details = _sanitize_details(row["details"])
        timestamp = str(row["timestamp"] or "").strip()
        expected_mac = _calculate_entry_mac(previous_mac, event_type, details, timestamp)
        stored_mac = str(row["entry_mac"] or "").strip().lower()
        if not stored_mac:
            raise AuditIntegrityError("Audit log entry integrity state is missing.")
        if not hmac.compare_digest(stored_mac, expected_mac):
            raise AuditIntegrityError("Security audit log was modified outside SecureApp Locker.")
        previous_mac = expected_mac

    if not hmac.compare_digest(stored_head, previous_mac):
        raise AuditIntegrityError("Audit log integrity head does not match the stored entries.")


def verify_audit_integrity_safely(conn) -> None:
    try:
        verify_audit_integrity(conn)
    except ProtectedStateError as exc:
        raise AuditIntegrityError("Protected audit integrity key is unavailable.") from exc


def append_security_event(conn, event_type: str, details: str = "") -> None:
    verify_audit_integrity_safely(conn)

    normalized_event_type = _normalize_event_type(event_type)
    normalized_details = _sanitize_details(details)
    timestamp = _now_timestamp()
    previous_mac = _read_head_mac(conn) or ""
    entry_mac = _calculate_entry_mac(
        previous_mac,
        normalized_event_type,
        normalized_details,
        timestamp,
    )

    conn.execute(
        """
        INSERT INTO security_logs (event_type, details, timestamp, entry_mac)
        VALUES (?, ?, ?, ?)
        """,
        (normalized_event_type, normalized_details, timestamp, entry_mac),
    )
    _write_head_mac(conn, entry_mac)


def log_security_event(event_type: str, details: str = "") -> None:
    try:
        from config.config_manager import write_connection

        with write_connection() as conn:
            append_security_event(conn, event_type, details)
    except Exception as exc:
        logger.error("Error logging security event: %s", exc)
