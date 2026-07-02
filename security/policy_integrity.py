from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Iterable

from security.protected_state import ProtectedStateError, get_integrity_key

LOCKED_APPS_HMAC_SETTING_KEY = "locked_apps_hmac"


class PolicyIntegrityError(RuntimeError):
    """Raised when the locked-app policy has been modified outside the app."""


def _canonical_record(row: object) -> dict[str, str]:
    if isinstance(row, Mapping):
        value_getter = row.get
    elif hasattr(row, "keys") and hasattr(row, "__getitem__"):
        value_getter = lambda key, default="": row[key] if key in row.keys() else default
    else:
        value_getter = lambda key, default="": getattr(row, key, default)

    return {
        "app_name": str(value_getter("app_name", "") or "").strip(),
        "app_path": str(value_getter("app_path", "") or "").strip(),
        "match_mode": str(value_getter("match_mode", "") or "").strip().casefold(),
        "file_sha256": str(value_getter("file_sha256", "") or "").strip().lower(),
    }


def _canonical_payload(rows: Iterable[object]) -> str:
    normalized = sorted(
        (_canonical_record(row) for row in rows),
        key=lambda row: (
            row["match_mode"],
            row["app_name"].casefold(),
            row["app_path"].casefold(),
            row["file_sha256"],
        ),
    )
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


def _calculate_mac(rows: Iterable[object]) -> str:
    key = get_integrity_key()
    payload = _canonical_payload(rows).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _read_locked_app_rows(conn) -> list[object]:
    return conn.execute(
        """
        SELECT app_name, app_path, match_mode, file_sha256
        FROM locked_apps
        """
    ).fetchall()


def refresh_policy_integrity(conn) -> str:
    mac = _calculate_mac(_read_locked_app_rows(conn))
    conn.execute(
        """
        INSERT INTO settings(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (LOCKED_APPS_HMAC_SETTING_KEY, mac),
    )
    return mac


def initialize_or_verify_policy_integrity(conn) -> None:
    rows = _read_locked_app_rows(conn)
    stored_row = conn.execute(
        "SELECT value FROM settings WHERE key = ? LIMIT 1",
        (LOCKED_APPS_HMAC_SETTING_KEY,),
    ).fetchone()
    if stored_row is None:
        if not rows:
            refresh_policy_integrity(conn)
            return
        raise PolicyIntegrityError("Locked application policy integrity state is missing.")

    stored_mac = str(stored_row["value"] or "").strip().lower()
    if not stored_mac:
        if not rows:
            refresh_policy_integrity(conn)
            return
        raise PolicyIntegrityError("Locked application policy integrity state is empty.")

    current_mac = _calculate_mac(rows)
    if not hmac.compare_digest(stored_mac, current_mac):
        raise PolicyIntegrityError("Locked application policy was modified outside SecureApp Locker.")


def verify_policy_integrity(conn) -> None:
    stored_row = conn.execute(
        "SELECT value FROM settings WHERE key = ? LIMIT 1",
        (LOCKED_APPS_HMAC_SETTING_KEY,),
    ).fetchone()
    if stored_row is None:
        raise PolicyIntegrityError("Locked application policy integrity state is missing.")

    stored_mac = str(stored_row["value"] or "").strip().lower()
    if not stored_mac:
        raise PolicyIntegrityError("Locked application policy integrity state is empty.")

    current_mac = _calculate_mac(_read_locked_app_rows(conn))
    if not hmac.compare_digest(stored_mac, current_mac):
        raise PolicyIntegrityError("Locked application policy was modified outside SecureApp Locker.")


def verify_policy_integrity_safely(conn) -> None:
    try:
        verify_policy_integrity(conn)
    except ProtectedStateError as exc:
        raise PolicyIntegrityError("Protected integrity key is unavailable.") from exc
