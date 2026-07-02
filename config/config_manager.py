from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

from app_utils.logger import logger
from app_utils.paths import get_database_path
from security.audit import verify_audit_integrity_safely
from security.policy_integrity import (
    initialize_or_verify_policy_integrity,
    refresh_policy_integrity,
)
from security.protected_state import ensure_state

DB_FILE = get_database_path()
DB_TIMEOUT_SECONDS = 10

_WRITE_LOCK = threading.RLock()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(
        str(DB_FILE),
        timeout=DB_TIMEOUT_SECONDS,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    busy_timeout_ms = int(DB_TIMEOUT_SECONDS * 1000)
    conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA secure_delete = ON")
    try:
        conn.execute("PRAGMA trusted_schema = OFF")
    except sqlite3.DatabaseError:
        pass
    return conn


@contextmanager
def write_connection():
    with _WRITE_LOCK:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _deduplicate_locked_apps(conn: sqlite3.Connection) -> bool:
    cursor = conn.cursor()
    before_changes = conn.total_changes
    rows = cursor.execute(
        """
        SELECT id, app_name, app_path, match_mode, file_sha256
        FROM locked_apps
        ORDER BY id
        """
    ).fetchall()

    seen_paths: set[str] = set()
    seen_name_rules: set[str] = set()
    duplicate_ids: list[int] = []

    for row in rows:
        app_id = int(row["id"])
        app_name = (row["app_name"] or "").strip()
        app_path = (row["app_path"] or "").strip()
        file_sha256 = (row["file_sha256"] or "").strip().lower()
        match_mode = (row["match_mode"] or "").strip().casefold()

        if match_mode not in {"path", "name"}:
            match_mode = "path" if app_path else "name"

        if match_mode == "name":
            app_path = ""
            file_sha256 = ""
        elif not app_path:
            match_mode = "name"

        if not app_name and not app_path:
            duplicate_ids.append(app_id)
            continue

        if match_mode == "path" and app_path:
            dedupe_key = app_path.casefold()
            if dedupe_key in seen_paths:
                duplicate_ids.append(app_id)
                continue
            seen_paths.add(dedupe_key)
        else:
            dedupe_key = app_name.casefold()
            if dedupe_key in seen_name_rules:
                duplicate_ids.append(app_id)
                continue
            seen_name_rules.add(dedupe_key)

        if (
            app_name != (row["app_name"] or "").strip()
            or app_path != (row["app_path"] or "").strip()
            or match_mode != (row["match_mode"] or "").strip().casefold()
            or file_sha256 != (row["file_sha256"] or "").strip().lower()
        ):
            cursor.execute(
                """
                UPDATE locked_apps
                SET app_name = ?, app_path = ?, match_mode = ?, file_sha256 = ?
                WHERE id = ?
                """,
                (app_name, app_path, match_mode, file_sha256, app_id),
            )

    if duplicate_ids:
        cursor.executemany(
            "DELETE FROM locked_apps WHERE id = ?",
            [(app_id,) for app_id in duplicate_ids],
        )
    return conn.total_changes > before_changes


def _create_indexes(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_locked_apps_name
        ON locked_apps(LOWER(app_name), match_mode)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_locked_apps_path
        ON locked_apps(LOWER(app_path), match_mode)
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_locked_apps_unique_path
        ON locked_apps(LOWER(app_path))
        WHERE TRIM(app_path) <> '' AND match_mode = 'path'
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_locked_apps_unique_name_without_path
        ON locked_apps(LOWER(app_name))
        WHERE TRIM(app_path) = '' AND match_mode = 'name'
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp
        ON security_logs(timestamp)
        """
    )


def _migrate_locked_apps_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    columns = {
        str(row["name"]).strip().casefold(): row
        for row in cursor.execute("PRAGMA table_info(locked_apps)").fetchall()
    }

    if "match_mode" not in columns:
        cursor.execute(
            "ALTER TABLE locked_apps ADD COLUMN match_mode TEXT NOT NULL DEFAULT 'path'"
        )
    if "file_sha256" not in columns:
        cursor.execute(
            "ALTER TABLE locked_apps ADD COLUMN file_sha256 TEXT NOT NULL DEFAULT ''"
        )


def _normalize_locked_apps_schema(conn: sqlite3.Connection) -> bool:
    before_changes = conn.total_changes
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE locked_apps
        SET match_mode = CASE
            WHEN TRIM(app_path) = '' THEN 'name'
            ELSE 'path'
        END
        WHERE TRIM(match_mode) NOT IN ('path', 'name')
           OR (match_mode = 'path' AND TRIM(app_path) = '')
           OR (match_mode = 'name' AND TRIM(app_path) <> '')
        """
    )
    cursor.execute(
        """
        UPDATE locked_apps
        SET app_path = '', file_sha256 = ''
        WHERE match_mode = 'name'
        """
    )
    cursor.execute(
        """
        UPDATE locked_apps
        SET file_sha256 = LOWER(TRIM(file_sha256))
        WHERE match_mode = 'path'
        """
    )
    return conn.total_changes > before_changes


def _migrate_security_logs_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    columns = {
        str(row["name"]).strip().casefold(): row
        for row in cursor.execute("PRAGMA table_info(security_logs)").fetchall()
    }

    if "entry_mac" not in columns:
        cursor.execute(
            "ALTER TABLE security_logs ADD COLUMN entry_mac TEXT NOT NULL DEFAULT ''"
        )


def checkpoint_database(mode: str = "TRUNCATE") -> None:
    conn: sqlite3.Connection | None = None
    allowed_modes = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
    safe_mode = mode.upper() if mode.upper() in allowed_modes else "TRUNCATE"
    try:
        conn = get_connection()
        conn.execute(f"PRAGMA wal_checkpoint({safe_mode})")
        conn.execute("PRAGMA optimize")
    finally:
        if conn is not None:
            conn.close()


def init_db() -> None:
    conn: sqlite3.Connection | None = None
    try:
        with _WRITE_LOCK:
            ensure_state()
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA synchronous = NORMAL")
            cursor.execute("PRAGMA wal_autocheckpoint = 1000")
            cursor.execute("PRAGMA journal_size_limit = 1048576")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS locked_apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    app_path TEXT NOT NULL DEFAULT '',
                    match_mode TEXT NOT NULL DEFAULT 'path',
                    file_sha256 TEXT NOT NULL DEFAULT ''
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            _migrate_locked_apps_schema(conn)
            _migrate_security_logs_schema(conn)
            _create_indexes(conn)
            verify_audit_integrity_safely(conn)
            initialize_or_verify_policy_integrity(conn)

            locked_apps_changed = _normalize_locked_apps_schema(conn)
            locked_apps_changed = locked_apps_changed or _deduplicate_locked_apps(conn)
            if locked_apps_changed:
                refresh_policy_integrity(conn)

            conn.commit()

        logger.info("Database initialized successfully.")
    except Exception as exc:
        logger.error(f"Error initializing database: {exc}")
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    init_db()
