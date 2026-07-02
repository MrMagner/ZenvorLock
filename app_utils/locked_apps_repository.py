from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app_utils.file_identity import file_sha256
from app_utils.software_inventory import (
    InventoryApp,
    extract_executable_name,
    normalize_path,
)
from config.config_manager import get_connection, write_connection
from security.audit import log_security_event
from security.policy_integrity import verify_policy_integrity_safely, refresh_policy_integrity


@dataclass(frozen=True)
class LockedAppRecord:
    id: int | None
    app_name: str
    app_path: str = ""
    match_mode: str = "path"
    file_sha256: str = ""
    integrity_issue: str = ""

    @property
    def display_name(self) -> str:
        if self.app_path:
            return Path(self.app_path).stem or self.app_name
        return self.app_name

    @property
    def identity(self) -> str:
        if self.match_mode == "path" and self.app_path:
            return normalize_path(self.app_path).casefold()
        return self.app_name.casefold()

    @property
    def is_path_rule(self) -> bool:
        return self.match_mode == "path" and bool(self.app_path)


def list_locked_apps() -> list[LockedAppRecord]:
    conn = get_connection()
    try:
        verify_policy_integrity_safely(conn)
        rows = conn.execute(
            """
            SELECT id, app_name, app_path, match_mode, file_sha256
            FROM locked_apps
            ORDER BY
                CASE match_mode WHEN 'path' THEN 0 ELSE 1 END,
                LOWER(app_name),
                LOWER(app_path)
            """
        ).fetchall()
        return [
            LockedAppRecord(
                id=int(row["id"]),
                app_name=(row["app_name"] or "").strip(),
                app_path=normalize_path(row["app_path"]),
                match_mode=_normalize_match_mode(row["match_mode"], row["app_path"]),
                file_sha256=(row["file_sha256"] or "").strip().lower(),
            )
            for row in rows
        ]
    finally:
        conn.close()


def lock_apps(apps: Iterable[InventoryApp | LockedAppRecord]) -> int:
    changed = 0

    with write_connection() as conn:
        verify_policy_integrity_safely(conn)
        cursor = conn.cursor()

        for app in apps:
            app_name, app_path, match_mode, app_hash = _normalize_locked_values(app)
            if not app_name and not app_path:
                continue

            if match_mode == "path":
                existing = cursor.execute(
                    """
                    SELECT id, app_name, file_sha256
                    FROM locked_apps
                    WHERE LOWER(app_path) = LOWER(?)
                      AND match_mode = 'path'
                    LIMIT 1
                    """,
                    (app_path,),
                ).fetchone()
                if existing:
                    if (
                        (existing["app_name"] or "").strip() != app_name
                        or (existing["file_sha256"] or "").strip().lower() != app_hash
                    ):
                        cursor.execute(
                            """
                            UPDATE locked_apps
                            SET app_name = ?, app_path = ?, match_mode = 'path', file_sha256 = ?
                            WHERE id = ?
                            """,
                            (app_name, app_path, app_hash, int(existing["id"])),
                        )
                        changed += cursor.rowcount
                    continue

                pathless_existing = cursor.execute(
                    """
                    SELECT id FROM locked_apps
                    WHERE LOWER(app_name) = LOWER(?)
                      AND match_mode = 'name'
                    LIMIT 1
                    """,
                    (app_name,),
                ).fetchone()
                if pathless_existing:
                    cursor.execute(
                        """
                        UPDATE locked_apps
                        SET app_name = ?, app_path = ?, match_mode = 'path', file_sha256 = ?
                        WHERE id = ?
                        """,
                        (app_name, app_path, app_hash, int(pathless_existing["id"])),
                    )
                    changed += cursor.rowcount
                    continue

                cursor.execute(
                    """
                    INSERT OR IGNORE INTO locked_apps (app_name, app_path, match_mode, file_sha256)
                    VALUES (?, ?, 'path', ?)
                    """,
                    (app_name, app_path, app_hash),
                )
                changed += cursor.rowcount
                continue

            existing = cursor.execute(
                """
                SELECT id FROM locked_apps
                WHERE LOWER(app_name) = LOWER(?)
                  AND match_mode = 'name'
                LIMIT 1
                """,
                (app_name,),
            ).fetchone()
            if existing:
                continue

            cursor.execute(
                """
                INSERT OR IGNORE INTO locked_apps (app_name, app_path, match_mode, file_sha256)
                VALUES (?, '', 'name', '')
                """,
                (app_name,),
            )
            changed += cursor.rowcount

        refresh_policy_integrity(conn)

    if changed:
        log_security_event("LOCK_APPS", f"Locked or updated {changed} application rule(s).")
    return changed


def unlock_apps(apps: Iterable[InventoryApp | LockedAppRecord]) -> int:
    changed = 0

    with write_connection() as conn:
        verify_policy_integrity_safely(conn)
        cursor = conn.cursor()

        for app in apps:
            app_id = getattr(app, "id", None)
            if app_id is not None:
                cursor.execute("DELETE FROM locked_apps WHERE id = ?", (int(app_id),))
                changed += cursor.rowcount
                continue

            app_name, app_path, match_mode, _ = _normalize_locked_values(app)
            if match_mode == "path" and app_path:
                cursor.execute(
                    """
                    DELETE FROM locked_apps
                    WHERE LOWER(app_path) = LOWER(?)
                      AND match_mode = 'path'
                    """,
                    (app_path,),
                )
                changed += cursor.rowcount
                continue

            if not app_name:
                continue

            cursor.execute(
                """
                DELETE FROM locked_apps
                WHERE LOWER(app_name) = LOWER(?)
                  AND match_mode = 'name'
                """,
                (app_name,),
            )
            changed += cursor.rowcount

        refresh_policy_integrity(conn)

    if changed:
        log_security_event("UNLOCK_APPS", f"Unlocked {changed} application rule(s).")
    return changed


def unlock_all_apps() -> int:
    with write_connection() as conn:
        verify_policy_integrity_safely(conn)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM locked_apps")
        changed = cursor.rowcount
        refresh_policy_integrity(conn)

    if changed:
        log_security_event("UNLOCK_ALL_APPS", f"Removed all locked application rules ({changed}).")
    return changed


def get_locked_targets() -> tuple[
    dict[str, LockedAppRecord],
    dict[str, LockedAppRecord],
    dict[str, list[LockedAppRecord]],
]:
    by_path: dict[str, LockedAppRecord] = {}
    by_hash: dict[str, LockedAppRecord] = {}
    by_name: dict[str, list[LockedAppRecord]] = {}

    for record in list_locked_apps():
        if record.is_path_rule:
            normalized_path = normalize_path(record.app_path).casefold()
            by_path[normalized_path] = record
            if record.file_sha256:
                by_hash[record.file_sha256] = record
        else:
            by_name.setdefault(record.app_name.casefold(), []).append(record)

    return by_path, by_hash, by_name


def _normalize_match_mode(raw_mode: object, raw_path: object) -> str:
    mode = str(raw_mode or "").strip().casefold()
    if mode in {"path", "name"}:
        if mode == "path" and not str(raw_path or "").strip():
            return "name"
        return mode
    return "path" if str(raw_path or "").strip() else "name"


def _normalize_locked_values(
    app: InventoryApp | LockedAppRecord,
) -> tuple[str, str, str, str]:
    raw_path = normalize_path(getattr(app, "path", "") or getattr(app, "app_path", ""))
    raw_name = getattr(app, "executable_name", "") or getattr(app, "app_name", "")
    app_name = extract_executable_name(raw_path, fallback=str(raw_name or "").strip()).strip()
    match_mode = _normalize_match_mode(getattr(app, "match_mode", ""), raw_path)
    if not raw_path:
        raise ValueError(
            "SecureApp Locker requires a concrete executable path for each locked application."
        )
    if match_mode == "path" and raw_path:
        digest = file_sha256(raw_path)
        if not digest:
            raise ValueError(f"Unable to calculate a stable file identity for {raw_path}.")
        return app_name, raw_path, "path", digest
    raise ValueError(
        "SecureApp Locker requires a concrete executable path for each locked application."
    )
