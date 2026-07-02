from __future__ import annotations

from contextlib import ExitStack
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app_utils.locked_apps_repository import (
    LockedAppRecord,
    list_locked_apps,
    lock_apps,
    unlock_all_apps,
)
from config import config_manager
from security.audit import AuditIntegrityError, verify_audit_integrity_safely
from security.auth_manager import (
    change_master_password,
    get_lockout_time,
    setup_master_password,
    verify_master_password,
)
from security.policy_integrity import PolicyIntegrityError
from security.protected_state import ProtectedStateError, load_state


class SettingsActionTests(unittest.TestCase):
    def _temp_security_patches(self, temp_dir: str) -> ExitStack:
        db_path = Path(temp_dir) / "secureapp.db"
        state_path = Path(temp_dir) / ".secureapp-auth.bin"
        guard_path = Path(temp_dir) / ".secureapp-install-guard.json"
        registry_anchor: dict[str, object] = {}

        def load_registry_anchor() -> dict[str, object] | None:
            return dict(registry_anchor) if registry_anchor else None

        def save_registry_anchor(state: dict[str, object], *, auth_configured: bool) -> None:
            registry_anchor.clear()
            registry_anchor.update(
                {
                    "install_id": str(state.get("install_id") or "").strip(),
                    "auth_configured": bool(auth_configured),
                }
            )

        stack = ExitStack()
        stack.enter_context(patch.object(config_manager, "DB_FILE", db_path))
        stack.enter_context(
            patch("security.protected_state.get_state_path", return_value=state_path)
        )
        stack.enter_context(
            patch("security.protected_state.get_guard_path", return_value=guard_path)
        )
        stack.enter_context(
            patch("security.protected_state._load_registry_anchor", side_effect=load_registry_anchor)
        )
        stack.enter_context(
            patch("security.protected_state._save_registry_anchor", side_effect=save_registry_anchor)
        )
        return stack

    def test_change_master_password_updates_stored_password(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1"))

                success, message = change_master_password("OldPassword1", "NewPassword2")

                self.assertTrue(success)
                self.assertEqual(message, "Master password changed successfully.")
                self.assertTrue(verify_master_password("NewPassword2"))
                self.assertFalse(verify_master_password("OldPassword1"))

    def test_change_master_password_rejects_wrong_previous_password(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1"))

                success, message = change_master_password("WrongPassword9", "NewPassword2")

                self.assertFalse(success)
                self.assertEqual(message, "Previous password is incorrect.")
                self.assertTrue(verify_master_password("OldPassword1"))

    def test_unlock_all_apps_clears_locked_apps_table(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                changed = lock_apps(
                    [
                        LockedAppRecord(
                            id=None,
                            app_name="chrome.exe",
                            app_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        ),
                        LockedAppRecord(
                            id=None,
                            app_name="notepad.exe",
                            app_path=r"C:\Windows\System32\notepad.exe",
                        ),
                    ]
                )

                self.assertEqual(changed, 2)
                self.assertEqual(len(list_locked_apps()), 2)
                self.assertEqual(unlock_all_apps(), 2)
                self.assertEqual(list_locked_apps(), [])

    def test_setup_master_password_rejects_weak_password(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertFalse(setup_master_password("  weak  "))
                self.assertFalse(verify_master_password("  weak  "))

    def test_change_master_password_rejects_weak_new_password(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1!"))

                success, message = change_master_password("OldPassword1!", "  123  ")

                self.assertFalse(success)
                self.assertIn("at least 10 characters", message)
                self.assertTrue(verify_master_password("OldPassword1!"))

    def test_lockout_state_persists_across_calls(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1!"))
                with patch("security.auth_manager.time.time", return_value=100.0):
                    for _ in range(5):
                        self.assertFalse(verify_master_password("WrongPassword9"))

                with patch("security.auth_manager.time.time", return_value=100.0):
                    self.assertEqual(get_lockout_time(), 60.0)
                    self.assertFalse(verify_master_password("OldPassword1!"))

                with patch("security.auth_manager.time.time", return_value=161.0):
                    self.assertEqual(get_lockout_time(), 0.0)
                    self.assertTrue(verify_master_password("OldPassword1!"))

    def test_locked_app_policy_tampering_is_detected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                lock_apps(
                    [
                        LockedAppRecord(
                            id=None,
                            app_name=Path(sys.executable).name,
                            app_path=str(Path(sys.executable)),
                        )
                    ]
                )

                conn = config_manager.get_connection()
                try:
                    conn.execute(
                        "UPDATE locked_apps SET app_name = ? WHERE app_name = ?",
                        ("tampered.exe", Path(sys.executable).name),
                    )
                    conn.commit()
                finally:
                    conn.close()

                with self.assertRaises(PolicyIntegrityError):
                    list_locked_apps()

    def test_missing_policy_hmac_is_detected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                lock_apps(
                    [
                        LockedAppRecord(
                            id=None,
                            app_name=Path(sys.executable).name,
                            app_path=str(Path(sys.executable)),
                        )
                    ]
                )

                conn = config_manager.get_connection()
                try:
                    conn.execute("DELETE FROM settings WHERE key = 'locked_apps_hmac'")
                    conn.commit()
                finally:
                    conn.close()

                with self.assertRaises(PolicyIntegrityError):
                    list_locked_apps()

    def test_deleting_protected_state_files_does_not_reset_authentication(self) -> None:
        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / ".secureapp-auth.bin"
            guard_path = Path(temp_dir) / ".secureapp-install-guard.json"
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1!"))

                state_path.unlink()
                guard_path.unlink()

                with self.assertRaises(ProtectedStateError):
                    load_state()

    def test_audit_log_tampering_is_detected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with self._temp_security_patches(temp_dir):
                config_manager.init_db()
                self.assertTrue(setup_master_password("OldPassword1!"))

                conn = config_manager.get_connection()
                try:
                    conn.execute(
                        "UPDATE security_logs SET details = ? WHERE event_type = ?",
                        ("tampered", "PASSWORD_SET"),
                    )
                    conn.commit()
                finally:
                    conn.close()

                conn = config_manager.get_connection()
                try:
                    with self.assertRaises(AuditIntegrityError):
                        verify_audit_integrity_safely(conn)
                finally:
                    conn.close()


if __name__ == "__main__":
    unittest.main()
