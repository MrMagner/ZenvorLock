from __future__ import annotations

import unittest
from unittest.mock import patch

from app_utils.secure_queue import SecureQueue
from app_utils.locked_apps_repository import LockedAppRecord
from controller import Controller
from monitoring.process_monitor import ProcessMonitor, _PID_ACCESS_DENIED


APP_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


class FakeProcess:
    def __init__(
        self,
        pid: int,
        name: str = "chrome.exe",
        exe: str = APP_PATH,
        ppid: int | None = None,
        started_at: float = 10.0,
    ):
        self._started_at = started_at
        self.pid = pid
        self.info = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "ppid": ppid,
            "create_time": started_at,
        }

    def create_time(self) -> float:
        return self._started_at


class ProcessMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = ProcessMonitor()
        self.app = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)
        self.name_only_app = LockedAppRecord(id=1, app_name="chrome.exe", app_path="")

    def test_suppression_does_not_apply_across_name_and_path_rule_types(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.suppress_app(self.app, timeout=5.0)

        with patch("monitoring.process_monitor.time.time", return_value=102.0):
            self.assertFalse(self.monitor._is_suppressed(self.name_only_app))

    def test_path_rule_does_not_fallback_to_name_match(self) -> None:
        self.monitor.locked_by_path = {APP_PATH.casefold(): self.app}
        self.monitor.locked_by_name = {}
        self.assertIsNone(
            self.monitor._match_locked_app("chrome.exe", r"C:\Elsewhere\chrome.exe")
        )

    def test_hash_match_blocks_copied_binary_from_different_path(self) -> None:
        copied_path = r"C:\Elsewhere\chrome-copy.exe"
        self.monitor.locked_by_path = {}
        self.monitor.locked_by_hash = {"abc123": self.app}
        self.monitor.locked_by_name = {}

        with patch("monitoring.process_monitor.file_sha256", return_value="abc123"):
            matched = self.monitor._match_locked_app("chrome-copy.exe", copied_path)

        self.assertIsNotNone(matched)
        self.assertEqual(matched.app_path, copied_path)
        self.assertEqual(matched.match_mode, "path")

    def test_active_session_allows_new_matching_processes(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=5.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch("monitoring.process_monitor.time.time", return_value=104.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
        ):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(202, started_at=12.0),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_startup_grace_allows_first_process_from_launcher(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=5.0)

        with patch("monitoring.process_monitor.time.time", return_value=103.0):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(202, started_at=12.0),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_empty_startup_session_survives_until_startup_deadline(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=5.0)

        with patch("monitoring.process_monitor.time.time", return_value=103.0):
            self.monitor._prune_authorized_sessions()

        self.assertIsNotNone(self.monitor._find_authorized_session(self.app))

        with patch("monitoring.process_monitor.time.time", return_value=106.0):
            self.monitor._prune_authorized_sessions()

        self.assertIsNone(self.monitor._find_authorized_session(self.app))

    def test_child_process_is_allowed_after_startup_grace_if_parent_is_authorized(
        self,
    ) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch("monitoring.process_monitor.time.time", return_value=120.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
        ):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(202, ppid=101, started_at=12.0),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_live_path_session_allows_same_app_process_churn(
        self,
    ) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch("monitoring.process_monitor.time.time", return_value=120.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
        ):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(202, ppid=999, started_at=12.0),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_name_only_session_allows_same_app_process_churn(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.name_only_app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(
                101,
                self.name_only_app,
                pid_started_at=11.0,
            )

        with (
            patch("monitoring.process_monitor.time.time", return_value=120.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
        ):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.name_only_app,
                    FakeProcess(
                        202,
                        exe="",
                        ppid=999,
                        started_at=12.0,
                    ),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_recent_session_allows_process_handoff_after_original_pid_exits(
        self,
    ) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch("monitoring.process_monitor.time.time", return_value=105.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: False,
            ),
        ):
            self.assertTrue(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(202, ppid=999, started_at=12.0),
                )
            )

        self.assertIn(202, self.monitor.allowed_pids)

    def test_pid_reuse_does_not_inherit_authorized_status(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with patch("monitoring.process_monitor.time.time", return_value=120.0):
            self.assertFalse(
                self.monitor._authorize_running_instance(
                    self.app,
                    FakeProcess(101, started_at=99.0),
                )
            )

    def test_access_denied_does_not_clear_known_allowed_pid(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch.object(
                self.monitor,
                "_read_pid_started_at",
                return_value=_PID_ACCESS_DENIED,
            ),
            patch("monitoring.process_monitor.psutil.pid_exists", return_value=True),
        ):
            self.monitor.clear_dead_pids()
            self.monitor._prune_authorized_sessions()

        self.assertIn(101, self.monitor.allowed_pids)
        self.assertIsNotNone(self.monitor._find_authorized_session(self.app))

    def test_expired_session_requires_reauthentication(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=0.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        session = self.monitor._find_authorized_session(self.app)
        self.assertIsNotNone(session)
        session.startup_deadline = 100.0
        session.last_seen_at = 100.0

        with (
            patch("monitoring.process_monitor.time.time", return_value=200.0),
            patch.object(
                self.monitor, "_pid_matches_current_process", return_value=False
            ),
        ):
            self.monitor._prune_authorized_sessions()
            self.assertIsNone(self.monitor._find_authorized_session(self.app))
            self.assertFalse(
                self.monitor._authorize_running_instance(self.app, FakeProcess(202))
            )

    def test_windowless_session_expires_after_close_timeout(self) -> None:
        with patch("monitoring.process_monitor.time.time", return_value=100.0):
            self.monitor.authorize_app_session(self.app, startup_grace=5.0)
            self.monitor.allow_pid_for_session(101, self.app, pid_started_at=11.0)

        with (
            patch("monitoring.process_monitor.time.time", return_value=101.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
            patch.object(self.monitor, "_session_has_visible_window", return_value=False),
        ):
            self.monitor._prune_authorized_sessions()
            self.assertIsNotNone(self.monitor._find_authorized_session(self.app))
            self.assertIn(101, self.monitor.allowed_pids)

        with (
            patch("monitoring.process_monitor.time.time", return_value=107.0),
            patch.object(
                self.monitor,
                "_pid_matches_current_process",
                side_effect=lambda pid, started: pid == 101 and started == 11.0,
            ),
            patch.object(self.monitor, "_session_has_visible_window", return_value=False),
            patch.object(self.monitor, "_terminate_lingering_session_pid") as terminate_pid,
        ):
            self.monitor._prune_authorized_sessions()

        self.assertIsNone(self.monitor._find_authorized_session(self.app))
        self.assertNotIn(101, self.monitor.allowed_pids)
        terminate_pid.assert_called_once_with(101)

    def test_name_rule_is_upgraded_to_path_specific_match_for_runtime_session(
        self,
    ) -> None:
        candidate_path = r"C:\Portable\chrome.exe"
        self.monitor.locked_by_path = {}
        self.monitor.locked_by_hash = {}
        self.monitor.locked_by_name = {"chrome.exe": [self.name_only_app]}

        with patch("monitoring.process_monitor.file_sha256", return_value="digest-1"):
            matched = self.monitor._match_locked_app("chrome.exe", candidate_path)

        self.assertIsNotNone(matched)
        self.assertEqual(matched.match_mode, "path")
        self.assertEqual(matched.app_path, candidate_path)
        self.assertEqual(matched.file_sha256, "digest-1")


class ControllerPromptTests(unittest.TestCase):
    def test_prompt_deduplicates_name_and_path_views_of_same_app(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        path_app = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)
        name_only_app = LockedAppRecord(
            id=2, app_name="chrome.exe", app_path="", match_mode="name"
        )

        with (
            patch("controller.list_locked_apps", return_value=[path_app]),
            patch.object(controller.monitor, "suppress_app") as suppress_app,
        ):
            controller._on_intercept(name_only_app)
            controller._on_intercept(path_app)

        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])
        self.assertTrue(ui_queue.empty())
        self.assertEqual(controller._pending_prompts, [])
        suppress_app.assert_not_called()

    def test_authorized_session_still_prompts_for_new_intercept(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        path_app = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)

        with patch.object(controller.monitor, "is_app_authorized", return_value=True):
            controller._on_intercept(path_app)

        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])
        self.assertTrue(ui_queue.empty())

    def test_cancel_clears_pending_duplicates_for_same_app(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        path_app = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)
        name_only_app = LockedAppRecord(
            id=2, app_name="chrome.exe", app_path="", match_mode="name"
        )

        with patch("controller.list_locked_apps", return_value=[path_app]):
            controller._pending_prompts = [name_only_app]
            controller.prompt_in_progress = True
            controller.prompting_apps.update(controller._tracked_aliases(path_app))
            controller.on_prompt_result(path_app, False)

        self.assertEqual(controller._pending_prompts, [])

    def test_successful_unlock_does_not_immediately_reprompt_for_same_app(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        path_app = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)

        with (
            patch("controller.time.time", return_value=100.0),
            patch.object(controller, "_launch_allowed_app", return_value=True),
        ):
            controller._on_intercept(path_app)
            controller.on_prompt_result(path_app, True)
            controller._on_intercept(path_app)

        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])
        self.assertTrue(ui_queue.empty())

    def test_only_one_prompt_can_be_active_at_a_time(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        app_one = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)
        app_two = LockedAppRecord(
            id=2, app_name="notepad.exe", app_path=r"C:\Windows\System32\notepad.exe"
        )

        controller._on_intercept(app_one)
        controller._on_intercept(app_two)

        # Only app_one's prompt is queued; app_two is deferred
        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])
        self.assertTrue(ui_queue.empty())
        self.assertTrue(controller.prompt_in_progress)

        # Resolving app_one triggers the deferred prompt for app_two
        controller.on_prompt_result(app_one, False)
        self.assertTrue(controller.prompt_in_progress)
        self.assertEqual(len(controller._pending_prompts), 0)

        # app_two's prompt is now queued
        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])

    def test_second_prompt_can_queue_after_first_prompt_finishes(self) -> None:
        ui_queue = SecureQueue()
        controller = Controller(ui_queue)
        app_one = LockedAppRecord(id=1, app_name="chrome.exe", app_path=APP_PATH)
        app_two = LockedAppRecord(
            id=2, app_name="notepad.exe", app_path=r"C:\Windows\System32\notepad.exe"
        )

        controller._on_intercept(app_one)
        _ = ui_queue.get_nowait()
        controller.on_prompt_result(app_one, False)
        controller._on_intercept(app_two)

        queued = [ui_queue.get_nowait()]
        self.assertEqual([item[0] for item in queued], ["PROMPT"])
        self.assertTrue(ui_queue.empty())

    def test_windows_store_package_is_resolved_from_path(self) -> None:
        controller = Controller(SecureQueue())
        path = (
            r"C:\Program Files\WindowsApps"
            r"\Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe"
            r"\CalculatorApp.exe"
        )

        self.assertTrue(controller._is_windows_store_app_path(path))
        self.assertEqual(
            controller._windows_store_package_from_path(path),
            "Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe",
        )


if __name__ == "__main__":
    unittest.main()
