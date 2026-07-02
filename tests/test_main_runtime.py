from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main


class _FakeRoot:
    def __init__(self) -> None:
        self.destroyed = False
        self.mainloop_called = False

    def destroy(self) -> None:
        self.destroyed = True

    def mainloop(self) -> None:
        self.mainloop_called = True


class _FakeThread:
    def __init__(self, target=None, daemon=None):
        self.target = target
        self.daemon = daemon
        self.started = False

    def start(self) -> None:
        self.started = True


class MainRuntimeTests(unittest.TestCase):
    def tearDown(self) -> None:
        main._single_instance_mutex_handle = None

    def _build_app(self, *, startup_error: str = "", startup_access: bool = True):
        app = main.SecureAppLocker.__new__(main.SecureAppLocker)
        app.root = _FakeRoot()
        app.controller = SimpleNamespace(start=Mock())
        app.icon = SimpleNamespace(run=Mock())
        app.dashboard = None
        app._dashboard_authenticated = False
        app._startup_error = startup_error
        app.require_startup_access = Mock(return_value=startup_access)
        app.show_dashboard = Mock()
        return app

    def test_run_does_not_start_watchdog_when_startup_fails(self) -> None:
        app = self._build_app(startup_error="broken")

        with (
            patch("main._spawn_watchdog") as spawn_watchdog,
            patch("main.messagebox.showerror"),
        ):
            app.run()

        spawn_watchdog.assert_not_called()
        self.assertTrue(app.root.destroyed)
        app.controller.start.assert_not_called()

    def test_run_does_not_start_watchdog_when_startup_access_is_cancelled(self) -> None:
        app = self._build_app(startup_access=False)

        with patch("main._spawn_watchdog") as spawn_watchdog:
            app.run()

        spawn_watchdog.assert_not_called()
        self.assertTrue(app.root.destroyed)
        app.controller.start.assert_not_called()

    def test_run_starts_watchdog_only_after_startup_access_is_granted(self) -> None:
        app = self._build_app(startup_access=True)

        with (
            patch("main._spawn_watchdog") as spawn_watchdog,
            patch("main.is_background_launch", return_value=False),
            patch("main.threading.Thread", side_effect=lambda *args, **kwargs: _FakeThread(*args, **kwargs)),
        ):
            app.run()

        spawn_watchdog.assert_called_once()
        app.controller.start.assert_called_once()
        app.show_dashboard.assert_called_once()
        self.assertTrue(app._dashboard_authenticated)
        self.assertTrue(app.root.mainloop_called)

    def test_background_run_starts_monitor_without_opening_dashboard(self) -> None:
        app = self._build_app(startup_access=False)

        with (
            patch("main._spawn_watchdog") as spawn_watchdog,
            patch("main.is_background_launch", return_value=True),
            patch("main.threading.Thread", side_effect=lambda *args, **kwargs: _FakeThread(*args, **kwargs)),
        ):
            app.run()

        spawn_watchdog.assert_called_once()
        app.controller.start.assert_called_once()
        app.require_startup_access.assert_not_called()
        app.show_dashboard.assert_not_called()
        self.assertFalse(app._dashboard_authenticated)
        self.assertTrue(app.root.mainloop_called)

    def test_single_instance_lock_allows_non_windows_platforms(self) -> None:
        with patch("main.os.name", "posix"):
            self.assertTrue(main.acquire_single_instance_lock())

    def test_single_instance_lock_rejects_duplicate_windows_instance(self) -> None:
        fake_kernel32 = SimpleNamespace(
            CreateMutexW=Mock(return_value=123),
            CloseHandle=Mock(return_value=True),
            WaitForSingleObject=Mock(return_value=0),
        )

        with (
            patch("main.os.name", "nt"),
            patch("main.ctypes.WinDLL", return_value=fake_kernel32, create=True),
            patch("main.ctypes.get_last_error", return_value=main.ERROR_ALREADY_EXISTS),
        ):
            self.assertFalse(main.acquire_single_instance_lock())

        fake_kernel32.CloseHandle.assert_called_once_with(123)
        self.assertIsNone(main._single_instance_mutex_handle)

    def test_single_instance_lock_keeps_and_releases_mutex_handle(self) -> None:
        fake_kernel32 = SimpleNamespace(
            CreateMutexW=Mock(return_value=456),
            ReleaseMutex=Mock(return_value=True),
            CloseHandle=Mock(return_value=True),
        )

        with (
            patch("main.os.name", "nt"),
            patch("main.ctypes.WinDLL", return_value=fake_kernel32, create=True),
            patch("main.ctypes.get_last_error", return_value=0),
        ):
            self.assertTrue(main.acquire_single_instance_lock())
            self.assertEqual(main._single_instance_mutex_handle, 456)
            main.release_single_instance_lock()

        fake_kernel32.ReleaseMutex.assert_called_once_with(456)
        fake_kernel32.CloseHandle.assert_called_once_with(456)
        self.assertIsNone(main._single_instance_mutex_handle)


if __name__ == "__main__":
    unittest.main()
