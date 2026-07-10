import os
import queue
import threading
from pathlib import Path
import subprocess
import sys
import time
import ctypes

import pystray
import psutil
from PIL import Image, ImageTk

from app_utils.locked_apps_repository import LockedAppRecord, list_locked_apps
from app_utils.logger import logger
from app_utils.paths import APP_DISPLAY_NAME, get_data_dir
from app_utils.secure_queue import SecureQueue
from app_utils.startup import BACKGROUND_ARG, ensure_startup_shortcut, ensure_start_menu_shortcut, is_background_launch
from app_utils.tk_runtime import bootstrap_tk_runtime, relaunch_with_compatible_python
from config.config_manager import checkpoint_database, get_connection, init_db

bootstrap_tk_runtime()

import tkinter as tk
from tkinter import messagebox

from controller import Controller
from security.auth_manager import (
    is_master_password_set,
    prepare_auth_runtime,
)
from security.audit import (
    AuditIntegrityError,
    log_security_event,
    verify_audit_integrity_safely,
)
from security.policy_integrity import PolicyIntegrityError
from ui.dashboard import Dashboard
from ui.password_prompt import PasswordPrompt, prompt_for_master_password

WINDOWLESS_RELAUNCH_ENV = "SECUREAPP_LOCKER_WINDOWLESS_RELAUNCHED"
SINGLE_INSTANCE_MUTEX_NAME = "Local\\ZenvorLockApp"
ERROR_ALREADY_EXISTS = 183

_single_instance_mutex_handle: int | None = None


def resolve_asset_path(filename: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "assets" / filename
    return Path(__file__).resolve().parent / "assets" / filename


def load_app_icon_image(size: tuple[int, int]) -> Image.Image | None:
    icon_path = resolve_asset_path("app_icon.png")
    if not icon_path.exists():
        logger.warning("Application icon asset not found at %s", icon_path)
        return None

    try:
        with Image.open(icon_path) as image:
            return image.convert("RGBA").resize(
                size,
                getattr(Image, "Resampling", Image).LANCZOS,
            )
    except Exception as exc:
        logger.warning("Failed to load application icon from %s: %s", icon_path, exc)
        return None


def load_tray_icon() -> Image.Image:
    icon_image = load_app_icon_image((64, 64))
    if icon_image is None:
        return Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    return icon_image


def acquire_single_instance_lock() -> bool:
    global _single_instance_mutex_handle

    if _single_instance_mutex_handle is not None:
        return True
    if os.name != "nt":
        return True

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.c_wchar_p,
        )
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_bool

        handle = kernel32.CreateMutexW(None, True, SINGLE_INSTANCE_MUTEX_NAME)
        last_error = ctypes.get_last_error()
        if not handle:
            logger.warning("Failed to create single-instance mutex.")
            return True

        if last_error == ERROR_ALREADY_EXISTS:
            kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            WAIT_ABANDONED = 0x00000080
            if kernel32.WaitForSingleObject(handle, 0) == WAIT_ABANDONED:
                kernel32.CloseHandle(handle)
                handle = kernel32.CreateMutexW(None, True, SINGLE_INSTANCE_MUTEX_NAME)
                _single_instance_mutex_handle = int(handle)
                return True
            kernel32.CloseHandle(handle)
            return False

        _single_instance_mutex_handle = int(handle)
        return True
    except Exception as exc:
        logger.warning("Single-instance guard failed: %s", exc)
        return True


def release_single_instance_lock() -> None:
    global _single_instance_mutex_handle

    if _single_instance_mutex_handle is None or os.name != "nt":
        _single_instance_mutex_handle = None
        return

    handle = _single_instance_mutex_handle
    _single_instance_mutex_handle = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.ReleaseMutex.argtypes = (ctypes.c_void_p,)
        kernel32.ReleaseMutex.restype = ctypes.c_bool
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_bool
        kernel32.ReleaseMutex(handle)
        kernel32.CloseHandle(handle)
    except Exception as exc:
        logger.warning("Failed to release single-instance mutex: %s", exc)


def notify_existing_instance() -> None:
    logger.info("%s is already running; signaling to open dashboard.", APP_DISPLAY_NAME)
    try:
        (get_data_dir() / ".open_dashboard").touch()
    except Exception:
        pass


WATCHDOG_ARG = "--watchdog"
WATCHDOG_PARENT_PID_ARG = "--watchdog-parent-pid"
WATCHDOG_PARENT_STARTED_AT_ARG = "--watchdog-parent-started-at"
INTENTIONAL_EXIT_MARKER = ".secureapp-intentional-exit"


def _is_running_as_administrator() -> bool:
    try:
        ctypes = __import__("ctypes")
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _preferred_python_executable() -> str:
    executable = Path(sys.executable).resolve(strict=False)
    if executable.name.casefold() == "pythonw.exe":
        return str(executable)

    pythonw = executable.with_name("pythonw.exe")
    if pythonw.is_file():
        return str(pythonw)

    return str(executable)


def ensure_windowless_python_session(script_path: str | Path) -> bool:
    if os.name != "nt" or getattr(sys, "frozen", False):
        return True

    if os.getenv(WINDOWLESS_RELAUNCH_ENV) == "1":
        return True

    preferred_executable = _preferred_python_executable()
    current_executable = str(Path(sys.executable).resolve(strict=False))
    if Path(preferred_executable).resolve(strict=False) == Path(
        current_executable
    ).resolve(strict=False):
        return True

    env = os.environ.copy()
    env[WINDOWLESS_RELAUNCH_ENV] = "1"

    try:
        subprocess.Popen(
            [preferred_executable, str(Path(script_path).resolve()), *sys.argv[1:]],
            cwd=str(Path(script_path).resolve().parent),
            env=env,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return False
    except OSError as exc:
        logger.error(
            "Failed to relaunch SecureApp Locker without a console window: %s", exc
        )
        return True


def ensure_administrator_session() -> str:
    if os.name != "nt" or _is_running_as_administrator():
        return "ready"

    try:
        ctypes = __import__("ctypes")
        if getattr(sys, "frozen", False):
            executable = sys.executable
            parameters = subprocess.list2cmdline(sys.argv[1:])
        else:
            executable = _preferred_python_executable()
            parameters = subprocess.list2cmdline(
                [str(Path(__file__).resolve()), *sys.argv[1:]]
            )

        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            parameters,
            None,
            0,
        )
        if int(result) > 32:
            return "relaunched"
        return "failed"
    except Exception as exc:
        logger.error(
            "Failed to relaunch SecureApp Locker with administrator rights: %s", exc
        )
        return "failed"


def _intentional_exit_marker_path() -> Path:
    return get_data_dir() / INTENTIONAL_EXIT_MARKER


def _clear_intentional_exit_marker() -> None:
    try:
        _intentional_exit_marker_path().unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("Failed to clear shutdown marker: %s", exc)


def _mark_intentional_exit() -> None:
    try:
        marker_path = _intentional_exit_marker_path()
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text("intentional-exit", encoding="utf-8")
        with open(marker_path, "rb") as f:
            os.fsync(f.fileno())
    except OSError as exc:
        logger.warning("Failed to write shutdown marker: %s", exc)


def _build_launch_command(
    *,
    watchdog: bool,
    parent_pid: int | None = None,
    parent_started_at: float | None = None,
    background: bool | None = None,
) -> list[str]:
    if getattr(sys, "frozen", False):
        command = [sys.executable]
    else:
        command = [_preferred_python_executable(), str(Path(__file__).resolve())]

    if background is None:
        background = is_background_launch()
    if background:
        command.append(BACKGROUND_ARG)

    if watchdog:
        if parent_pid is None or parent_started_at is None:
            raise ValueError("Watchdog launch requires the parent PID and start time.")
        command.extend(
            [
                WATCHDOG_ARG,
                WATCHDOG_PARENT_PID_ARG,
                str(parent_pid),
                WATCHDOG_PARENT_STARTED_AT_ARG,
                str(parent_started_at),
            ]
        )

    return command


def _spawn_watchdog() -> subprocess.Popen | None:
    current_pid = os.getpid()
    try:
        current_started_at = psutil.Process(current_pid).create_time()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        ValueError,
    ) as exc:
        logger.warning(
            "Failed to determine the current process start time for watchdog: %s", exc
        )
        return None

    command = _build_launch_command(
        watchdog=True,
        parent_pid=current_pid,
        parent_started_at=current_started_at,
        background=is_background_launch(),
    )
    try:
        return subprocess.Popen(
            command,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        logger.warning("Failed to launch watchdog process: %s", exc)
        return None


def _watchdog_should_exit(parent_pid: int, expected_started_at: float) -> bool:
    try:
        parent_process = psutil.Process(parent_pid)
        return float(parent_process.create_time()) != expected_started_at
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError):
        return True
    except psutil.AccessDenied:
        return False


def run_watchdog(parent_pid: int, parent_started_at: float) -> None:
    while True:
        if _watchdog_should_exit(parent_pid, parent_started_at):
            if _intentional_exit_marker_path().exists():
                return

            logger.warning("SecureApp Locker exited unexpectedly; restarting it.")
            try:
                subprocess.Popen(
                    _build_launch_command(watchdog=False, background=is_background_launch()),
                    close_fds=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception as exc:
                logger.error("Watchdog failed to relaunch SecureApp Locker: %s", exc)
            return
        time.sleep(1.0)


class SecureAppLocker:
    def __init__(self):
        init_db()

        self.ui_queue = SecureQueue()
        self.controller = Controller(self.ui_queue)

        self.root = tk.Tk()
        self._set_windows_app_id()
        self.app_icons = self._load_window_icons()
        if self.app_icons:
            self.root.iconphoto(True, *self.app_icons)
        self.root.withdraw()
        self.root.protocol("WM_DELETE_WINDOW", self.request_exit)

        self.dashboard = None
        self._active_prompt_dialog: tk.Toplevel | None = None
        self._startup_error = ""
        self._dashboard_authenticated = False

        ok, message = prepare_auth_runtime()
        if not ok:
            self._startup_error = message
        else:
            try:
                conn = get_connection()
                try:
                    verify_audit_integrity_safely(conn)
                finally:
                    conn.close()
                list_locked_apps()
            except AuditIntegrityError:
                self._startup_error = "The security audit trail appears to have been modified outside the app."
            except PolicyIntegrityError:
                self._startup_error = "The locked-application policy appears to have been modified outside the app."
            except Exception as exc:
                logger.error("Error validating startup lock policy: %s", exc)
                self._startup_error = (
                    "Failed to validate the locked-application policy."
                )

        self._watchdog_process: subprocess.Popen | None = None

        self.icon = pystray.Icon(
            "SecureAppLocker",
            load_tray_icon(),
            APP_DISPLAY_NAME,
            menu=pystray.Menu(
                pystray.MenuItem("Dashboard", self.show_dashboard),
                pystray.MenuItem("Exit", self.request_exit),
            ),
        )

        self.poll_queue()
        ensure_startup_shortcut()
        ensure_start_menu_shortcut()

    def _set_windows_app_id(self):
        try:
            ctypes = __import__("ctypes")
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "SecureAppLocker.App"
            )
        except Exception:
            pass

    def _load_window_icons(self):
        sizes = [
            (16, 16),
            (24, 24),
            (32, 32),
            (48, 48),
            (64, 64),
            (128, 128),
            (256, 256),
        ]
        photos = []
        for size in sizes:
            img = load_app_icon_image(size)
            if img:
                photos.append(ImageTk.PhotoImage(img))
        return photos

    def poll_queue(self):
        try:
            req_file = get_data_dir() / ".open_dashboard"
            if req_file.exists():
                try:
                    req_file.unlink()
                except OSError:
                    pass
                self.show_dashboard()
        except Exception:
            pass

        try:
            while True:
                msg, payload = self.ui_queue.get_nowait()
                if not msg:
                    break
                if msg == "PROMPT":
                    if (
                        self._active_prompt_dialog is not None
                        and self._active_prompt_dialog.winfo_exists()
                    ):
                        self.ui_queue.put("PROMPT", payload)
                        break
                    if not self.controller.prompt_in_progress:
                        if self._active_prompt_dialog is None:
                            self.controller._process_pending_prompts()
                        continue
                    logger.info("Processing UI prompt for %s", payload.app_name)
                    self.show_prompt(payload)
                    break
                elif msg == "EXIT_REQUEST":
                    self.confirm_exit()
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def show_prompt(self, locked_app: LockedAppRecord):
        if locked_app.integrity_issue:
            log_security_event(
                "RULE_TAMPER_DETECTED",
                f"Blocked {locked_app.app_name} because the file identity at the locked path changed.",
            )
            messagebox.showerror(
                "Launch Blocked",
                locked_app.integrity_issue,
                parent=self.dashboard or self.root,
            )
            self.controller.on_prompt_result(locked_app, False)
            return

        if (
            self._active_prompt_dialog is not None
            and self._active_prompt_dialog.winfo_exists()
        ):
            logger.warning(
                "Password dialog already active; deferring prompt for %s",
                locked_app.app_name,
            )
            return

        logger.info("Showing password prompt for %s", locked_app.app_name)

        def cb(success, app):
            self.controller.on_prompt_result(app, success)
            self._active_prompt_dialog = None

        prompt_parent = self.root
        if self.dashboard is not None and self.dashboard.winfo_exists():
            prompt_parent = self.dashboard

        dialog = tk.Toplevel(prompt_parent)
        if prompt_parent.winfo_exists() and bool(int(prompt_parent.winfo_viewable())):
            dialog.transient(prompt_parent)
        PasswordPrompt(dialog, locked_app, cb)
        self._active_prompt_dialog = dialog

    def show_dashboard(self, icon=None, item=None):
        if not self._dashboard_authenticated and not self.require_startup_access():
            logger.info("Dashboard authentication cancelled.")
            return
        self._dashboard_authenticated = True

        if self.dashboard is None or not self.dashboard.winfo_exists():
            self.dashboard = Dashboard(self.root, controller=self.controller)
            self.dashboard.protocol("WM_DELETE_WINDOW", self.hide_dashboard)
        else:
            self.dashboard.deiconify()

        self.dashboard.lift()
        self.dashboard.attributes("-topmost", True)
        self.dashboard.after(10, lambda: self.dashboard.attributes("-topmost", False))
        self.dashboard.focus_force()

    def hide_dashboard(self):
        if self.dashboard and self.dashboard.winfo_exists():
            self.dashboard.withdraw()

    def request_exit(self, icon=None, item=None):
        self.ui_queue.put("EXIT_REQUEST", None)

    def confirm_exit(self):
        if getattr(self, "_exit_prompt_active", False):
            return

        if is_master_password_set() or list_locked_apps():
            self._exit_prompt_active = True
            try:
                success = prompt_for_master_password(
                    self.root,
                    title=f"Exit {APP_DISPLAY_NAME}",
                    message=f"Enter the master password to exit {APP_DISPLAY_NAME}.",
                    action_label="Exit",
                )
            finally:
                self._exit_prompt_active = False

            if not success:
                logger.info("Exit authentication cancelled.")
                return

        self.perform_exit()

    def perform_exit(self):
        logger.info("Exiting application...")
        _mark_intentional_exit()

        if self._watchdog_process is not None:
            try:
                proc = psutil.Process(self._watchdog_process.pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

        self.controller.running = False
        try:
            checkpoint_database()
        except Exception as exc:
            logger.error("Failed to checkpoint database during shutdown: %s", exc)

        release_single_instance_lock()

        self.root.quit()
        self.root.destroy()

        try:
            self.icon.visible = False
        except Exception:
            pass

        os._exit(0)

    def require_startup_access(self) -> bool:
        if not is_master_password_set():
            return True

        return prompt_for_master_password(
            self.root,
            title=f"Open {APP_DISPLAY_NAME}",
            message=f"Enter the master password to open {APP_DISPLAY_NAME}.",
            action_label="Open",
        )

    def run(self):
        if self._startup_error:
            messagebox.showerror(
                "Security Error", self._startup_error, parent=self.root
            )
            self.root.destroy()
            return

        background_launch = is_background_launch()
        if not background_launch and not self.require_startup_access():
            logger.info("Startup authentication cancelled.")
            self.root.destroy()
            return
        if not background_launch:
            self._dashboard_authenticated = True

        self._watchdog_process = _spawn_watchdog()
        self.controller.start()

        threading.Thread(target=self.icon.run, daemon=True).start()

        if not background_launch:
            self.show_dashboard()
        else:
            logger.info("%s started in background protection mode.", APP_DISPLAY_NAME)

        self.root.mainloop()


if __name__ == "__main__":
    if not ensure_windowless_python_session(Path(__file__)):
        raise SystemExit(0)

    if WATCHDOG_ARG in sys.argv:
        try:
            parent_pid = int(sys.argv[sys.argv.index(WATCHDOG_PARENT_PID_ARG) + 1])
            parent_started_at = float(
                sys.argv[sys.argv.index(WATCHDOG_PARENT_STARTED_AT_ARG) + 1]
            )
        except (ValueError, IndexError):
            raise SystemExit(1)
        run_watchdog(parent_pid, parent_started_at)
        raise SystemExit(0)

    if not acquire_single_instance_lock():
        notify_existing_instance()
        raise SystemExit(0)

    admin_session_state = ensure_administrator_session()
    if admin_session_state == "relaunched":
        raise SystemExit(0)
    if admin_session_state != "ready":
        raise SystemExit(1)
    _clear_intentional_exit_marker()
    try:
        app = SecureAppLocker()
    except tk.TclError as exc:
        release_single_instance_lock()
        if relaunch_with_compatible_python(Path(__file__), exc):
            raise SystemExit(0)
        raise
    try:
        app.run()
    finally:
        release_single_instance_lock()
