from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import threading
import time
from dataclasses import dataclass, field, replace

import psutil

from app_utils.file_identity import file_sha256, matches_expected_sha256
from app_utils.locked_apps_repository import LockedAppRecord, get_locked_targets
from app_utils.logger import logger
from app_utils.software_inventory import normalize_path
from security.policy_integrity import PolicyIntegrityError
from security.audit import log_security_event

TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('cntUsage', ctypes.wintypes.DWORD),
        ('th32ProcessID', ctypes.wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ctypes.wintypes.ULONG)),
        ('th32ModuleID', ctypes.wintypes.DWORD),
        ('cntThreads', ctypes.wintypes.DWORD),
        ('th32ParentProcessID', ctypes.wintypes.DWORD),
        ('pcPriClassBase', ctypes.wintypes.LONG),
        ('dwFlags', ctypes.wintypes.DWORD),
        ('szExeFile', ctypes.c_char * 260),
    ]

def _get_fast_pids() -> set[int]:
    try:
        kernel32 = ctypes.windll.kernel32
        hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if hProcessSnap == -1:
            return set()
            
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        procs = set()
        if kernel32.Process32First(hProcessSnap, ctypes.byref(pe32)):
            procs.add(pe32.th32ProcessID)
            while kernel32.Process32Next(hProcessSnap, ctypes.byref(pe32)):
                procs.add(pe32.th32ProcessID)
                
        kernel32.CloseHandle(hProcessSnap)
        return procs
    except Exception:
        return set()

_PID_ACCESS_DENIED = object()


@dataclass
class AuthorizedSession:
    app: LockedAppRecord
    startup_deadline: float
    last_seen_at: float
    observed_pids: dict[int, float] = field(default_factory=dict)
    windowless_since: float | None = None

    def touch(
        self,
        pid: int | None = None,
        *,
        pid_started_at: float | None = None,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        self.last_seen_at = timestamp
        if pid is not None and pid_started_at is not None:
            self.observed_pids[pid] = pid_started_at


class ProcessMonitor:
    def __init__(self):
        self.locked_by_path: dict[str, LockedAppRecord] = {}
        self.locked_by_hash: dict[str, LockedAppRecord] = {}
        self.locked_by_name: dict[str, list[LockedAppRecord]] = {}
        self.allowed_pids: dict[int, float] = {}
        self._hidden_hwnds: set[int] = set()
        self._suppressed_apps: dict[str, float] = {}
        self._authorized_sessions: dict[str, AuthorizedSession] = {}
        self._session_idle_timeout = 1.0
        self._child_spawn_grace = 5.0
        self._windowless_session_timeout = 0.0
        self._state_lock = threading.RLock()
        self._last_db_refresh = 0.0
        self._monitor_start_time: float | None = None
        self._known_pids: set[int] = _get_fast_pids()

    def mark_monitoring_started(self):
        """Record the time when monitoring begins. Processes started before this
        time are considered pre-existing and will not trigger intercept prompts."""
        self._monitor_start_time = time.time()

    def refresh_locked_apps(self, force: bool = False):
        """Fetches the latest list of locked applications from the database."""
        now = time.time()
        if (
            not force
            and (now - self._last_db_refresh < 1.0)
            and (self.locked_by_path or self.locked_by_name)
        ):
            return

        try:
            locked_by_path, locked_by_hash, locked_by_name = get_locked_targets()
            self.locked_by_path = locked_by_path
            self.locked_by_hash = locked_by_hash
            self.locked_by_name = locked_by_name
            self._last_db_refresh = now
        except PolicyIntegrityError as exc:
            logger.error(
                "Blocked policy refresh because integrity verification failed: %s", exc
            )
        except Exception as exc:
            logger.error("Error fetching locked apps: %s", exc)

    def add_allowed_pid(self, pid: int, *, pid_started_at: float | None = None):
        """Temporarily allows a specific instance of a locked app."""
        with self._state_lock:
            if pid_started_at is None:
                pid_started_at = self._read_pid_started_at(pid)
            if pid_started_at is not None and pid_started_at is not _PID_ACCESS_DENIED:
                self.allowed_pids[pid] = pid_started_at

    def authorize_app_session(self, app: LockedAppRecord, startup_grace: float = 3.0):
        """
        Allow a locked app to relaunch and spawn child processes after one
        successful password entry.
        """
        identities = self._app_identities(app)
        now = time.time()
        deadline = now + max(startup_grace, 0.0)

        with self._state_lock:
            session = self._find_authorized_session(app)
            if session is None:
                session = AuthorizedSession(
                    app=app,
                    startup_deadline=deadline,
                    last_seen_at=now,
                )
            else:
                session.app = app
                session.startup_deadline = max(session.startup_deadline, deadline)
                session.touch(now=now)

            for identity in identities:
                self._authorized_sessions[identity] = session

    def allow_pid_for_session(
        self,
        pid: int,
        app: LockedAppRecord,
        *,
        pid_started_at: float | None = None,
    ):
        """Allow a PID and associate it with the app's current unlock session."""
        with self._state_lock:
            if pid_started_at is None:
                pid_started_at = self._read_pid_started_at(pid)
            if pid_started_at is None or pid_started_at is _PID_ACCESS_DENIED:
                return

            self.allowed_pids[pid] = pid_started_at

            session = self._find_authorized_session(app)
            if session is not None:
                session.touch(pid=pid, pid_started_at=pid_started_at)
                for identity in self._app_identities(app):
                    self._authorized_sessions[identity] = session

    def authorize_all_running_apps(self, startup_grace: float = 3.0):
        """Create authorized sessions for all locked apps that are currently running."""
        self.refresh_locked_apps()
        now = time.time()
        deadline = now + max(startup_grace, 0.0)

        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "create_time"]):
            try:
                pid = proc.info.get("pid")
                name = (proc.info.get("name") or "").strip()
                exe_path = normalize_path(proc.info.get("exe"))
                pid_started_at = proc.info.get("create_time")

                locked_app = self._match_locked_app(name, exe_path)
                if locked_app is None:
                    continue

                identities = self._app_identities(locked_app)
                session = self._find_authorized_session(locked_app)
                if session is None:
                    session = AuthorizedSession(
                        app=locked_app,
                        startup_deadline=deadline,
                        last_seen_at=now,
                    )
                else:
                    session.startup_deadline = max(session.startup_deadline, deadline)
                    session.last_seen_at = now

                for identity in identities:
                    self._authorized_sessions[identity] = session

                if pid_started_at is not None:
                    self.allowed_pids[pid] = pid_started_at
                    session.observed_pids[pid] = pid_started_at

                logger.info(
                    "Pre-authorized running locked app: %s (PID: %s)",
                    locked_app.app_name,
                    pid,
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def suppress_app(self, app: LockedAppRecord | str, timeout: float = 5.0):
        """Ignore intercepts for an app for ``timeout`` seconds."""
        with self._state_lock:
            expires_at = time.time() + timeout
            for identity in self._app_identities(app):
                self._suppressed_apps[identity] = expires_at

    def _is_suppressed(self, app: LockedAppRecord) -> bool:
        with self._state_lock:
            now = time.time()
            suppressed = False

            for key in self._app_identities(app):
                expiry = self._suppressed_apps.get(key)
                if expiry is None:
                    continue
                if expiry > now:
                    suppressed = True
                    continue
                del self._suppressed_apps[key]

            return suppressed

    def _app_identities(self, app: LockedAppRecord | str) -> tuple[str, ...]:
        if isinstance(app, LockedAppRecord):
            identity = app.identity
            return (identity,) if identity else ("",)

        value = str(app or "").strip()
        if not value:
            return ("",)
        return (value.casefold(),)

    def _find_authorized_session(
        self, app: LockedAppRecord | str
    ) -> AuthorizedSession | None:
        for identity in self._app_identities(app):
            if not identity:
                continue
            session = self._authorized_sessions.get(identity)
            if session is not None:
                return session
        return None

    def is_app_authorized(self, app: LockedAppRecord) -> bool:
        """Check if the app currently has an active authorized session."""
        with self._state_lock:
            session = self._find_authorized_session(app)
            if session is None:
                return False
            if session.observed_pids:
                any_alive = any(
                    self._pid_matches_current_process(pid, started_at)
                    for pid, started_at in session.observed_pids.items()
                )
                if any_alive:
                    return True
            return False

    def clear_dead_pids(self):
        """Removes PIDs from the allowed list if the process has died."""
        with self._state_lock:
            dead_pids = [
                pid
                for pid, pid_started_at in self.allowed_pids.items()
                if not self._pid_matches_current_process(pid, pid_started_at)
            ]
            for pid in dead_pids:
                del self.allowed_pids[pid]

    def _prune_authorized_sessions(self):
        now = time.time()
        with self._state_lock:
            expired_sessions: set[int] = set()
            unique_sessions: dict[int, AuthorizedSession] = {}

            for session in self._authorized_sessions.values():
                unique_sessions[id(session)] = session

            for session in unique_sessions.values():
                dead_pids = {
                    pid
                    for pid, pid_started_at in session.observed_pids.items()
                    if not self._pid_matches_current_process(pid, pid_started_at)
                }
                if dead_pids:
                    for pid in dead_pids:
                        del session.observed_pids[pid]

                if session.observed_pids:
                    if now <= session.startup_deadline:
                        session.windowless_since = None
                        continue

                    if self._session_has_visible_window(session):
                        session.windowless_since = None
                        continue

                    if session.windowless_since is None:
                        session.windowless_since = now
                        continue

                    if (
                        now - session.windowless_since
                        <= self._windowless_session_timeout
                    ):
                        continue

                    for pid in list(session.observed_pids):
                        self.allowed_pids.pop(pid, None)
                        self._terminate_lingering_session_pid(pid)
                    session.observed_pids.clear()
                    logger.info(
                        "Expired unlocked session for %s after its windows closed.",
                        session.app.app_name,
                    )
                    expired_sessions.add(id(session))
                    continue

                if now <= session.startup_deadline:
                    continue

                if now - session.last_seen_at <= self._session_idle_timeout:
                    continue

                expired_sessions.add(id(session))

            if not expired_sessions:
                return

            for identity, session in list(self._authorized_sessions.items()):
                if id(session) in expired_sessions:
                    del self._authorized_sessions[identity]

    def _authorize_running_instance(
        self, app: LockedAppRecord, proc: psutil.Process
    ) -> bool:
        with self._state_lock:
            session = self._find_authorized_session(app)
            if session is None:
                return False

            pid = (
                proc.info.get("pid")
                if (isinstance(proc.info, dict) and "pid" in proc.info)
                else proc.pid
            )
            pid_started_at = self._get_process_started_at(proc)
            if pid_started_at is None:
                return False

            if (
                self.allowed_pids.get(pid) == pid_started_at
                or session.observed_pids.get(pid) == pid_started_at
            ):
                session.touch(pid=pid, pid_started_at=pid_started_at)
                self.allowed_pids[pid] = pid_started_at
                return True

            if pid in self.allowed_pids or pid in session.observed_pids:
                return False

            now = time.time()
            if now <= session.startup_deadline:
                session.touch(pid=pid, pid_started_at=pid_started_at, now=now)
                self.allowed_pids[pid] = pid_started_at
                for identity in self._app_identities(app):
                    self._authorized_sessions[identity] = session
                logger.info(
                    "Allowed PID %s for %s during authenticated startup grace",
                    pid,
                    app.app_name,
                )
                return True

            session_has_live_process = any(
                self._pid_matches_current_process(known_pid, known_started_at)
                for known_pid, known_started_at in session.observed_pids.items()
            )
            if not session_has_live_process:
                if now - session.last_seen_at > self._child_spawn_grace:
                    return False

            session.touch(pid=pid, pid_started_at=pid_started_at, now=now)
            self.allowed_pids[pid] = pid_started_at
            session.startup_deadline = max(
                session.startup_deadline,
                now + self._child_spawn_grace,
            )
            for identity in self._app_identities(app):
                self._authorized_sessions[identity] = session
            logger.info(
                "Allowed PID %s for %s via active unlocked session",
                pid,
                app.app_name,
            )
            return True

    def scan_processes(self, callback):
        """
        Scans for running processes that match the locked apps list.
        If a restricted app is found and not in allowed_pids, it terminates it
        and triggers the callback function.
        """
        self.refresh_locked_apps()
        self.clear_dead_pids()
        self._prune_authorized_sessions()

        if not self.locked_by_path and not self.locked_by_name:
            return

        intercepted_apps: dict[str, tuple[LockedAppRecord, list[psutil.Process], bool]] = {}

        current_pids = _get_fast_pids()
        if not current_pids:
            return
            
        new_pids = current_pids - self._known_pids
        self._known_pids = current_pids

        if not new_pids:
            return

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = (proc.name() or "").strip()
                exe_path = normalize_path(proc.exe())
                create_time = proc.create_time()

                if create_time is not None and self._monitor_start_time is not None:
                    if create_time < self._monitor_start_time:
                        continue

                locked_app = self._match_locked_app(name, exe_path)
                if locked_app is None:
                    continue

                if self._authorize_running_instance(locked_app, proc):
                    self._unhide_all_windows()
                    continue

                if pid in self.allowed_pids:
                    self._unhide_all_windows()
                    continue

                if self._is_suppressed(locked_app):
                    continue

                if pid not in self.allowed_pids:
                    app_id = locked_app.app_name
                    if app_id not in intercepted_apps:
                        intercepted_apps[app_id] = (locked_app, [], False)
                    intercepted_apps[app_id][1].append(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        for app_id, (locked_app, procs, _) in intercepted_apps.items():
            access_denied_count = 0
            for proc in procs:
                pid = proc.pid
                logger.warning(
                    "Intercepted locked application: %s (PID: %s)",
                    locked_app.app_name,
                    pid,
                )
                try:
                    try:
                        self._hide_app_windows(proc.pid)
                        proc.terminate()
                        proc.kill()
                    except psutil.NoSuchProcess:
                        pass
                except psutil.AccessDenied:
                    access_denied_count += 1
                    logger.error(
                        "Access denied while terminating locked application %s (PID: %s).",
                        locked_app.app_name,
                        pid,
                    )
            
            # If all intercepted processes for this app threw AccessDenied, it's a full failure
            if access_denied_count > 0 and access_denied_count == len(procs):
                log_security_event(
                    "TERMINATION_DENIED",
                    f"Failed to terminate locked application {locked_app.app_name} because SecureApp Locker lacked process access."
                )
                self.suppress_app(locked_app, timeout=5.0)
                callback(
                    replace(
                        locked_app,
                        integrity_issue=(
                            "SecureApp Locker detected a locked application but could not "
                            "terminate it. Run the locker with administrator rights to "
                            "enforce elevated targets."
                        ),
                    )
                )
            else:
                callback(locked_app)

    def _match_locked_app(
        self, process_name: str, process_path: str
    ) -> LockedAppRecord | None:
        normalized_process_path = normalize_path(process_path) if process_path else ""
        if normalized_process_path:
            by_path_match = self.locked_by_path.get(normalized_process_path.casefold())
            if by_path_match is not None:
                if by_path_match.file_sha256 and not matches_expected_sha256(
                    process_path, by_path_match.file_sha256
                ):
                    return replace(
                        by_path_match,
                        integrity_issue=(
                            "The protected executable no longer matches the file that was originally locked. "
                            "Review the application path before unlocking it."
                        ),
                    )
                return by_path_match

            process_digest = file_sha256(process_path)
            if process_digest:
                by_hash_match = self.locked_by_hash.get(process_digest)
                if by_hash_match is not None:
                    return replace(
                        by_hash_match,
                        app_path=normalized_process_path,
                        match_mode="path",
                        file_sha256=process_digest,
                    )

        if process_name:
            name_matches = self.locked_by_name.get(process_name.casefold(), [])
            if name_matches:
                matched = name_matches[0]
                if normalized_process_path:
                    return replace(
                        matched,
                        app_path=normalized_process_path,
                        match_mode="path",
                        file_sha256=file_sha256(process_path),
                    )
                return matched

        return None

    def _read_pid_started_at(self, pid: int) -> float | object | None:
        try:
            return float(psutil.Process(pid).create_time())
        except psutil.AccessDenied:
            return _PID_ACCESS_DENIED
        except (
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            ValueError,
        ):
            return None

    def _get_process_started_at(self, proc: psutil.Process) -> float | None:
        info = proc.info if isinstance(getattr(proc, "info", None), dict) else {}
        started_at = info.get("create_time")
        if started_at is not None:
            try:
                return float(started_at)
            except (TypeError, ValueError):
                return None

        try:
            return float(proc.create_time())
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            ValueError,
        ):
            return None

    def _pid_matches_current_process(
        self, pid: int, expected_started_at: float
    ) -> bool:
        current_started_at = self._read_pid_started_at(pid)
        if current_started_at is _PID_ACCESS_DENIED:
            return psutil.pid_exists(pid)
        if current_started_at is None:
            return False
        return current_started_at == expected_started_at

    def _session_has_visible_window(self, session: AuthorizedSession) -> bool:
        if os.name != "nt":
            return True

        live_pids = {
            pid
            for pid, started_at in session.observed_pids.items()
            if self._pid_matches_current_process(pid, started_at)
        }
        if not live_pids:
            return False

        try:
            user32 = ctypes.windll.user32
            visible = False

            enum_proc = ctypes.WINFUNCTYPE(
                ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p
            )

            def window_belongs_to_session(hwnd) -> bool:
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                return int(pid.value) in live_pids

            dwmapi = ctypes.windll.dwmapi
            
            def is_real_visible_window(hwnd) -> bool:
                if not user32.IsWindowVisible(hwnd):
                    return False
                
                # Check for DWM Cloaking (UWP apps use this to hide windows without removing WS_VISIBLE)
                cloaked = ctypes.c_int(0)
                if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0:
                    if cloaked.value != 0:
                        return False
                        
                # Check for non-zero size (ignore tiny 1x1 hidden windows) and off-screen windows
                rect = ctypes.wintypes.RECT()
                if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                    width = rect.right - rect.left
                    height = rect.bottom - rect.top
                    if width <= 10 or height <= 10:
                        return False
                    # Many system tray apps hide their window by moving it far off-screen
                    if rect.left <= -10000 or rect.top <= -10000:
                        return False
                        
                logger.debug("Window %s is truly visible! Size: %sx%s, Pos: (%s, %s)", hwnd, width, height, rect.left, rect.top)
                return True

            def check_child_window(hwnd, _lparam):
                nonlocal visible
                if is_real_visible_window(hwnd) and window_belongs_to_session(hwnd):
                    visible = True
                    return False
                return True

            def check_window(hwnd, _lparam):
                nonlocal visible
                if not is_real_visible_window(hwnd):
                    return True

                if window_belongs_to_session(hwnd):
                    visible = True
                    return False
                user32.EnumChildWindows(hwnd, enum_proc(check_child_window), 0)
                if visible:
                    return False
                return True

            user32.EnumWindows(enum_proc(check_window), 0)
            return visible
        except Exception as exc:
            logger.debug("Unable to inspect visible app windows: %s", exc)
            return True

    def _hide_app_windows(self, target_pid: int) -> None:
        try:
            if os.name != "nt":
                return
            user32 = ctypes.windll.user32
            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x00080000
            LWA_ALPHA = 0x00000002
            enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            def hide_window(hwnd, _lparam):
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value == target_pid:
                    parent = user32.GetAncestor(hwnd, 2) # GA_ROOT
                    if parent and parent != hwnd:
                        # Make the window instantly transparent instead of hiding it permanently
                        exstyle = user32.GetWindowLongW(parent, GWL_EXSTYLE)
                        user32.SetWindowLongW(parent, GWL_EXSTYLE, exstyle | WS_EX_LAYERED)
                        user32.SetLayeredWindowAttributes(parent, 0, 0, LWA_ALPHA)
                        self._hidden_hwnds.add(parent)
                return True
            user32.EnumWindows(enum_proc(hide_window), 0)
            user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(hide_window), 0)
        except Exception as exc:
            logger.debug("Failed to hide windows for PID %s: %s", target_pid, exc)

    def _unhide_all_windows(self) -> None:
        if not self._hidden_hwnds:
            return
        try:
            if os.name != "nt":
                self._hidden_hwnds.clear()
                return
            user32 = ctypes.windll.user32
            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x00080000
            for hwnd in list(self._hidden_hwnds):
                exstyle = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                if exstyle & WS_EX_LAYERED:
                    user32.SetWindowLongW(hwnd, GWL_EXSTYLE, exstyle & ~WS_EX_LAYERED)
            self._hidden_hwnds.clear()
        except Exception as exc:
            logger.debug("Failed to unhide windows: %s", exc)

    def _terminate_lingering_session_pid(self, pid: int) -> None:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            OSError,
        ):
            pass
