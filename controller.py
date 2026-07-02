from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import PureWindowsPath
from tkinter import messagebox

import psutil

from app_utils.file_identity import matches_expected_sha256
from app_utils.locked_apps_repository import LockedAppRecord, list_locked_apps
from app_utils.logger import logger
from app_utils.paths import APP_DISPLAY_NAME
from app_utils.software_inventory import normalize_path
from monitoring.process_monitor import ProcessMonitor
from security.audit import log_security_event

AUTHORIZED_LAUNCH_GRACE = 2.0


class Controller:
    def __init__(self, ui_queue):
        self.monitor = ProcessMonitor()
        self.ui_queue = ui_queue
        self.running = False
        self.thread = None
        self.prompting_apps = set()
        self.prompt_cooldowns: dict[str, float] = {}
        self.prompt_in_progress = False
        self._pending_prompts: list[LockedAppRecord] = []
        self.lock = threading.Lock()

    def start(self):
        if not self.running:
            self.running = True
            self.monitor.mark_monitoring_started()
            logger.info("Starting controller...")
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            logger.info("Controller stopped.")

    def _run_loop(self):
        while self.running:
            try:
                self.monitor.scan_processes(self._on_intercept)
            except Exception as exc:
                logger.error("Error in monitor loop: %s", exc)
            time.sleep(0.02)

    def _on_intercept(self, locked_app: LockedAppRecord):
        tracked_aliases = self._tracked_aliases(locked_app)
        now = time.time()

        with self.lock:
            self._prune_prompt_cooldowns(now)

            if self.prompt_in_progress:
                if any(alias in self.prompting_apps for alias in tracked_aliases):
                    return
                if not self._has_pending_prompt_for_aliases(tracked_aliases):
                    self._pending_prompts.append(locked_app)
                return
            if any(alias in self.prompting_apps for alias in tracked_aliases):
                return
            if any(
                self.prompt_cooldowns.get(alias, 0.0) > now for alias in tracked_aliases
            ):
                return
            self.prompt_in_progress = True
            self.prompting_apps.update(tracked_aliases)

        logger.info("Queueing UI prompt for %s", locked_app.app_name)
        self.ui_queue.put("PROMPT", locked_app)

    CANCEL_COOLDOWN = 5.0

    def on_prompt_result(self, locked_app: LockedAppRecord, success: bool):
        tracked_aliases = self._tracked_aliases(locked_app)

        if not success:
            with self.lock:
                self._remove_pending_prompts_for_aliases(tracked_aliases)
                self.prompting_apps.difference_update(tracked_aliases)
                self.prompt_in_progress = False
                self._hold_prompt_aliases(tracked_aliases, timeout=self.CANCEL_COOLDOWN)
            self._process_pending_prompts()
            return

        launched = False
        try:
            launched = self._launch_allowed_app(locked_app)
        finally:
            with self.lock:
                self._remove_pending_prompts_for_aliases(tracked_aliases)
                self.prompting_apps.difference_update(tracked_aliases)
                self.prompt_in_progress = False
                if launched:
                    self._hold_prompt_aliases(
                        tracked_aliases, timeout=AUTHORIZED_LAUNCH_GRACE
                    )
        self._process_pending_prompts()

    def _launch_allowed_app(self, locked_app: LockedAppRecord) -> bool:
        """
        Start a locked application after successful authentication and keep
        its follow-up processes authorized for the current app run.
        """
        target = self._resolve_launch_target(locked_app)
        if target is None or not target.app_path:
            logger.error("Unable to resolve a launch path for %s", locked_app.app_name)
            messagebox.showerror(
                "Error",
                f"{APP_DISPLAY_NAME} does not have a valid executable path for {locked_app.app_name}.",
            )
            return False

        if target.integrity_issue:
            messagebox.showerror("Launch Blocked", target.integrity_issue)
            log_security_event(
                "LAUNCH_BLOCKED",
                f"Blocked launch for {target.app_name} because its identity no longer matches the locked rule.",
            )
            return False

        path = normalize_path(target.app_path)

        try:
            if not os.path.exists(path):
                logger.error("Path not found: %s", path)
                messagebox.showerror("Error", f"Executable not found at {path}")
                return False

            if target.file_sha256 and not matches_expected_sha256(
                path, target.file_sha256
            ):
                messagebox.showerror(
                    "Launch Blocked",
                    (
                        "The executable at this path has changed since it was locked. "
                        "Unlock or relock the application after you verify the file."
                    ),
                )
                log_security_event(
                    "LAUNCH_BLOCKED",
                    f"Blocked launch for {target.app_name} because its stored file identity no longer matched.",
                )
                return False

            self.monitor.authorize_app_session(
                target, startup_grace=AUTHORIZED_LAUNCH_GRACE
            )

            if self._is_windows_store_app_path(path):
                return self._launch_windows_store_app(target, path)

            cwd = os.path.dirname(path) or None
            try:
                # Launch via explorer to drop elevated privileges and run as the desktop user.
                # This works for both regular desktop apps and UWP/Store apps.
                subprocess.Popen(["explorer.exe", path], cwd=cwd, close_fds=True)
                logger.info("Successfully started %s via explorer.exe from %s", target.app_name, path)
                return True
            except Exception as e:
                logger.error("Failed to start %s via explorer.exe: %s", target.app_name, e)
                # Fallback to direct execution if explorer fails
                try:
                    subprocess.Popen([path], cwd=cwd, close_fds=True)
                    logger.info("Successfully started %s directly from %s", target.app_name, path)
                    return True
                except Exception as exc2:
                    raise exc2
        except Exception as exc:
            logger.error("Failed to start %s: %s", target.app_name, exc)
            messagebox.showerror("Error", f"Failed to launch {target.app_name}: {exc}")
            return False

    def _is_windows_store_app_path(self, path: str) -> bool:
        return any(part.casefold() == "windowsapps" for part in PureWindowsPath(path).parts)

    def _windows_store_package_from_path(self, path: str) -> str:
        parts = PureWindowsPath(path).parts
        for index, part in enumerate(parts):
            if part.casefold() == "windowsapps" and index + 1 < len(parts):
                return parts[index + 1]
        return ""

    def _resolve_amuid(self, path: str) -> str:
        package_full_name = self._windows_store_package_from_path(path)
        if not package_full_name:
            return ""
            
        manifest_path = os.path.join(os.environ.get("ProgramW6432", "C:\\Program Files"), "WindowsApps", package_full_name, "AppxManifest.xml")
        if not os.path.exists(manifest_path):
            parts = package_full_name.split('_')
            if len(parts) >= 2:
                return f"{parts[0]}_{parts[-1]}!App"
            return ""
            
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            for elem in root.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]
                    
            identity = root.find('Identity')
            if identity is None: return ""
            
            parts = package_full_name.split("_")
            if len(parts) >= 2:
                package_family_name = identity.get('Name') + "_" + parts[-1]
            else:
                return ""
                
            applications = root.find('Applications')
            if applications is None: return ""
            
            target_exe = os.path.basename(path).casefold()
            for app in applications.findall('Application'):
                exe = app.get('Executable', '')
                if os.path.basename(exe).casefold() == target_exe:
                    return f"{package_family_name}!{app.get('Id')}"
                    
            first_app = applications.find('Application')
            if first_app is not None:
                return f"{package_family_name}!{first_app.get('Id')}"
                
            return ""
        except Exception as e:
            logger.error("Failed to parse manifest: %s", e)
            return ""

    def _launch_windows_store_app(self, target: LockedAppRecord, path: str) -> bool:
        amuid = self._resolve_amuid(path)
        if not amuid:
            logger.error("Unable to resolve Windows Store AMUID for %s", path)
            messagebox.showerror(
                "Launch Failed",
                f"Failed to launch {target.display_name}. Ensure it is installed correctly.",
            )
            return False
            
        try:
            logger.info("Launching Windows Store app %s via AMUID %s", target.app_name, amuid)
            subprocess.Popen(["explorer.exe", f"shell:AppsFolder\\{amuid}"], close_fds=True)
            return True
        except Exception as exc:
            logger.error("Failed to launch Windows Store app %s: %s", target.app_name, exc)
            messagebox.showerror(
                "Launch Failed",
                f"Failed to launch {target.display_name}. Try opening it again from Start.",
            )
            return False



    def _hold_prompt_aliases(self, aliases: set[str], *, timeout: float) -> None:
        if timeout <= 0:
            return

        expires_at = time.time() + timeout
        for alias in aliases:
            if alias:
                self.prompt_cooldowns[alias] = expires_at

    def _prune_prompt_cooldowns(self, now: float | None = None) -> None:
        current_time = time.time() if now is None else now
        expired_aliases = [
            alias
            for alias, expires_at in self.prompt_cooldowns.items()
            if expires_at <= current_time
        ]
        for alias in expired_aliases:
            del self.prompt_cooldowns[alias]

    def _has_pending_prompt_for_aliases(self, aliases: set[str]) -> bool:
        return any(
            self._tracked_aliases(pending_app).intersection(aliases)
            for pending_app in self._pending_prompts
        )

    def _remove_pending_prompts_for_aliases(self, aliases: set[str]) -> None:
        self._pending_prompts = [
            pending_app
            for pending_app in self._pending_prompts
            if not self._tracked_aliases(pending_app).intersection(aliases)
        ]

    def _process_pending_prompts(self) -> None:
        if not self._pending_prompts:
            return

        with self.lock:
            if self.prompt_in_progress:
                return
            now = time.time()
            self._prune_prompt_cooldowns(now)
            remaining: list[LockedAppRecord] = []
            for pending_app in self._pending_prompts:
                if remaining or self.prompt_in_progress:
                    remaining.append(pending_app)
                    continue

                tracked_aliases = self._tracked_aliases(pending_app)
                if any(
                    self.prompt_cooldowns.get(alias, 0.0) > now
                    for alias in tracked_aliases
                ):
                    remaining.append(pending_app)
                    continue
                if any(alias in self.prompting_apps for alias in tracked_aliases):
                    remaining.append(pending_app)
                    continue
                self.prompt_in_progress = True
                self.prompting_apps.update(tracked_aliases)
                logger.info("Queueing deferred UI prompt for %s", pending_app.app_name)
                self.ui_queue.put("PROMPT", pending_app)
            self._pending_prompts = remaining

    def preserve_running_app_sessions(self, apps):
        """
        Deprecated by design: currently running locked apps must reauthenticate.
        """
        return None

    def _resolve_launch_target(
        self, locked_app: LockedAppRecord
    ) -> LockedAppRecord | None:
        if locked_app.app_path:
            return locked_app

        for candidate in list_locked_apps():
            if candidate.match_mode != "name":
                continue
            if candidate.app_name.casefold() != locked_app.app_name.casefold():
                continue
            if candidate.app_path:
                return candidate

        return locked_app if locked_app.app_path else None

    def _coerce_locked_app(self, app) -> LockedAppRecord | None:
        app_path = normalize_path(
            getattr(app, "app_path", "") or getattr(app, "path", "")
        )
        app_name = str(
            getattr(app, "app_name", "") or getattr(app, "executable_name", "")
        ).strip()

        if not app_name and not app_path:
            return None

        if not app_name and app_path:
            app_name = os.path.basename(app_path)

        return LockedAppRecord(
            id=getattr(app, "id", None),
            app_name=app_name,
            app_path=app_path,
            match_mode="path" if app_path else "name",
            file_sha256=str(getattr(app, "file_sha256", "") or "").strip().lower(),
        )

    def _matches_target_process(
        self, proc_info: dict, locked_app: LockedAppRecord
    ) -> bool:
        process_path = normalize_path(proc_info.get("exe"))
        process_name = (proc_info.get("name") or "").strip()

        if locked_app.is_path_rule and process_path:
            return (
                process_path.casefold()
                == normalize_path(locked_app.app_path).casefold()
            )

        return process_name.casefold() == locked_app.app_name.casefold()

    def _tracked_aliases(self, locked_app: LockedAppRecord) -> set[str]:
        aliases = self._app_aliases(locked_app)
        resolved_app = self._resolve_launch_target(locked_app)
        if resolved_app is not None:
            aliases.update(self._app_aliases(resolved_app))
        return aliases

    def _app_aliases(self, locked_app: LockedAppRecord | None) -> set[str]:
        aliases: set[str] = set()
        if locked_app is None:
            return aliases

        aliases.add(locked_app.identity)
        app_name = str(locked_app.app_name or "").strip().casefold()
        if app_name:
            aliases.add(app_name)
        if locked_app.is_path_rule and locked_app.app_path:
            aliases.add(normalize_path(locked_app.app_path).casefold())
        return {alias for alias in aliases if alias}
