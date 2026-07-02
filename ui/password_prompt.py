from __future__ import annotations

import ctypes
import math
import tkinter as tk
from tkinter import messagebox

from app_utils.locked_apps_repository import LockedAppRecord
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import verify_master_password, get_lockout_time


def _lockout_message(lockout_seconds: float) -> str:
    remaining_seconds = max(1, math.ceil(lockout_seconds))
    return f"Too many failed attempts. Try again in {remaining_seconds} seconds."


def _center_dialog(window: tk.Toplevel, parent: tk.Misc | None = None) -> None:
    try:
        window.tk.call("tk", "PlaceWindow", window._w, "center")
        return
    except Exception:
        pass

    window.update_idletasks()
    if (
        parent is not None
        and parent.winfo_exists()
        and bool(int(parent.winfo_viewable()))
    ):
        x = parent.winfo_x() + (parent.winfo_width() - window.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - window.winfo_height()) // 2
    else:
        x = (window.winfo_screenwidth() - window.winfo_width()) // 2
        y = (window.winfo_screenheight() - window.winfo_height()) // 2
    window.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def _focus_password_entry(entry: tk.Entry) -> None:
    if not entry.winfo_exists() or str(entry.cget("state")) != tk.NORMAL:
        return

    entry.focus_set()
    entry.icursor(tk.END)
    entry.update_idletasks()

    pointer_x = entry.winfo_rootx() + max(18, min(entry.winfo_width() // 2, 28))
    pointer_y = entry.winfo_rooty() + (entry.winfo_height() // 2)

    try:
        ctypes.windll.user32.SetCursorPos(int(pointer_x), int(pointer_y))
    except Exception:
        try:
            entry.event_generate(
                "<Motion>",
                warp=True,
                x=max(18, min(entry.winfo_width() // 2, 28)),
                y=max(entry.winfo_height() // 2, 1),
            )
        except Exception:
            pass


class PasswordPrompt:
    def __init__(self, root: tk.Toplevel, locked_app: LockedAppRecord, callback):
        self.root = root
        self.locked_app = locked_app
        self.callback = callback
        self._lockout_job: str | None = None
        self._dismissed = False

        self.root.title(f"{APP_DISPLAY_NAME} - Authentication Required")
        self.root.geometry("420x205")
        self.root.resizable(False, False)
        
        # Bring to front initially, but don't force it to stay on top forever
        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)
        
        self.root.focus_force()
        self.root.lift()
        self.root.grab_set()
        self.root.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.root.attributes("-toolwindow", False)

        try:
            self.root.wm_attributes("-disabled", False)
        except Exception:
            pass

        _center_dialog(self.root)

        app_label = self.locked_app.display_name or self.locked_app.app_name
        tk.Label(
            self.root,
            text=f"The application '{app_label}' is locked.",
            font=("Segoe UI", 11, "bold"),
        ).pack(pady=(14, 6))
        tk.Label(self.root, text="Enter Master Password:", font=("Segoe UI", 10)).pack()

        self.password_entry = tk.Entry(self.root, show="*", width=32)
        self.password_entry.pack(pady=8)
        self.password_entry.bind("<Return>", lambda event: self.on_submit())
        self.root.after(75, self._focus_password_entry)

        self.status_var = tk.StringVar(value="")
        tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            fg="#a40000",
            wraplength=360,
            justify=tk.CENTER,
        ).pack(pady=(0, 4))

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        self.submit_button = tk.Button(
            btn_frame,
            text="Unlock",
            command=self.on_submit,
            width=12,
        )
        self.submit_button.pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Cancel", command=self.on_cancel, width=12).pack(
            side=tk.LEFT, padx=6
        )
        self._refresh_lockout_state()

    def _focus_password_entry(self) -> None:
        _focus_password_entry(self.password_entry)

    def _cancel_lockout_refresh(self) -> None:
        if self._lockout_job and self.root.winfo_exists():
            self.root.after_cancel(self._lockout_job)
        self._lockout_job = None

    def _set_auth_controls_enabled(self, enabled: bool) -> None:
        if enabled:
            self.password_entry.configure(state=tk.NORMAL)
            self.submit_button.configure(state=tk.NORMAL)
            self.root.after(75, self._focus_password_entry)
            return

        self.password_entry.configure(state=tk.NORMAL)
        self.password_entry.delete(0, tk.END)
        self.password_entry.configure(state=tk.DISABLED)
        self.submit_button.configure(state=tk.DISABLED)

    def _schedule_lockout_refresh(self) -> None:
        self._cancel_lockout_refresh()
        self._lockout_job = self.root.after(1000, self._refresh_lockout_state)

    def _refresh_lockout_state(self, *, notify: bool = False) -> bool:
        if not self.root.winfo_exists():
            return False

        lockout = get_lockout_time()
        if lockout > 0:
            message = _lockout_message(lockout)
            self.status_var.set(message)
            self._set_auth_controls_enabled(False)
            if notify:
                messagebox.showerror("Locked Out", message, parent=self.root)
            self._schedule_lockout_refresh()
            return True

        self.status_var.set("")
        self._cancel_lockout_refresh()
        self._set_auth_controls_enabled(True)
        return False

    def on_submit(self):
        if self._refresh_lockout_state(notify=True):
            return

        password = self.password_entry.get()
        self.password_entry.delete(0, tk.END)
        if verify_master_password(password):
            self._cancel_lockout_refresh()
            self.root.destroy()
            self.callback(True, self.locked_app)
        else:
            password = ""
            if self._refresh_lockout_state(notify=True):
                return
            else:
                messagebox.showerror("Error", "Incorrect password", parent=self.root)
                self.password_entry.delete(0, tk.END)
                self.root.after(75, self._focus_password_entry)

    def on_cancel(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cancel_lockout_refresh()
        self.root.destroy()
        self.callback(False, self.locked_app)


class MasterPasswordDialog:
    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        message: str,
        action_label: str,
    ):
        self.parent = parent
        self.result = False
        self._lockout_job: str | None = None

        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("360x185")
        self.dialog.resizable(False, False)
        if bool(int(parent.winfo_viewable())):
            self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.lift()
        self.dialog.focus_force()
        self.dialog.protocol("WM_DELETE_WINDOW", self.close)

        _center_dialog(self.dialog, parent)

        tk.Label(self.dialog, text=message, font=("Segoe UI", 10)).pack(pady=(16, 8))
        self.password_entry = tk.Entry(self.dialog, show="*", width=30)
        self.password_entry.pack(pady=4)
        self.password_entry.bind("<Return>", lambda event: self.submit())
        self.dialog.after(75, self._focus_password_entry)

        self.status_var = tk.StringVar(value="")
        tk.Label(
            self.dialog,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            fg="#a40000",
            wraplength=300,
            justify=tk.CENTER,
        ).pack(pady=(6, 0))

        btn_frame = tk.Frame(self.dialog)
        btn_frame.pack(pady=12)

        self.submit_button = tk.Button(
            btn_frame,
            text=action_label,
            width=12,
            command=self.submit,
        )
        self.submit_button.pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Cancel", width=12, command=self.close).pack(
            side=tk.LEFT, padx=6
        )
        self._refresh_lockout_state()

    def _focus_password_entry(self) -> None:
        _focus_password_entry(self.password_entry)

    def _cancel_lockout_refresh(self) -> None:
        if self._lockout_job and self.dialog.winfo_exists():
            self.dialog.after_cancel(self._lockout_job)
        self._lockout_job = None

    def _set_auth_controls_enabled(self, enabled: bool) -> None:
        if enabled:
            self.password_entry.configure(state=tk.NORMAL)
            self.submit_button.configure(state=tk.NORMAL)
            self.dialog.after(75, self._focus_password_entry)
            return

        self.password_entry.configure(state=tk.NORMAL)
        self.password_entry.delete(0, tk.END)
        self.password_entry.configure(state=tk.DISABLED)
        self.submit_button.configure(state=tk.DISABLED)

    def _schedule_lockout_refresh(self) -> None:
        self._cancel_lockout_refresh()
        self._lockout_job = self.dialog.after(1000, self._refresh_lockout_state)

    def _refresh_lockout_state(self, *, notify: bool = False) -> bool:
        if not self.dialog.winfo_exists():
            return False

        lockout = get_lockout_time()
        if lockout > 0:
            message = _lockout_message(lockout)
            self.status_var.set(message)
            self._set_auth_controls_enabled(False)
            if notify:
                messagebox.showerror("Locked Out", message, parent=self.dialog)
            self._schedule_lockout_refresh()
            return True

        self.status_var.set("")
        self._cancel_lockout_refresh()
        self._set_auth_controls_enabled(True)
        return False

    def submit(self):
        if self._refresh_lockout_state(notify=True):
            return

        password = self.password_entry.get()
        self.password_entry.delete(0, tk.END)
        if verify_master_password(password):
            self.result = True
            self._cancel_lockout_refresh()
            self.dialog.destroy()
            return

        password = ""
        if self._refresh_lockout_state(notify=True):
            return
        else:
            messagebox.showerror("Error", "Incorrect password", parent=self.dialog)
            self.password_entry.delete(0, tk.END)
            self.dialog.after(75, self._focus_password_entry)

    def close(self):
        self.result = False
        self._cancel_lockout_refresh()
        self.dialog.destroy()


def prompt_for_master_password(
    parent: tk.Misc,
    title: str = "Authentication Required",
    message: str = "Enter Master Password:",
    action_label: str = "Verify",
) -> bool:
    dialog = MasterPasswordDialog(
        parent, title=title, message=message, action_label=action_label
    )
    parent.wait_window(dialog.dialog)
    return dialog.result


def show_password_prompt(root, locked_app: LockedAppRecord, callback):
    dialog = tk.Toplevel(root)
    if root.winfo_exists() and bool(int(root.winfo_viewable())):
        dialog.transient(root)
    PasswordPrompt(dialog, locked_app, callback)


if __name__ == "__main__":

    def test_cb(success, app):
        print(f"Success: {success}, App: {app.app_name}")

    root = tk.Tk()
    root.withdraw()
    show_password_prompt(
        root, LockedAppRecord(id=None, app_name="TestApp.exe", app_path=""), test_cb
    )
    root.mainloop()
