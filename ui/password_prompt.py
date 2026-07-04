from __future__ import annotations

import ctypes
import math
import tkinter as tk
from tkinter import messagebox

from app_utils.locked_apps_repository import LockedAppRecord
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import verify_master_password, get_lockout_time

# ── Design tokens ────────────────────────────────────────────────────────────
_BG = "#ffffff"
_BG_HEADER = "#f0f4fa"
_FG_TITLE = "#1f2a37"
_FG_SUBTITLE = "#5b6470"
_FG_ERROR = "#dc2626"
_FG_MUTED = "#94a3b8"
_ENTRY_BG = "#f8fafc"
_ENTRY_BORDER = "#cbd5e1"
_ENTRY_FG = "#1e293b"
_BTN_PRIMARY_BG = "#1f6feb"
_BTN_PRIMARY_FG = "#ffffff"
_BTN_CANCEL_BG = "#e7eef8"
_BTN_CANCEL_FG = "#1f3a5f"
_FONT_FAMILY = "Segoe UI"
_LOCK_ICON = "\U0001F512"  # 🔒

# Minimum dialog widths (in pixels at 96 DPI; Tk will scale them automatically)
_MIN_WIDTH_PROMPT = 460
_MIN_WIDTH_DIALOG = 440


def _lockout_message(lockout_seconds: float) -> str:
    remaining_seconds = max(1, math.ceil(lockout_seconds))
    return f"Too many failed attempts. Try again in {remaining_seconds} seconds."


def _auto_fit_and_center(
    window: tk.Toplevel,
    parent: tk.Misc | None = None,
    min_width: int = 440,
) -> None:
    """Let the window auto-size to its content, enforce a minimum width, then center it."""
    window.update_idletasks()

    # Measure natural content size
    req_w = max(window.winfo_reqwidth(), min_width)
    req_h = window.winfo_reqheight()

    # Add a safety margin so nothing is clipped on high-DPI displays
    final_w = req_w + 20
    final_h = req_h + 20

    # Determine center position
    if (
        parent is not None
        and parent.winfo_exists()
        and bool(int(parent.winfo_viewable()))
    ):
        cx = parent.winfo_x() + (parent.winfo_width() - final_w) // 2
        cy = parent.winfo_y() + (parent.winfo_height() - final_h) // 2
    else:
        cx = (window.winfo_screenwidth() - final_w) // 2
        cy = (window.winfo_screenheight() - final_h) // 2

    window.geometry(f"{final_w}x{final_h}+{max(cx, 0)}+{max(cy, 0)}")
    window.minsize(final_w, final_h)


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


def _create_styled_entry(parent: tk.Widget, *, show: str = "*", width: int = 36) -> tk.Entry:
    """Create a consistently styled password entry field with a visible border frame."""
    border_frame = tk.Frame(parent, bg=_ENTRY_BORDER, bd=0, highlightthickness=0)

    entry = tk.Entry(
        border_frame,
        show=show,
        width=width,
        font=(_FONT_FAMILY, 11),
        relief=tk.FLAT,
        bg=_ENTRY_BG,
        fg=_ENTRY_FG,
        insertbackground=_ENTRY_FG,
        selectbackground=_BTN_PRIMARY_BG,
        selectforeground=_BTN_PRIMARY_FG,
        highlightthickness=0,
        bd=0,
    )
    entry.pack(padx=1, pady=1, ipady=6, fill=tk.X)

    # Store a reference to the border frame so callers can pack/grid it
    entry._border_frame = border_frame
    return entry


def _pack_styled_entry(entry: tk.Entry, **pack_kwargs) -> None:
    """Pack the border frame that wraps a styled entry."""
    frame = getattr(entry, "_border_frame", None)
    if frame is not None:
        frame.pack(**pack_kwargs)
    else:
        entry.pack(**pack_kwargs)


def _create_styled_button(
    parent: tk.Widget,
    text: str,
    command,
    *,
    primary: bool = True,
    width: int = 14,
) -> tk.Button:
    """Create a consistently styled button."""
    bg = _BTN_PRIMARY_BG if primary else _BTN_CANCEL_BG
    fg = _BTN_PRIMARY_FG if primary else _BTN_CANCEL_FG
    active_bg = "#1a5ecf" if primary else "#d6e0f0"

    btn = tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        font=(_FONT_FAMILY, 10),
        bg=bg,
        fg=fg,
        activebackground=active_bg,
        activeforeground=fg,
        relief=tk.FLAT,
        cursor="hand2",
        bd=0,
        highlightthickness=0,
        padx=16,
        pady=6,
    )
    return btn


class PasswordPrompt:
    """Styled password prompt shown when a locked app is intercepted."""

    def __init__(self, root: tk.Toplevel, locked_app: LockedAppRecord, callback):
        self.root = root
        self.locked_app = locked_app
        self.callback = callback
        self._lockout_job: str | None = None
        self._dismissed = False

        self.root.title(f"{APP_DISPLAY_NAME} \u2014 Authentication Required")
        self.root.resizable(False, False)
        self.root.configure(bg=_BG)

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

        # ── Header section ───────────────────────────────────────────────
        header = tk.Frame(self.root, bg=_BG_HEADER)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text=_LOCK_ICON,
            font=(_FONT_FAMILY, 20),
            bg=_BG_HEADER,
            fg=_BTN_PRIMARY_BG,
        ).pack(pady=(16, 4))

        app_label = self.locked_app.display_name or self.locked_app.app_name
        tk.Label(
            header,
            text=f"'{app_label}' is locked",
            font=(_FONT_FAMILY, 12, "bold"),
            bg=_BG_HEADER,
            fg=_FG_TITLE,
        ).pack(pady=(0, 14))

        # ── Body section ─────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=32, pady=(20, 0))

        tk.Label(
            body,
            text="Enter Master Password",
            font=(_FONT_FAMILY, 9),
            bg=_BG,
            fg=_FG_SUBTITLE,
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(0, 6))

        self.password_entry = _create_styled_entry(body)
        _pack_styled_entry(self.password_entry, fill=tk.X, pady=(0, 6))
        self.password_entry.bind("<Return>", lambda event: self.on_submit())
        self.root.after(75, self._focus_password_entry)

        # ── Status / error label ─────────────────────────────────────────
        self.status_var = tk.StringVar(value="")
        tk.Label(
            body,
            textvariable=self.status_var,
            font=(_FONT_FAMILY, 9),
            fg=_FG_ERROR,
            bg=_BG,
            wraplength=380,
            justify=tk.LEFT,
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(2, 0))

        # ── Buttons ──────────────────────────────────────────────────────
        btn_frame = tk.Frame(self.root, bg=_BG)
        btn_frame.pack(fill=tk.X, padx=32, pady=(16, 24))

        self.submit_button = _create_styled_button(
            btn_frame, "Unlock", self.on_submit, primary=True
        )
        self.submit_button.pack(side=tk.LEFT, padx=(0, 10))

        _create_styled_button(
            btn_frame, "Cancel", self.on_cancel, primary=False
        ).pack(side=tk.LEFT)

        # ── Auto-fit window to content, then center ──────────────────────
        _auto_fit_and_center(self.root, min_width=_MIN_WIDTH_PROMPT)

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
            self.submit_button.configure(state=tk.NORMAL, cursor="hand2")
            self.root.after(75, self._focus_password_entry)
            return

        self.password_entry.configure(state=tk.NORMAL)
        self.password_entry.delete(0, tk.END)
        self.password_entry.configure(state=tk.DISABLED)
        self.submit_button.configure(state=tk.DISABLED, cursor="arrow")

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
    """Styled master-password dialog for dashboard lock/unlock/exit actions."""

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
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=_BG)

        if bool(int(parent.winfo_viewable())):
            self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.lift()
        self.dialog.focus_force()
        self.dialog.protocol("WM_DELETE_WINDOW", self.close)

        # ── Header section ───────────────────────────────────────────────
        header = tk.Frame(self.dialog, bg=_BG_HEADER)
        header.pack(fill=tk.X)

        header_content = tk.Frame(header, bg=_BG_HEADER)
        header_content.pack(pady=(16, 14))

        tk.Label(
            header_content,
            text=_LOCK_ICON,
            font=(_FONT_FAMILY, 16),
            bg=_BG_HEADER,
            fg=_BTN_PRIMARY_BG,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            header_content,
            text=title,
            font=(_FONT_FAMILY, 12, "bold"),
            bg=_BG_HEADER,
            fg=_FG_TITLE,
        ).pack(side=tk.LEFT)

        # ── Body section ─────────────────────────────────────────────────
        body = tk.Frame(self.dialog, bg=_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=32, pady=(16, 0))

        tk.Label(
            body,
            text=message,
            font=(_FONT_FAMILY, 10),
            bg=_BG,
            fg=_FG_SUBTITLE,
            anchor=tk.W,
            wraplength=360,
            justify=tk.LEFT,
        ).pack(fill=tk.X, pady=(0, 12))

        self.password_entry = _create_styled_entry(body)
        _pack_styled_entry(self.password_entry, fill=tk.X, pady=(0, 6))
        self.password_entry.bind("<Return>", lambda event: self.submit())
        self.dialog.after(75, self._focus_password_entry)

        # ── Status / error label ─────────────────────────────────────────
        self.status_var = tk.StringVar(value="")
        tk.Label(
            body,
            textvariable=self.status_var,
            font=(_FONT_FAMILY, 9),
            fg=_FG_ERROR,
            bg=_BG,
            wraplength=360,
            justify=tk.LEFT,
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(2, 0))

        # ── Buttons ──────────────────────────────────────────────────────
        btn_frame = tk.Frame(self.dialog, bg=_BG)
        btn_frame.pack(fill=tk.X, padx=32, pady=(16, 24))

        self.submit_button = _create_styled_button(
            btn_frame, action_label, self.submit, primary=True
        )
        self.submit_button.pack(side=tk.LEFT, padx=(0, 10))

        _create_styled_button(
            btn_frame, "Cancel", self.close, primary=False
        ).pack(side=tk.LEFT)

        # ── Auto-fit window to content, then center ──────────────────────
        _auto_fit_and_center(self.dialog, parent, min_width=_MIN_WIDTH_DIALOG)

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
            self.submit_button.configure(state=tk.NORMAL, cursor="hand2")
            self.dialog.after(75, self._focus_password_entry)
            return

        self.password_entry.configure(state=tk.NORMAL)
        self.password_entry.delete(0, tk.END)
        self.password_entry.configure(state=tk.DISABLED)
        self.submit_button.configure(state=tk.DISABLED, cursor="arrow")

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
