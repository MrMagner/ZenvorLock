import math
import os
from pathlib import Path
import ctypes

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QApplication,
    QWidget
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QIcon, QPixmap, QColor, QPalette, QFont

from app_utils.locked_apps_repository import LockedAppRecord
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import verify_master_password, get_lockout_time

# ── Design tokens ────────────────────────────────────────────────────────────
_BG = "#ffffff"
_FG_TITLE = "#1f2a37"
_FG_SUBTITLE = "#5b6470"
_FG_ERROR = "#dc2626"
_ENTRY_BG = "#f8fafc"
_ENTRY_BORDER = "#cbd5e1"
_BTN_PRIMARY_BG = "#1f6feb"
_BTN_PRIMARY_FG = "#ffffff"
_BTN_CANCEL_BG = "#e7eef8"
_BTN_CANCEL_FG = "#1f3a5f"
_FONT_FAMILY = "Segoe UI"


def prompt_for_master_password(
    parent=None,
    title: str = "Authentication Required",
    message: str = "Enter the master password.",
    action_label: str = "Unlock",
) -> bool:
    dialog = MasterPasswordDialog(parent, title, message, action_label)
    result = dialog.exec()
    return result == QDialog.DialogCode.Accepted


class MasterPasswordDialog(QDialog):
    def __init__(self, parent=None, title="", message="", action_label=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(460, 260)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(f"background-color: {_BG};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 32, 40, 32)
        layout.setSpacing(16)

        # Title
        title_lbl = QLabel(title)
        title_font = QFont(_FONT_FAMILY, 14, QFont.Bold)
        title_lbl.setFont(title_font)
        title_lbl.setStyleSheet(f"color: {_FG_TITLE};")
        title_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_lbl)

        # Message
        msg_lbl = QLabel(message)
        msg_font = QFont(_FONT_FAMILY, 10)
        msg_lbl.setFont(msg_font)
        msg_lbl.setStyleSheet(f"color: {_FG_SUBTITLE};")
        msg_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg_lbl)

        # Password Input
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Enter master password")
        self.pwd_input.setFixedHeight(40)
        self.pwd_input.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid {_ENTRY_BORDER};
                border-radius: 6px;
                padding: 0 12px;
                background: {_ENTRY_BG};
                font-family: {_FONT_FAMILY};
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border: 2px solid {_BTN_PRIMARY_BG};
            }}
        """)
        layout.addWidget(self.pwd_input)

        # Error Label
        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {_FG_ERROR}; font-family: {_FONT_FAMILY}; font-size: 12px;")
        self.error_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_lbl)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(36)
        self.cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_CANCEL_BG};
                color: {_BTN_CANCEL_FG};
                border-radius: 6px;
                font-family: {_FONT_FAMILY};
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #dbeafe;
            }}
        """)
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        self.submit_btn = QPushButton(action_label)
        self.submit_btn.setFixedHeight(36)
        self.submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG};
                color: {_BTN_PRIMARY_FG};
                border-radius: 6px;
                font-family: {_FONT_FAMILY};
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #1d4ed8;
            }}
        """)
        self.submit_btn.clicked.connect(self.verify_password)
        btn_layout.addWidget(self.submit_btn)

        layout.addLayout(btn_layout)

    def verify_password(self):
        pwd = self.pwd_input.text()
        if not pwd:
            self.error_lbl.setText("Password cannot be empty.")
            return

        lockout = get_lockout_time()
        if lockout > 0:
            remaining = max(1, math.ceil(lockout))
            self.error_lbl.setText(f"Too many failed attempts. Try again in {remaining} seconds.")
            return

        if verify_master_password(pwd):
            self.accept()
        else:
            self.error_lbl.setText("Incorrect password.")
            self.pwd_input.clear()


class PasswordPrompt(QDialog):
    """PySide6 version of the interception password prompt."""
    def __init__(self, parent, locked_app: LockedAppRecord, callback):
        super().__init__(parent)
        self.locked_app = locked_app
        self.callback = callback
        self.setWindowTitle(f"{APP_DISPLAY_NAME} — Authentication Required")
        self.setFixedSize(480, 280)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Dialog)
        self.setStyleSheet(f"background-color: {_BG}; border: 1px solid #cbd5e1; border-radius: 8px;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 32, 40, 32)
        layout.setSpacing(16)

        # Title
        app_label = self.locked_app.display_name or self.locked_app.app_name
        title_layout = QHBoxLayout()
        title_layout.setSpacing(8)

        title_lbl = QLabel(f"'{app_label}' is locked")
        title_font = QFont(_FONT_FAMILY, 14, QFont.Bold)
        title_lbl.setFont(title_font)
        title_lbl.setStyleSheet(f"color: {_FG_TITLE}; border: none;")
        title_layout.addWidget(title_lbl, 0, Qt.AlignCenter)

        # Authenticode Check
        if self.locked_app.app_path and str(self.locked_app.app_path).lower().endswith(".exe"):
            try:
                from security.authenticode import is_executable_signed
                if is_executable_signed(self.locked_app.app_path):
                    auth_lbl = QLabel(" \u2714\ufe0f")
                    auth_lbl.setStyleSheet("color: #10b981; font-size: 16px; border: none;")
                    title_layout.addWidget(auth_lbl, 0, Qt.AlignLeft)
                else:
                    auth_lbl = QLabel(" \u26a0\ufe0f Unsigned")
                    auth_lbl.setStyleSheet("color: #ef4444; font-size: 12px; font-weight: bold; border: none;")
                    title_layout.addWidget(auth_lbl, 0, Qt.AlignLeft)
            except Exception:
                pass

        layout.addLayout(title_layout)

        # Message
        msg_lbl = QLabel("Enter the master password to unlock the application.")
        msg_font = QFont(_FONT_FAMILY, 10)
        msg_lbl.setFont(msg_font)
        msg_lbl.setStyleSheet(f"color: {_FG_SUBTITLE}; border: none;")
        msg_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg_lbl)

        # Password Input
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Enter master password")
        self.pwd_input.setFixedHeight(40)
        self.pwd_input.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid {_ENTRY_BORDER};
                border-radius: 6px;
                padding: 0 12px;
                background: {_ENTRY_BG};
                font-family: {_FONT_FAMILY};
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border: 2px solid {_BTN_PRIMARY_BG};
            }}
        """)
        self.pwd_input.returnPressed.connect(self.on_submit)
        layout.addWidget(self.pwd_input)

        # Error Label
        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {_FG_ERROR}; font-family: {_FONT_FAMILY}; font-size: 12px; border: none;")
        self.error_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_lbl)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(36)
        self.cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_CANCEL_BG};
                color: {_BTN_CANCEL_FG};
                border-radius: 6px;
                font-family: {_FONT_FAMILY};
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #dbeafe;
            }}
        """)
        self.cancel_btn.clicked.connect(self.on_cancel)
        btn_layout.addWidget(self.cancel_btn)

        self.submit_btn = QPushButton("Unlock")
        self.submit_btn.setFixedHeight(36)
        self.submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG};
                color: {_BTN_PRIMARY_FG};
                border-radius: 6px;
                font-family: {_FONT_FAMILY};
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #1d4ed8;
            }}
        """)
        self.submit_btn.clicked.connect(self.on_submit)
        btn_layout.addWidget(self.submit_btn)

        layout.addLayout(btn_layout)

        self.activateWindow()
        self.raise_()
        self.pwd_input.setFocus()

    def on_submit(self):
        pwd = self.pwd_input.text()
        if not pwd:
            self.error_lbl.setText("Password cannot be empty.")
            return

        lockout = get_lockout_time()
        if lockout > 0:
            remaining = max(1, math.ceil(lockout))
            self.error_lbl.setText(f"Too many failed attempts. Try again in {remaining} seconds.")
            return

        if verify_master_password(pwd):
            self.accept()
            self.callback(True, self.locked_app)
        else:
            self.error_lbl.setText("Incorrect password.")
            self.pwd_input.clear()

    def on_cancel(self):
        self.reject()
        self.callback(False, self.locked_app)

    def closeEvent(self, event):
        self.callback(False, self.locked_app)
        event.accept()
