from __future__ import annotations

import os
from pathlib import Path
import ctypes

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox, QLineEdit, QComboBox,
    QMenu, QDialog, QFileDialog, QFormLayout, QFileIconProvider,
    QApplication, QTextEdit
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize, QFileInfo
from PySide6.QtGui import QFont, QIcon, QColor, QPixmap, QClipboard

from app_utils.software_inventory import build_software_inventory, InventoryApp, normalize_path, is_valid_executable
from app_utils.locked_apps_repository import list_locked_apps, lock_apps, unlock_apps, unlock_all_apps
from app_utils.logger import logger
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import (
    is_master_password_set, change_master_password,
    get_master_password_policy_hint, validate_master_password_strength,
    setup_master_password,
)

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

# ── Shared dialog base style ─────────────────────────────────────────────────
_DIALOG_STYLE = f"""
    QDialog {{
        background-color: {_BG};
    }}
    QLabel {{
        color: {_FG_TITLE};
        font-family: '{_FONT_FAMILY}';
    }}
    QLineEdit {{
        border: 1px solid {_ENTRY_BORDER};
        border-radius: 6px;
        padding: 0 12px;
        background: {_ENTRY_BG};
        color: {_FG_TITLE};
        font-family: '{_FONT_FAMILY}';
        font-size: 13px;
    }}
    QLineEdit:focus {{
        border: 2px solid {_BTN_PRIMARY_BG};
    }}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  Setup Master Password Dialog
# ══════════════════════════════════════════════════════════════════════════════
class SetupPasswordDialog(QDialog):
    """First-run dialog that sets the master password and shows the recovery key."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Initial Setup")
        self.setFixedSize(520, 520)
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.WindowContextHelpButtonHint) | Qt.WindowStaysOnTopHint
        )
        self.setStyleSheet(_DIALOG_STYLE)
        self._recovery_key: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 32, 40, 32)
        layout.setSpacing(12)

        # Title
        title = QLabel(f"Welcome to {APP_DISPLAY_NAME}")
        title.setFont(QFont(_FONT_FAMILY, 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Set the master password used for unlocking\nand dashboard changes.")
        subtitle.setFont(QFont(_FONT_FAMILY, 10))
        subtitle.setStyleSheet(f"color: {_FG_SUBTITLE};")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        # Policy hint
        policy_frame = QWidget()
        policy_frame.setStyleSheet("background-color: #f0f4fa; border: 1px solid #d0ddf5; border-radius: 6px;")
        policy_layout = QVBoxLayout(policy_frame)
        policy_layout.setContentsMargins(16, 12, 16, 12)
        policy_lbl = QLabel(
            "\U0001f6e1\ufe0f Use at least 12 characters and include all of these:\n"
            "uppercase letters, lowercase letters, numbers, and symbols."
        )
        policy_lbl.setFont(QFont(_FONT_FAMILY, 9))
        policy_lbl.setStyleSheet("color: #1f6feb; border: none;")
        policy_lbl.setAlignment(Qt.AlignCenter)
        policy_lbl.setWordWrap(True)
        policy_layout.addWidget(policy_lbl)
        layout.addWidget(policy_frame)

        # Password field
        lbl1 = QLabel("Master Password")
        lbl1.setFont(QFont(_FONT_FAMILY, 9))
        layout.addWidget(lbl1)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Enter master password")
        self.pwd_input.setFixedHeight(40)
        layout.addWidget(self.pwd_input)

        # Confirm field
        lbl2 = QLabel("Re-enter Password")
        lbl2.setFont(QFont(_FONT_FAMILY, 9))
        layout.addWidget(lbl2)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm master password")
        self.confirm_input.setFixedHeight(40)
        layout.addWidget(self.confirm_input)

        # Error label
        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {_FG_ERROR};")
        self.error_lbl.setFont(QFont(_FONT_FAMILY, 10))
        self.error_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_lbl)

        # Save button
        save_btn = QPushButton("\U0001f512 Save Password")
        save_btn.setFixedHeight(40)
        save_btn.setFont(QFont(_FONT_FAMILY, 10, QFont.Bold))
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG}; color: {_BTN_PRIMARY_FG};
                border-radius: 6px; border: none;
            }}
            QPushButton:hover {{ background-color: #1a5ecf; }}
        """)
        save_btn.clicked.connect(self._save_password)
        layout.addWidget(save_btn)

        self.pwd_input.returnPressed.connect(lambda: self.confirm_input.setFocus())
        self.confirm_input.returnPressed.connect(self._save_password)

    def _save_password(self):
        password = self.pwd_input.text()
        confirmation = self.confirm_input.text()

        validation_error = validate_master_password_strength(password)
        if validation_error:
            self.error_lbl.setText(validation_error)
            self.pwd_input.setFocus()
            return

        if password != confirmation:
            self.error_lbl.setText("The passwords do not match.")
            self.confirm_input.setFocus()
            return

        success, result = setup_master_password(password)
        if success:
            self._recovery_key = result
            self.accept()
        else:
            self.error_lbl.setText(result)

    @property
    def recovery_key(self) -> str | None:
        return self._recovery_key


# ══════════════════════════════════════════════════════════════════════════════
#  Recovery Key Dialog
# ══════════════════════════════════════════════════════════════════════════════
class RecoveryKeyDialog(QDialog):
    """Shows a recovery key with copy-to-clipboard and acknowledge."""

    def __init__(self, parent, recovery_key: str):
        super().__init__(parent)
        self.setWindowTitle("Recovery Key")
        self.setFixedSize(480, 340)
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.WindowContextHelpButtonHint) | Qt.WindowStaysOnTopHint
        )
        self.setStyleSheet(_DIALOG_STYLE)
        self._recovery_key = recovery_key

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(12)

        title = QLabel("Save Your Recovery Key")
        title.setFont(QFont(_FONT_FAMILY, 14, QFont.Bold))
        title.setStyleSheet("color: #d97706;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        msg = QLabel(
            "This key is the ONLY way to reset your password if forgotten.\n"
            "Store it in a safe place (password manager, printed copy, etc.).\n"
            "It will NOT be shown again."
        )
        msg.setFont(QFont(_FONT_FAMILY, 9))
        msg.setStyleSheet(f"color: {_FG_SUBTITLE};")
        msg.setAlignment(Qt.AlignCenter)
        msg.setWordWrap(True)
        layout.addWidget(msg)

        key_frame = QWidget()
        key_frame.setStyleSheet("background-color: #fef3c7; border: 2px solid #fbbf24; border-radius: 6px;")
        key_layout = QVBoxLayout(key_frame)
        key_layout.setContentsMargins(12, 12, 12, 12)
        key_lbl = QLabel(recovery_key)
        key_lbl.setFont(QFont("Consolas", 14, QFont.Bold))
        key_lbl.setStyleSheet("color: #92400e; border: none;")
        key_lbl.setAlignment(Qt.AlignCenter)
        key_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        key_layout.addWidget(key_lbl)
        layout.addWidget(key_frame)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setFixedHeight(36)
        copy_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #d97706; color: white; border-radius: 6px; border: none;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #b45309; }}
        """)
        copy_btn.clicked.connect(self._copy_key)
        layout.addWidget(copy_btn)

        ack_btn = QPushButton("I Have Saved This Key")
        ack_btn.setFixedHeight(36)
        ack_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG}; color: white; border-radius: 6px; border: none;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #1a5ecf; }}
        """)
        ack_btn.clicked.connect(self.accept)
        layout.addWidget(ack_btn)

    def _copy_key(self):
        QApplication.clipboard().setText(self._recovery_key)
        QMessageBox.information(self, "Copied", "Recovery key copied to clipboard.")

    def closeEvent(self, event):
        self.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  Reset Master Password Dialog
# ══════════════════════════════════════════════════════════════════════════════
class ResetPasswordDialog(QDialog):
    """Change current password by providing the old one."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Reset Password")
        self.setFixedSize(440, 400)
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.WindowContextHelpButtonHint) | Qt.WindowStaysOnTopHint
        )
        self.setStyleSheet(_DIALOG_STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(10)

        title = QLabel("Reset Master Password")
        title.setFont(QFont(_FONT_FAMILY, 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        msg = QLabel("Enter your current password and the new password.")
        msg.setFont(QFont(_FONT_FAMILY, 10))
        msg.setStyleSheet(f"color: {_FG_SUBTITLE};")
        msg.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg)

        hint = QLabel(get_master_password_policy_hint())
        hint.setFont(QFont(_FONT_FAMILY, 9))
        hint.setStyleSheet("color: #6b7280;")
        hint.setAlignment(Qt.AlignCenter)
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # Previous Password
        lbl1 = QLabel("Previous Password")
        lbl1.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl1)
        self.prev_input = QLineEdit()
        self.prev_input.setEchoMode(QLineEdit.Password)
        self.prev_input.setFixedHeight(36)
        layout.addWidget(self.prev_input)

        # New Password
        lbl2 = QLabel("New Password")
        lbl2.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl2)
        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.Password)
        self.new_input.setFixedHeight(36)
        layout.addWidget(self.new_input)

        # Confirm New Password
        lbl3 = QLabel("Confirm New Password")
        lbl3.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl3)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setFixedHeight(36)
        layout.addWidget(self.confirm_input)

        # Error label
        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {_FG_ERROR};")
        self.error_lbl.setFont(QFont(_FONT_FAMILY, 10))
        self.error_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_lbl)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        update_btn = QPushButton("Update Password")
        update_btn.setFixedHeight(36)
        update_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG}; color: {_BTN_PRIMARY_FG};
                border-radius: 6px; border: none; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #1a5ecf; }}
        """)
        update_btn.clicked.connect(self._submit)
        btn_row.addWidget(update_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedHeight(36)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_CANCEL_BG}; color: {_BTN_CANCEL_FG};
                border-radius: 6px; border: none; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #dbeafe; }}
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        layout.addLayout(btn_row)

        self.prev_input.returnPressed.connect(lambda: self.new_input.setFocus())
        self.new_input.returnPressed.connect(lambda: self.confirm_input.setFocus())
        self.confirm_input.returnPressed.connect(self._submit)

    def _submit(self):
        new_password = self.new_input.text()
        validation_error = validate_master_password_strength(new_password)
        if validation_error:
            self.error_lbl.setText(validation_error)
            self.new_input.setFocus()
            return

        if new_password != self.confirm_input.text():
            self.error_lbl.setText("The new passwords do not match.")
            self.confirm_input.setFocus()
            return

        success, message = change_master_password(self.prev_input.text(), new_password)
        if success:
            QMessageBox.information(self, "Success", message)
            self.accept()
        else:
            self.error_lbl.setText(message)
            self.prev_input.setFocus()


# ══════════════════════════════════════════════════════════════════════════════
#  Recovery Reset Dialog (forgot password flow)
# ══════════════════════════════════════════════════════════════════════════════
class RecoveryResetDialog(QDialog):
    """Reset password using the recovery key."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Recover Account Access")
        self.setFixedSize(460, 420)
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.WindowContextHelpButtonHint) | Qt.WindowStaysOnTopHint
        )
        self.setStyleSheet(_DIALOG_STYLE)
        self._new_recovery_key: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(10)

        title = QLabel("Recover Account Access")
        title.setFont(QFont(_FONT_FAMILY, 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        msg = QLabel("Enter your recovery key and a new password.")
        msg.setFont(QFont(_FONT_FAMILY, 10))
        msg.setStyleSheet(f"color: {_FG_SUBTITLE};")
        msg.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg)

        lbl1 = QLabel("Recovery Key")
        lbl1.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl1)
        self.key_input = QLineEdit()
        self.key_input.setFixedHeight(36)
        layout.addWidget(self.key_input)

        lbl2 = QLabel("New Password")
        lbl2.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl2)
        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.Password)
        self.new_input.setFixedHeight(36)
        layout.addWidget(self.new_input)

        lbl3 = QLabel("Confirm New Password")
        lbl3.setFont(QFont(_FONT_FAMILY, 10))
        layout.addWidget(lbl3)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setFixedHeight(36)
        layout.addWidget(self.confirm_input)

        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {_FG_ERROR};")
        self.error_lbl.setFont(QFont(_FONT_FAMILY, 10))
        self.error_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        reset_btn = QPushButton("Reset Password")
        reset_btn.setFixedHeight(36)
        reset_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG}; color: {_BTN_PRIMARY_FG};
                border-radius: 6px; border: none; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #1a5ecf; }}
        """)
        reset_btn.clicked.connect(self._submit)
        btn_row.addWidget(reset_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedHeight(36)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_CANCEL_BG}; color: {_BTN_CANCEL_FG};
                border-radius: 6px; border: none; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #dbeafe; }}
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        layout.addLayout(btn_row)

        self.key_input.returnPressed.connect(lambda: self.new_input.setFocus())
        self.new_input.returnPressed.connect(lambda: self.confirm_input.setFocus())
        self.confirm_input.returnPressed.connect(self._submit)

    def _submit(self):
        from security.auth_manager import reset_password_with_recovery_key

        new_password = self.new_input.text()
        validation_error = validate_master_password_strength(new_password)
        if validation_error:
            self.error_lbl.setText(validation_error)
            self.new_input.setFocus()
            return

        if new_password != self.confirm_input.text():
            self.error_lbl.setText("The new passwords do not match.")
            self.confirm_input.setFocus()
            return

        success, result = reset_password_with_recovery_key(
            self.key_input.text().strip(), new_password
        )
        if success:
            self._new_recovery_key = result
            self.accept()
        else:
            self.error_lbl.setText(result)

    @property
    def new_recovery_key(self) -> str | None:
        return self._new_recovery_key


# ══════════════════════════════════════════════════════════════════════════════
#  Security Audit Log Dialog
# ══════════════════════════════════════════════════════════════════════════════
class AuditLogDialog(QDialog):
    """Displays the security audit log with export capability."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Security Audit Log")
        self.resize(720, 480)
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.WindowContextHelpButtonHint) | Qt.WindowStaysOnTopHint
        )
        self.setStyleSheet(_DIALOG_STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        title = QLabel("Security Audit Log")
        title.setFont(QFont(_FONT_FAMILY, 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Table
        self.log_table = QTableWidget(0, 3)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Event", "Details"])
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.log_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_table.setShowGrid(False)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f9fafb;
                color: #111827;
                border: 1px solid #e5e7eb;
            }
            QHeaderView::section {
                background-color: #f3f4f6;
                padding: 4px;
                border: none;
                border-right: 1px solid #e5e7eb;
                border-bottom: 1px solid #e5e7eb;
                font-weight: bold;
                color: #374151;
            }
        """)
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.log_table)

        self._load_entries()

        # Buttons
        btn_row = QHBoxLayout()

        export_btn = QPushButton("Export CSV")
        export_btn.setFixedHeight(32)
        export_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_PRIMARY_BG}; color: {_BTN_PRIMARY_FG};
                border-radius: 6px; border: none; font-weight: bold; padding: 0 16px;
            }}
            QPushButton:hover {{ background-color: #1a5ecf; }}
        """)
        export_btn.clicked.connect(self._export_csv)
        btn_row.addWidget(export_btn)

        btn_row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setFixedHeight(32)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_BTN_CANCEL_BG}; color: {_BTN_CANCEL_FG};
                border-radius: 6px; border: none; font-weight: bold; padding: 0 16px;
            }}
            QPushButton:hover {{ background-color: #dbeafe; }}
        """)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)

        layout.addLayout(btn_row)

    def _load_entries(self):
        try:
            from config.config_manager import get_connection
            conn = get_connection()
            try:
                rows = conn.execute(
                    "SELECT timestamp, event_type, details FROM security_logs ORDER BY id DESC LIMIT 500"
                ).fetchall()
                self.log_table.setRowCount(len(rows))
                for i, row in enumerate(rows):
                    ts_item = QTableWidgetItem(str(row["timestamp"] or ""))
                    ts_item.setForeground(QColor("#111827"))
                    ev_item = QTableWidgetItem(str(row["event_type"] or ""))
                    ev_item.setForeground(QColor("#111827"))
                    dt_item = QTableWidgetItem(str(row["details"] or ""))
                    dt_item.setForeground(QColor("#6b7280"))
                    self.log_table.setItem(i, 0, ts_item)
                    self.log_table.setItem(i, 1, ev_item)
                    self.log_table.setItem(i, 2, dt_item)
            finally:
                conn.close()
        except Exception as exc:
            logger.error("Failed to load audit log: %s", exc)
            QMessageBox.critical(self, "Error", "Failed to load audit log entries.")

    def _export_csv(self):
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Log", "", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write("Timestamp,Event,Details\n")
                for row in range(self.log_table.rowCount()):
                    values = []
                    for col in range(3):
                        item = self.log_table.item(row, col)
                        v = item.text() if item else ""
                        if "," in v:
                            v = '"' + v.replace('"', '""') + '"'
                        values.append(v)
                    f.write(",".join(values) + "\n")
            QMessageBox.information(self, "Success", f"Audit log exported to {save_path}")
        except Exception as exc:
            logger.error("Failed to export audit log: %s", exc)
            QMessageBox.critical(self, "Error", "Failed to export audit log.")


# ══════════════════════════════════════════════════════════════════════════════
#  Background Inventory Loader
# ══════════════════════════════════════════════════════════════════════════════
class InventoryLoaderThread(QThread):
    finished = Signal(list)

    def run(self):
        locked_apps = list_locked_apps()
        apps = list(build_software_inventory(locked_apps))
        self.finished.emit(apps)


# ══════════════════════════════════════════════════════════════════════════════
#  Main Dashboard
# ══════════════════════════════════════════════════════════════════════════════
class Dashboard(QMainWindow):
    def __init__(self, controller=None):
        super().__init__()
        self.controller = controller
        self.setWindowTitle(APP_DISPLAY_NAME)
        self.resize(1000, 700)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f3f4f6;
                color: #111827;
            }
            QWidget {
                color: #111827;
            }
            QLabel {
                font-family: 'Segoe UI';
                color: #111827;
            }
        """)

        self.inventory_apps: list[InventoryApp] = []
        self.filtered_apps: list[InventoryApp] = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top Header Area
        header_widget = QWidget()
        header_widget.setStyleSheet("background-color: #ffffff; border-bottom: 1px solid #e5e7eb;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 20, 20, 20)

        # Shield Icon
        shield_lbl = QLabel("\U0001F6E1\uFE0F")
        shield_lbl.setFont(QFont("Segoe UI", 28))
        shield_lbl.setStyleSheet("color: #3b82f6; border: none;")
        header_layout.addWidget(shield_lbl)

        # Title & Subtitle
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title_lbl = QLabel("Security Dashboard")
        title_lbl.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title_lbl.setStyleSheet("color: #111827; border: none;")
        title_layout.addWidget(title_lbl)

        subtitle_lbl = QLabel("Secure, monitor, and manage protected applications from one unified dashboard.")
        subtitle_lbl.setFont(QFont("Segoe UI", 10))
        subtitle_lbl.setStyleSheet("color: #6b7280; border: none;")
        title_layout.addWidget(subtitle_lbl)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        # Top Right Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedSize(80, 32)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #f3f4f6; color: #374151; border: 1px solid #d1d5db; border-radius: 4px;
            }
            QPushButton:hover { background-color: #e5e7eb; }
        """)
        self.refresh_btn.clicked.connect(self.refresh_inventory)
        btn_layout.addWidget(self.refresh_btn)

        self.settings_btn = QPushButton("\u2699\uFE0F")
        self.settings_btn.setFixedSize(32, 32)
        self.settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #f3f4f6; border: 1px solid #d1d5db; border-radius: 4px; font-size: 16px;
            }
            QPushButton:hover { background-color: #e5e7eb; }
        """)

        # Setup settings menu
        self.settings_menu = QMenu(self)
        self.settings_menu.addAction("Reset Master Password", self.show_reset_password_dialog)
        self.settings_menu.addAction("Recover with Recovery Key", self.show_recovery_dialog)
        self.settings_menu.addAction("Security Audit Log", self.show_audit_log_dialog)
        self.settings_menu.addSeparator()
        self.settings_menu.addAction("Unlock All Applications", self.unlock_all_applications)
        self.settings_btn.setMenu(self.settings_menu)

        btn_layout.addWidget(self.settings_btn)

        header_layout.addLayout(btn_layout)
        main_layout.addWidget(header_widget)

        # Controls Area
        controls_widget = QWidget()
        controls_widget.setStyleSheet("background-color: #f9fafb; border-bottom: 1px solid #e5e7eb;")
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setContentsMargins(20, 12, 20, 12)
        controls_layout.setSpacing(12)

        # Top Row of Controls (Search + Right Buttons)
        top_ctrl_layout = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.setFixedHeight(32)
        self.search_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #d1d5db; border-radius: 4px; padding: 0 8px; background: white; color: #111827;
            }
        """)
        self.search_input.textChanged.connect(self.apply_filters)
        top_ctrl_layout.addWidget(self.search_input, stretch=1)

        # Right Action Buttons
        self.custom_path_btn = QPushButton("Custom Path")
        self.custom_path_btn.setFixedHeight(32)
        self.custom_path_btn.setStyleSheet("QPushButton { background-color: white; color: #111827; border: 1px solid #d1d5db; border-radius: 4px; padding: 0 12px; } QPushButton:hover { background-color: #f3f4f6; }")
        self.custom_path_btn.clicked.connect(self.add_custom_path)
        top_ctrl_layout.addWidget(self.custom_path_btn)

        self.lock_sel_btn = QPushButton("Lock Selected")
        self.lock_sel_btn.setFixedHeight(32)
        self.lock_sel_btn.setStyleSheet("QPushButton { background-color: #2563eb; color: white; border: none; border-radius: 4px; padding: 0 12px; font-weight: bold; } QPushButton:hover { background-color: #1d4ed8; }")
        self.lock_sel_btn.clicked.connect(self.lock_selected)
        top_ctrl_layout.addWidget(self.lock_sel_btn)

        self.unlock_sel_btn = QPushButton("Unlock Selected")
        self.unlock_sel_btn.setFixedHeight(32)
        self.unlock_sel_btn.setStyleSheet("QPushButton { background-color: #10b981; color: white; border: none; border-radius: 4px; padding: 0 12px; font-weight: bold; } QPushButton:hover { background-color: #059669; }")
        self.unlock_sel_btn.clicked.connect(self.unlock_selected)
        top_ctrl_layout.addWidget(self.unlock_sel_btn)

        controls_layout.addLayout(top_ctrl_layout)

        # Bottom Row of Controls (Showing count + Filters)
        bot_ctrl_layout = QHBoxLayout()

        self.showing_lbl = QLabel("Showing 0 applications.")
        self.showing_lbl.setStyleSheet("color: #4b5563;")
        bot_ctrl_layout.addWidget(self.showing_lbl)

        bot_ctrl_layout.addStretch()

        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet("color: #4b5563;")
        bot_ctrl_layout.addWidget(filter_lbl)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Locked", "Unlocked"])
        self.status_filter.setFixedHeight(28)
        self.status_filter.setStyleSheet("QComboBox { border: 1px solid #d1d5db; border-radius: 4px; padding: 0 8px; background: white; color: #111827; } QComboBox QAbstractItemView { color: #111827; background: white; }")
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        bot_ctrl_layout.addWidget(self.status_filter)

        self.summary_lbl = QLabel("0 locked / 0 total")
        self.summary_lbl.setStyleSheet("color: #4b5563; margin-left: 8px;")
        bot_ctrl_layout.addWidget(self.summary_lbl)

        controls_layout.addLayout(bot_ctrl_layout)
        main_layout.addWidget(controls_widget)

        # Table Area
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(20, 20, 20, 20)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Name", "Status", "Path"])

        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f9fafb;
                color: #111827;
                border: 1px solid #e5e7eb;
                gridline-color: transparent;
                selection-background-color: #cce8ff;
                selection-color: #000000;
            }
            QHeaderView::section {
                background-color: #f3f4f6;
                padding: 4px;
                border: none;
                border-right: 1px solid #e5e7eb;
                border-bottom: 1px solid #e5e7eb;
                font-weight: bold;
                color: #374151;
            }
        """)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        table_layout.addWidget(self.table)
        main_layout.addWidget(table_widget, stretch=1)

        # Loading Thread
        self.loader = InventoryLoaderThread()
        self.loader.finished.connect(self.on_inventory_loaded)

        # Bootstrap: if no password is set yet, show the setup dialog
        QTimer.singleShot(100, self.bootstrap_dashboard)

    # ── Bootstrap ────────────────────────────────────────────────────────
    def bootstrap_dashboard(self):
        if not is_master_password_set():
            self.show_setup_password_dialog()
        self.refresh_inventory()

    # ── Inventory ────────────────────────────────────────────────────────
    def refresh_inventory(self):
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Loading...")
        self.loader.start()

    def on_inventory_loaded(self, apps):
        self.inventory_apps = apps
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Refresh")
        self.apply_filters()

    def apply_filters(self):
        query = self.search_input.text().lower()
        status_filter = self.status_filter.currentText()

        self.filtered_apps = []
        locked_count = 0

        for app in self.inventory_apps:
            if app.is_locked:
                locked_count += 1

            if status_filter == "Locked" and not app.is_locked:
                continue
            if status_filter == "Unlocked" and app.is_locked:
                continue

            if query and query not in app.display_name.lower() and query not in app.path.lower():
                continue

            self.filtered_apps.append(app)

        self.summary_lbl.setText(f"{locked_count} locked / {len(self.inventory_apps)} total")
        self.showing_lbl.setText(f"Showing {len(self.filtered_apps)} applications.")
        self.render_table()

    def render_table(self):
        self.table.setRowCount(0)
        self.table.setRowCount(len(self.filtered_apps))

        icon_provider = QFileIconProvider()

        for row, app in enumerate(self.filtered_apps):
            # Name
            name_item = QTableWidgetItem(app.display_name)
            name_item.setToolTip(app.display_name)
            name_item.setForeground(QColor("#111827"))

            # Extract icon natively using Qt
            file_info = QFileInfo(app.path)
            if file_info.exists():
                icon = icon_provider.icon(file_info)
                if not icon.isNull():
                    name_item.setIcon(icon)

            # Status
            status_text = "Locked" if app.is_locked else "Unlocked"
            status_item = QTableWidgetItem(status_text)
            if app.is_locked:
                status_item.setForeground(QColor("#ef4444"))
            else:
                status_item.setForeground(QColor("#4b5563"))

            # Path
            path_item = QTableWidgetItem(app.path)
            path_item.setForeground(QColor("#6b7280"))
            path_item.setToolTip(app.path)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, path_item)

    # ── Lock / Unlock ────────────────────────────────────────────────────
    def lock_selected(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        apps_to_lock = [self.filtered_apps[r] for r in selected_rows if not self.filtered_apps[r].is_locked]

        if apps_to_lock:
            try:
                lock_apps(apps_to_lock)
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to lock apps: {e}")

    def unlock_selected(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        apps_to_unlock = [self.filtered_apps[r] for r in selected_rows if self.filtered_apps[r].is_locked]

        if apps_to_unlock:
            try:
                unlock_apps(apps_to_unlock)
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to unlock apps: {e}")

    def unlock_all_applications(self):
        reply = QMessageBox.question(
            self, "Confirm Unlock All",
            "Are you sure you want to unlock all applications? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                unlock_all_apps()
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to unlock all apps: {e}")

    def add_custom_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Executable to Lock", "", "Executables (*.exe);;All Files (*.*)"
        )
        if file_path:
            norm_path = normalize_path(file_path)
            if not is_valid_executable(norm_path):
                QMessageBox.warning(self, "Invalid File", "Please select a valid executable (.exe) file.")
                return

            custom_app = InventoryApp(
                path=norm_path,
                display_name=Path(norm_path).name,
                is_locked=False,
                app_name=Path(norm_path).name
            )
            try:
                lock_apps([custom_app])
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to lock custom path: {e}")

    # ── Dialog launchers ─────────────────────────────────────────────────
    def show_setup_password_dialog(self):
        dlg = SetupPasswordDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.recovery_key:
            RecoveryKeyDialog(self, dlg.recovery_key).exec()

    def show_reset_password_dialog(self):
        ResetPasswordDialog(self).exec()

    def show_recovery_dialog(self):
        dlg = RecoveryResetDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.new_recovery_key:
            RecoveryKeyDialog(self, dlg.new_recovery_key).exec()
            QMessageBox.information(
                self, "Success",
                "Password reset successfully. A new recovery key has been generated."
            )

    def show_audit_log_dialog(self):
        AuditLogDialog(self).exec()

    # ── Window behaviour ─────────────────────────────────────────────────
    def closeEvent(self, event):
        self.hide()
        event.ignore()
