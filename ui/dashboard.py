from __future__ import annotations

import os
from pathlib import Path
import ctypes

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox, QLineEdit, QComboBox,
    QMenu, QDialog, QFileDialog, QFormLayout, QFileIconProvider
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize, QFileInfo
from PySide6.QtGui import QFont, QIcon, QColor, QPixmap

from app_utils.software_inventory import build_software_inventory, InventoryApp, normalize_path, is_valid_executable
from app_utils.locked_apps_repository import list_locked_apps, lock_apps, unlock_apps, unlock_all_apps
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import is_master_password_set, change_master_password, get_master_password_policy_hint, validate_master_password_strength

# Background thread to load inventory without freezing the UI
class InventoryLoaderThread(QThread):
    finished = Signal(list)

    def run(self):
        locked_apps = list_locked_apps()
        apps = list(build_software_inventory(locked_apps))
        self.finished.emit(apps)

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

        # Shield Icon (Fallback text if no icon)
        shield_lbl = QLabel("\U0001F6E1\uFE0F") # Shield Emoji
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

        self.settings_btn = QPushButton("\u2699\uFE0F") # Gear icon
        self.settings_btn.setFixedSize(32, 32)
        self.settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #f3f4f6; border: 1px solid #d1d5db; border-radius: 4px; font-size: 16px;
            }
            QPushButton:hover { background-color: #e5e7eb; }
        """)
        
        # Setup settings menu
        self.settings_menu = QMenu(self)
        self.settings_menu.addAction("Reset Master Password", self.not_implemented)
        self.settings_menu.addAction("View Recovery Key", self.not_implemented)
        self.settings_menu.addAction("Security Audit Log", self.not_implemented)
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
        
        # Style table to match Tkinter treeview closely
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

        QTimer.singleShot(100, self.refresh_inventory)

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
                status_item.setForeground(QColor("#ef4444")) # Red
            else:
                status_item.setForeground(QColor("#4b5563")) # Gray

            # Path
            path_item = QTableWidgetItem(app.path)
            path_item.setForeground(QColor("#6b7280"))
            path_item.setToolTip(app.path)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, path_item)

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

    def not_implemented(self):
        QMessageBox.information(self, "Coming Soon", "This feature is being ported to the new PySide6 UI and will be available shortly.")

    def closeEvent(self, event):
        self.hide()
        event.ignore()
