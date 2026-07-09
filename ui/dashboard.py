from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QIcon

from app_utils.software_inventory import build_software_inventory, InventoryApp
from app_utils.locked_apps_repository import list_locked_apps, lock_apps, unlock_apps
from app_utils.paths import APP_DISPLAY_NAME
from security.auth_manager import is_master_password_set

class Dashboard(QMainWindow):
    def __init__(self, controller=None):
        super().__init__()
        self.controller = controller
        self.setWindowTitle(APP_DISPLAY_NAME)
        self.resize(900, 600)
        self.setStyleSheet("background-color: #f8fafc;")

        self.inventory_apps: list[InventoryApp] = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Header
        header_layout = QHBoxLayout()
        title_lbl = QLabel(f"{APP_DISPLAY_NAME} Dashboard")
        title_lbl.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title_lbl.setStyleSheet("color: #0f172a;")
        header_layout.addWidget(title_lbl)

        header_layout.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedSize(100, 36)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #e2e8f0; color: #0f172a; border-radius: 6px; font-weight: bold;
            }
            QPushButton:hover { background-color: #cbd5e1; }
        """)
        refresh_btn.clicked.connect(self.refresh_inventory)
        header_layout.addWidget(refresh_btn)

        main_layout.addLayout(header_layout)

        # Table
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["App Name", "Status", "Path"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                gridline-color: #f1f5f9;
            }
            QHeaderView::section {
                background-color: #f8fafc;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #e2e8f0;
                font-weight: bold;
            }
        """)
        main_layout.addWidget(self.table)

        # Bottom Actions
        action_layout = QHBoxLayout()
        
        lock_btn = QPushButton("Lock Selected")
        lock_btn.setFixedSize(140, 40)
        lock_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444; color: white; border-radius: 6px; font-weight: bold;
            }
            QPushButton:hover { background-color: #dc2626; }
        """)
        lock_btn.clicked.connect(self.lock_selected)
        action_layout.addWidget(lock_btn)

        unlock_btn = QPushButton("Unlock Selected")
        unlock_btn.setFixedSize(140, 40)
        unlock_btn.setStyleSheet("""
            QPushButton {
                background-color: #10b981; color: white; border-radius: 6px; font-weight: bold;
            }
            QPushButton:hover { background-color: #059669; }
        """)
        unlock_btn.clicked.connect(self.unlock_selected)
        action_layout.addWidget(unlock_btn)
        
        action_layout.addStretch()
        main_layout.addLayout(action_layout)

        QTimer.singleShot(100, self.refresh_inventory)

    def refresh_inventory(self):
        self.table.setRowCount(0)
        self.inventory_apps = list(build_software_inventory())
        
        self.table.setRowCount(len(self.inventory_apps))
        for row, app in enumerate(self.inventory_apps):
            name_item = QTableWidgetItem(app.display_name)
            
            status = "Locked" if app.is_locked else "Unlocked"
            status_item = QTableWidgetItem(status)
            if app.is_locked:
                status_item.setForeground(QColor("#ef4444"))
            else:
                status_item.setForeground(QColor("#10b981"))
                
            path_item = QTableWidgetItem(app.path)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, path_item)

    def lock_selected(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            return
            
        apps_to_lock = [self.inventory_apps[r] for r in selected_rows if not self.inventory_apps[r].is_locked]
        if apps_to_lock:
            try:
                lock_apps(apps_to_lock)
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to lock apps: {e}")

    def unlock_selected(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            return
            
        apps_to_unlock = [self.inventory_apps[r] for r in selected_rows if self.inventory_apps[r].is_locked]
        if apps_to_unlock:
            try:
                unlock_apps(apps_to_unlock)
                self.refresh_inventory()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to unlock apps: {e}")

    def closeEvent(self, event):
        self.hide()
        event.ignore()
