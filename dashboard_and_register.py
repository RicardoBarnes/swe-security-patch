# -*- coding: utf-8 -*-
"""
Created on Sat Apr  5 20:13:19 2025

@author: calie
"""

import sys
import requests
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QGroupBox, QMainWindow, QStackedWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QIcon
from styles import global_qss

API_BASE = "http://localhost:8000"


class LoginPage(QWidget):
    def __init__(self, stacked_widget, parent=None):
        super().__init__(parent)
        self.stacked_widget = stacked_widget
        self.setWindowTitle("🛡️ Login Page")
        self.setGeometry(100, 100, 400, 300)
        self.setStyleSheet(global_qss())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # Logo 
        logo_lbl = QLabel()
        pixmap = QPixmap("resources/logo.png")
        if not pixmap.isNull():
            logo_lbl.setPixmap(pixmap.scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_lbl)

        # Login Section
        login_box = QGroupBox("🔒 Login")
        login_layout = QVBoxLayout()
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password")
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.login_user)
        login_layout.addWidget(self.user_input)
        login_layout.addWidget(self.pw_input)
        login_layout.addWidget(self.login_btn)
        login_box.setLayout(login_layout)

        layout.addWidget(login_box)

    def login_user(self):
        username = self.user_input.text()
        password = self.pw_input.text()

        response = requests.post(
            f"{API_BASE}/login",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code == 200:
            print("Login successful. Redirecting to dashboard...")
            self.stacked_widget.setCurrentIndex(1)
        else:
            print("Login failed. Check credentials.")
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")


class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Patch Management Dashboard")
        self.setGeometry(100, 100, 900, 600)
        self.setStyleSheet(global_qss())
        self.token = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(15)

        # Manual Scan Button
        self.scan_button = QPushButton("Run Manual Scan")
        self.scan_button.clicked.connect(self.run_scan)
        main_layout.addWidget(self.scan_button)

        # Get All Applications Button
        self.get_apps_button = QPushButton("Get All Applications")
        self.get_apps_button.clicked.connect(self.get_applications)
        main_layout.addWidget(self.get_apps_button)

        # Get Patches for App
        patch_layout = QHBoxLayout()
        self.app_id_input = QLineEdit()
        self.app_id_input.setPlaceholderText("Enter App ID")
        self.get_patches_button = QPushButton("Get Patches for App")
        self.get_patches_button.clicked.connect(self.get_patches)
        patch_layout.addWidget(self.app_id_input)
        patch_layout.addWidget(self.get_patches_button)
        main_layout.addLayout(patch_layout)

        # Update App by ID (needed????)
        update_layout = QHBoxLayout()
        self.update_id_input = QLineEdit()
        self.update_id_input.setPlaceholderText("Enter App ID")
        self.update_button = QPushButton("Update Application")
        self.update_button.clicked.connect(self.update_application)
        update_layout.addWidget(self.update_id_input)
        update_layout.addWidget(self.update_button)
        main_layout.addLayout(update_layout)

        # Output Display
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        main_layout.addWidget(self.output_box)

        # Logo at bottom (have logo???)
        logo_lbl = QLabel()
        pixmap = QPixmap("resources/logo.png")
        if not pixmap.isNull():
            logo_lbl.setPixmap(pixmap.scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(logo_lbl)

        self.setLayout(main_layout)

    def get_headers(self):
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def run_scan(self):
        try:
            response = requests.post(f"{API_BASE}/scan", headers=self.get_headers())
            self.show_response(response)
        except Exception as e:
            self.show_error(e)

    def get_applications(self):
        try:
            response = requests.get(f"{API_BASE}/applications", headers=self.get_headers())
            self.show_response(response)
        except Exception as e:
            self.show_error(e)

    def get_patches(self):
        app_id = self.app_id_input.text()
        if not app_id:
            QMessageBox.warning(self, "Input Error", "Please enter App ID.")
            return
        try:
            response = requests.get(f"{API_BASE}/patches/{app_id}", headers=self.get_headers())
            self.show_response(response)
        except Exception as e:
            self.show_error(e)

    def update_application(self):
        app_id = self.update_id_input.text()
        if not app_id:
            QMessageBox.warning(self, "Input Error", "Please enter App ID.")
            return
        try:
            response = requests.post(f"{API_BASE}/update/{app_id}", headers=self.get_headers())
            self.show_response(response)
        except Exception as e:
            self.show_error(e)

    def show_response(self, response):
        if response.status_code == 200:
            self.output_box.setPlainText(str(response.json()))
        else:
            self.output_box.setPlainText(f"Error {response.status_code}: {response.text}")

    def show_error(self, error):
        self.output_box.setPlainText(f"Request failed: {str(error)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Patch Management Dashboard")
        self.setGeometry(100, 100, 900, 600)

        # Create QStackedWidget to switch between login and dashboard pages
        self.stacked_widget = QStackedWidget(self)
        self.setCentralWidget(self.stacked_widget)

        self.login_page = LoginPage(self.stacked_widget)
        self.dashboard_page = DashboardPage()

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.dashboard_page)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
