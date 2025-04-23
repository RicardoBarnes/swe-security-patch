
import sys
import requests
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout
)

API_BASE = "http://localhost:8000"  

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Patch Management Dashboard")
        self.setGeometry(200, 200, 500, 400)
        
        self.token = None
        layout = QVBoxLayout()

        # Login Section
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login_user)

        layout.addWidget(QLabel("Login"))
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        # Manual Scan Button
        self.scan_button = QPushButton("Run Manual Scan")
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button)

        # Get All Applications Button
        self.get_apps_button = QPushButton("Get All Applications")
        self.get_apps_button.clicked.connect(self.get_applications)
        layout.addWidget(self.get_apps_button)

        # Get Patches for App
        patch_layout = QHBoxLayout()
        self.app_id_input = QLineEdit()
        self.app_id_input.setPlaceholderText("Enter App ID")
        self.get_patches_button = QPushButton("Get Patches for App")
        self.get_patches_button.clicked.connect(self.get_patches)
        patch_layout.addWidget(self.app_id_input)
        patch_layout.addWidget(self.get_patches_button)
        layout.addLayout(patch_layout)

        # Update App by ID
        update_layout = QHBoxLayout()
        self.update_id_input = QLineEdit()
        self.update_id_input.setPlaceholderText("Enter App ID")
        self.update_button = QPushButton("Update Application")
        self.update_button.clicked.connect(self.update_application)
        update_layout.addWidget(self.update_id_input)
        update_layout.addWidget(self.update_button)
        layout.addLayout(update_layout)

        # Output Display
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        layout.addWidget(self.output_box)

        self.setLayout(layout)

    def login_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        try:
            response = requests.post(
                f"{API_BASE}/login",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if response.status_code == 200:
                self.token = response.json()["access_token"]
                self.output_box.setPlainText("Login successful. Token acquired.")
            else:
                self.output_box.setPlainText(f"Login failed: {response.text}")
        except Exception as e:
            self.output_box.setPlainText(f"Login error: {str(e)}")

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec())