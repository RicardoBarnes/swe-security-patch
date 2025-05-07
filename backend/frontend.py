import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QStackedWidget,
    QLineEdit, QFormLayout, QMessageBox, QHeaderView, QFrame, QDialog, QSizePolicy, QProgressBar
)
from PyQt6.QtGui import QFont, QColor, QIcon
from PyQt6.QtCore import Qt
import requests
from PyQt6.QtWebSockets import QWebSocket
from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QTextEdit
import json 
from PyQt6.QtNetwork import QAbstractSocket


class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Patch Management - Login")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("Patch Management")
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #2c3e50;")
        
        # Form
        form = QFormLayout()
        form.setSpacing(15)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        login_btn = QPushButton("Login")
        login_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        login_btn.clicked.connect(self.attempt_login)
        
        register_btn = QPushButton("Register")
        register_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        register_btn.clicked.connect(self.show_register)
        
        button_layout.addWidget(login_btn)
        button_layout.addWidget(register_btn)
        
        layout.addWidget(title)
        layout.addLayout(form)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def attempt_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password")
            return
            
        try:
            response = requests.post(
                "http://localhost:8000/login",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                token = response.json().get("access_token")
                self.main_window.set_token(token)
                self.main_window.show_main_window()
            else:
                QMessageBox.warning(self, "Error", "Invalid credentials")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def show_register(self):
        self.main_window.show_register_window()

class RegisterWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Patch Management - Register")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("Register New User")
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #2c3e50;")
        
        # Form
        form = QFormLayout()
        form.setSpacing(15)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)
        form.addRow("Confirm Password:", self.confirm_password_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        register_btn = QPushButton("Register")
        register_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        register_btn.clicked.connect(self.attempt_register)
        
        back_btn = QPushButton("Back to Login")
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        back_btn.clicked.connect(self.main_window.show_login_window)
        
        button_layout.addWidget(register_btn)
        button_layout.addWidget(back_btn)
        
        layout.addWidget(title)
        layout.addLayout(form)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def attempt_register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password")
            return
            
        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
            
        try:
            response = requests.post(
                "http://localhost:8000/signup",
                json={"username": username, "password": password}
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "User registered successfully!")
                self.main_window.show_login_window()
            else:
                error = response.json().get("detail", "Registration failed")
                QMessageBox.warning(self, "Error", error)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")

# class ApplicationsTab(QWidget):
#     def __init__(self, parent=None):
#         super().__init__(parent)
#         self.main_window = parent
#         self.setup_ui()
#         self.load_applications()
        
#     def setup_ui(self):
#         layout = QVBoxLayout()
#         layout.setContentsMargins(20, 20, 20, 20)
#         layout.setSpacing(20)
        
#         # Header
#         header = QHBoxLayout()
        
#         title = QLabel("Applications")
#         title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
#         title.setStyleSheet("color: #2c3e50;")
        
#         scan_btn = QPushButton("Scan for Updates")
#         scan_btn.setIcon(QIcon.fromTheme("view-refresh"))
#         scan_btn.setStyleSheet("""
#             QPushButton {
#                 background-color: #3498db;
#                 color: white;
#                 border: none;
#                 padding: 8px 15px;
#                 border-radius: 5px;
#                 font-size: 14px;
#             }
#             QPushButton:hover {
#                 background-color: #2980b9;
#             }
#         """)
#         scan_btn.clicked.connect(self.scan_for_updates)
        
#         header.addWidget(title)
#         header.addStretch()
#         header.addWidget(scan_btn)
        
#         # Applications table
#         self.applications_table = QTableWidget()
#         self.applications_table.setColumnCount(4)
#         self.applications_table.setHorizontalHeaderLabels(["Name", "ID", "Current Version", "Available Update"])
#         self.applications_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
#         self.applications_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
#         self.applications_table.setStyleSheet("""
#             QTableWidget {
#                 border: 1px solid #bdc3c7;
#                 border-radius: 5px;
#                 font-size: 14px;
#             }
#             QHeaderView::section {
#                 background-color: #3498db;
#                 color: white;
#                 padding: 5px;
#                 border: none;
#             }
#             QTableWidget::item {
#                 padding: 5px;
#             }
#         """)
        
#         layout.addLayout(header)
#         layout.addWidget(self.applications_table)
        
#         self.setLayout(layout)
    
#     def load_applications(self):
#         try:
#             response = requests.get("http://localhost:8000/applications")
            
#             if response.status_code == 200:
#                 applications = response.json()
#                 self.applications_table.setRowCount(len(applications))
                
#                 for row, app in enumerate(applications):
#                     self.applications_table.setItem(row, 0, QTableWidgetItem(app["app_name"]))
#                     self.applications_table.setItem(row, 1, QTableWidgetItem(str(app["app_id"])))
#                     self.applications_table.setItem(row, 2, QTableWidgetItem(app["current_version"]))
                    
#                     update_item = QTableWidgetItem(app["available_update"])
#                     if app["available_update"] != "No update available":
#                         update_item.setForeground(QColor("#e74c3c"))
#                     self.applications_table.setItem(row, 3, update_item)
                    
#                     # Add update button to each row
#                     update_btn = QPushButton("Update")
#                     update_btn.setStyleSheet("""
#                         QPushButton {
#                             background-color: #2ecc71;
#                             color: white;
#                             border: none;
#                             padding: 5px 10px;
#                             border-radius: 3px;
#                             font-size: 12px;
#                         }
#                         QPushButton:hover {
#                             background-color: #27ae60;
#                         }
#                     """)
#                     update_btn.clicked.connect(lambda _, app_id=app["app_id"]: self.update_application(app_id))
#                     self.applications_table.setCellWidget(row, 3, update_btn)
                    
#             else:
#                 QMessageBox.warning(self, "Error", "Failed to load applications")
                
#         except Exception as e:
#             QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
#     def scan_for_updates(self):
#         try:
#             response = requests.post(
#                 "http://localhost:8000/scan",
#                 headers={"Authorization": f"Bearer {self.main_window.token}"}
#             )
            
#             if response.status_code == 200:
#                 QMessageBox.information(self, "Success", "Scan completed successfully!")
#                 self.load_applications()
#             else:
#                 QMessageBox.warning(self, "Error", "Failed to scan for updates")
                
#         except Exception as e:
#             QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
#     def update_application(self, app_id):
#         try:
#             response = requests.post(
#                 f"http://localhost:8000/update/{app_id}",
#                 headers={"Authorization": f"Bearer {self.main_window.token}"}
#             )
            
#             if response.status_code == 200:
#                 QMessageBox.information(self, "Success", "Application updated successfully!")
#                 self.load_applications()
#             else:
#                 error = response.json().get("error", "Failed to update application")
#                 QMessageBox.warning(self, "Error", error)
                
#         except Exception as e:
#             QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")

class ApplicationsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.load_applications()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QHBoxLayout()
        
        title = QLabel("Applications")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50;")
        
        scan_btn = QPushButton("Scan for Updates")
        scan_btn.setIcon(QIcon.fromTheme("view-refresh"))
        scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        scan_btn.clicked.connect(self.scan_for_updates)

        update_all_btn = QPushButton("Update All")
        update_all_btn.setIcon(QIcon.fromTheme("system-software-update"))
        update_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        update_all_btn.clicked.connect(self.update_all_applications)
        
        header.addWidget(title)
        header.addStretch()
        header.addWidget(scan_btn)
        header.addWidget(update_all_btn)
        
        # Applications table
        self.applications_table = QTableWidget()
        self.applications_table.setColumnCount(5)  # Added column for Update Status
        self.applications_table.setHorizontalHeaderLabels(["Name", "ID", "Current Version", "Available Version", "Status"])
        self.applications_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.applications_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.applications_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #3498db;
                color: white;
                padding: 5px;
                border: none;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        
        layout.addLayout(header)
        layout.addWidget(self.applications_table)
        
        self.setLayout(layout)
    
    def update_all_applications(self):
        try:
            # First scan for updates
            self.scan_for_updates()
            
            # Then update all
            response = requests.post(
                "http://localhost:8000/update-all",
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "All applications updated successfully!")
                self.load_applications()
            else:
                QMessageBox.warning(self, "Error", "Failed to update all applications")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def load_applications(self):
        try:
            response = requests.get("http://localhost:8000/applications")
            
            if response.status_code == 200:
                applications = response.json()
                self.applications_table.setRowCount(len(applications))
                
                for row, app in enumerate(applications):
                    # Application name
                    self.applications_table.setItem(row, 0, QTableWidgetItem(app["app_name"]))
                    
                    # Application ID
                    self.applications_table.setItem(row, 1, QTableWidgetItem(str(app["app_id"])))
                    
                    # Current version
                    self.applications_table.setItem(row, 2, QTableWidgetItem(app["current_version"]))
                    
                    # Available version
                    available_version = app["available_update"]
                    available_item = QTableWidgetItem(available_version)
                    self.applications_table.setItem(row, 3, available_item)
                    
                    # Determine status
                    needs_update = available_version != "No update available" and available_version != app["current_version"]
                    status_text = "Update Available" if needs_update else "Up to Date"
                    status_item = QTableWidgetItem(status_text)
                    
                    # Color coding for status
                    if needs_update:
                        status_item.setForeground(QColor("#e74c3c"))  # Red for updates available
                        available_item.setForeground(QColor("#e74c3c"))
                    else:
                        status_item.setForeground(QColor("#2ecc71"))  # Green for up to date
                    
                    self.applications_table.setItem(row, 4, status_item)
                    
                    # Add update button only if update is available
                    if needs_update:
                        update_btn = QPushButton("Update")
                        update_btn.setStyleSheet("""
                            QPushButton {
                                background-color: #f39c12;
                                color: white;
                                border: none;
                                padding: 5px 10px;
                                border-radius: 3px;
                                font-size: 12px;
                            }
                            QPushButton:hover {
                                background-color: #d35400;
                            }
                        """)
                        update_btn.clicked.connect(lambda _, app_id=app["app_id"]: self.update_application(app_id))
                        self.applications_table.setCellWidget(row, 4, update_btn)
                    else:
                        # Clear any existing widget
                        self.applications_table.setCellWidget(row, 4, None)
                    
            else:
                QMessageBox.warning(self, "Error", "Failed to load applications")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def scan_for_updates(self):
        try:
            response = requests.post(
                "http://localhost:8000/scan",
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "Scan completed successfully!")
                self.load_applications()
            else:
                QMessageBox.warning(self, "Error", "Failed to scan for updates")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def update_application(self, app_id):
        try:
            # First get the app name from the table
            row = -1
            for i in range(self.applications_table.rowCount()):
                if int(self.applications_table.item(i, 1).text()) == app_id:
                    row = i
                    break
            
            if row == -1:
                QMessageBox.warning(self, "Error", "Application not found in table")
                return
                
            app_name = self.applications_table.item(row, 0).text()
            
            # Show progress dialog
            progress = ScanProgressDialog(self)
            progress.label.setText(f"Updating {app_name}...")
            progress.show()
            
            # Call the update-by-name endpoint
            response = requests.post(
                f"http://localhost:8000/update-by-name/{app_name}",
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            progress.close()
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "Application updated successfully!")
                self.load_applications()
            else:
                error = response.json().get("detail", {})
                if isinstance(error, dict):
                    # Handle structured error response
                    error_msg = error.get("error", "Update failed")
                    solution = error.get("solution", "")
                    if solution:
                        error_msg += f"\n\n{solution}"
                else:
                    error_msg = str(error)
                
                QMessageBox.warning(
                    self, 
                    "Update Failed", 
                    error_msg,
                    QMessageBox.StandardButton.Ok
                )
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")


class ScanProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scanning for Updates")
        self.setFixedSize(300, 120)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        self.label = QLabel("Scanning system for updates...")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # Indeterminate mode
        
        layout.addWidget(self.label)
        layout.addWidget(self.progress)
        
        self.setLayout(layout)


class DevicesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.load_devices()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QHBoxLayout()
        
        title = QLabel("Devices")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #2c3e50;")
        
        add_device_btn = QPushButton("Add Device")
        add_device_btn.setIcon(QIcon.fromTheme("list-add"))
        add_device_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        add_device_btn.clicked.connect(self.show_add_device_dialog)
        
        header.addWidget(title)
        header.addStretch()
        header.addWidget(add_device_btn)
        
        # Devices table
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(4)
        self.devices_table.setHorizontalHeaderLabels(["ID", "Hostname", "IP Address", "Actions"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.devices_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #3498db;
                color: white;
                padding: 5px;
                border: none;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        
        layout.addLayout(header)
        layout.addWidget(self.devices_table)
        
        self.setLayout(layout)

    def filter_devices(self):
        search_text = self.search_input.text().lower()
        for row in range(self.devices_table.rowCount()):
            hostname_item = self.devices_table.item(row, 1)
            if hostname_item:
                match = search_text in hostname_item.text().lower()
                self.devices_table.setRowHidden(row, not match)

    def filter_devices(self):
        search_text = self.search_input.text().lower()
        for row in range(self.devices_table.rowCount()):
            hostname_item = self.devices_table.item(row, 1)
            if hostname_item:
                match = search_text in hostname_item.text().lower()
                self.devices_table.setRowHidden(row, not match)
    
    def load_devices(self):
        try:
            response = requests.get("http://localhost:8000/devices")
            
            if response.status_code == 200:
                devices = response.json()
                self.devices_table.setRowCount(len(devices))
                
                for row, device in enumerate(devices):
                    self.devices_table.setItem(row, 0, QTableWidgetItem(str(device["id"])))
                    self.devices_table.setItem(row, 1, QTableWidgetItem(device["hostname"]))
                    self.devices_table.setItem(row, 2, QTableWidgetItem(device["ip_address"]))
                    
                    # Add action buttons
                    btn_widget = QWidget()
                    btn_layout = QHBoxLayout()
                    btn_layout.setContentsMargins(0, 0, 0, 0)
                    btn_layout.setSpacing(5)
                    
                    connect_btn = QPushButton("Connect")
                    connect_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #3498db;
                            color: white;
                            border: none;
                            padding: 5px 10px;
                            border-radius: 3px;
                            font-size: 12px;
                        }
                        QPushButton:hover {
                            background-color: #2980b9;
                        }
                    """)
                    connect_btn.clicked.connect(lambda _, device_id=device["id"]: self.connect_to_device(device_id))
                    
                    scan_btn = QPushButton("Scan")
                    scan_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f39c12;
                            color: white;
                            border: none;
                            padding: 5px 10px;
                            border-radius: 3px;
                            font-size: 12px;
                        }
                        QPushButton:hover {
                            background-color: #d35400;
                        }
                    """)
                    scan_btn.clicked.connect(lambda _, device_id=device["id"]: self.scan_device(device_id))
                    
                    btn_layout.addWidget(connect_btn)
                    btn_layout.addWidget(scan_btn)
                    btn_widget.setLayout(btn_layout)
                    
                    self.devices_table.setCellWidget(row, 3, btn_widget)
                    
            else:
                QMessageBox.warning(self, "Error", "Failed to load devices")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def show_add_device_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Device")
        dialog.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        form = QFormLayout()
        form.setSpacing(10)
        
        self.hostname_input = QLineEdit()
        self.hostname_input.setPlaceholderText("e.g., My-PC")
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.100")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g., admin")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        form.addRow("Hostname:", self.hostname_input)
        form.addRow("IP Address:", self.ip_input)
        form.addRow("SSH Username:", self.username_input)
        form.addRow("SSH Password:", self.password_input)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_btn = QPushButton("Add Device")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        add_btn.clicked.connect(lambda: self.add_device(dialog))
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(form)
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        dialog.exec()
    
    def add_device(self, dialog):
        hostname = self.hostname_input.text()
        ip_address = self.ip_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not all([hostname, ip_address, username, password]):
            QMessageBox.warning(self, "Error", "Please fill all fields")
            return
            
        try:
            response = requests.post(
                "http://localhost:8000/devices/add",
                params={
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "ssh_username": username,
                    "ssh_password": password
                },
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "Device added successfully!")
                self.load_devices()
                dialog.accept()
            else:
                QMessageBox.warning(self, "Error", "Failed to add device")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
    
    def connect_to_device(self, device_id):
        self.main_window.show_device_window(device_id)
    
    def scan_device(self, device_id):
        try:
            # Show progress dialog
            self.scan_dialog = ScanProgressDialog(self)
            self.scan_dialog.show()
            
            # Perform the scan
            response = requests.post(
                f"http://localhost:8000/devices/{device_id}/scan",
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Create a formatted message
                message = f"Scan completed on {result['device_info']['hostname']}\n"
                message += f"OS: {result['device_info']['os'].capitalize()}\n\n"
                
                # Installed software
                message += "Installed Software:\n"
                if isinstance(result['scan_results']['installed_software'], list):
                    for app in result['scan_results']['installed_software'][:5]:  # Show first 5
                        message += f"- {app.get('name', 'Unknown')} ({app.get('version', 'Unknown')})\n"
                elif isinstance(result['scan_results']['installed_software'], dict):
                    for name, version in list(result['scan_results']['installed_software'].items())[:5]:
                        message += f"- {name} ({version})\n"
                
                # Available updates
                message += "\nAvailable Updates:\n"
                if isinstance(result['scan_results']['available_updates'], list):
                    for update in result['scan_results']['available_updates'][:5]:
                        message += f"- {update.get('name', 'Unknown')} (Current: {update.get('current_version', '?')}, Available: {update.get('available_version', '?')})\n"
                elif isinstance(result['scan_results']['available_updates'], dict):
                    for name, info in list(result['scan_results']['available_updates'].items())[:5]:
                        if isinstance(info, dict):
                            message += f"- {name} (Current: {info.get('current', '?')}, Available: {info.get('available', '?')})\n"
                        else:
                            message += f"- {name} (Available: {info})\n"
                
                QMessageBox.information(
                    self, 
                    "Scan Results", 
                    message
                )
            else:
                QMessageBox.warning(self, "Error", "Failed to scan device")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
        finally:
            if hasattr(self, 'scan_dialog'):
                self.scan_dialog.close()
    
    def perform_device_scan(self, device_id):
        try:
            response = requests.post(
                f"http://localhost:8000/devices/{device_id}/scan",
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                result = response.json()
                QMessageBox.information(
                    self, 
                    "Scan Results", 
                    f"Scan completed on {result['device_info']['hostname']}\n\n"
                    f"OS: {result['os']}\n\n"
                    f"Results:\n{result['scan_results']}"
                )
                self.load_devices()
            else:
                QMessageBox.warning(self, "Error", "Failed to scan device")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")
        finally:
            self.scan_dialog.close()

class DeviceWindow(QWidget):
    def __init__(self, device_id, parent=None):
        super().__init__(parent)
        self.device_id = device_id
        self.main_window = parent
        self.setup_ui()
        self.load_device_info()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QHBoxLayout()
        
        self.title = QLabel("Device Details")
        self.title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.title.setStyleSheet("color: #2c3e50;")
        
        back_btn = QPushButton("Back to Devices")
        back_btn.setIcon(QIcon.fromTheme("go-previous"))
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        back_btn.clicked.connect(self.main_window.return_to_devices_tab)
        
        header.addWidget(self.title)
        header.addStretch()
        header.addWidget(back_btn)
        
        # Device info
        self.device_info = QFrame()
        self.device_info.setFrameShape(QFrame.Shape.StyledPanel)
        self.device_info.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
            }
            QLabel {
                font-size: 14px;
            }
        """)
        
        info_layout = QFormLayout()
        info_layout.setSpacing(10)
        
        self.hostname_label = QLabel()
        self.ip_label = QLabel()
        
        info_layout.addRow("Hostname:", self.hostname_label)
        info_layout.addRow("IP Address:", self.ip_label)
        
        self.device_info.setLayout(info_layout)
        
        # Command section
        self.terminal = PowerShellTerminal(self.device_id, self)
        layout.addWidget(self.terminal)
        
        # run_btn = QPushButton("Run Command")
        # run_btn.setStyleSheet("""
        #     QPushButton {
        #         background-color: #3498db;
        #         color: white;
        #         border: none;
        #         padding: 8px 15px;
        #         border-radius: 5px;
        #         font-size: 14px;
        #     }
        #     QPushButton:hover {
        #         background-color: #2980b9;
        #     }
        # """)
        # run_btn.clicked.connect(self.run_command)
        
        # self.command_output = QLabel()
        # self.command_output.setWordWrap(True)
        # self.command_output.setStyleSheet("""
        #     QLabel {
        #         background-color: white;
        #         border: 1px solid #bdc3c7;
        #         border-radius: 5px;
        #         padding: 10px;
        #         font-family: monospace;
        #         font-size: 12px;
        #     }
        # """)
        
        # command_layout.addWidget(command_title)
        # command_layout.addWidget(self.command_input)
        # command_layout.addWidget(run_btn)
        # command_layout.addWidget(QLabel("Output:"))
        # command_layout.addWidget(self.command_output)
        
        # command_group.setLayout(command_layout)
        
        # layout.addLayout(header)
        # layout.addWidget(self.device_info)
        # layout.addWidget(command_group)
        
        self.setLayout(layout)
    
    def load_device_info(self):
        try:
            # Get device info to display in title
            if self.main_window.mock_mode:
                response = requests.get("http://localhost:8000/mock/devices")
            else:
                response = requests.get(
                    "http://localhost:8000/devices",
                    headers={"Authorization": f"Bearer {self.main_window.token}"}
                )
            
            if response.status_code == 200:
                devices = response.json()
                device = next((d for d in devices if d["id"] == self.device_id), None)
                if device:
                    self.title.setText(f"Terminal - {device['hostname']} ({device['ip_address']})")
        except Exception as e:
            print(f"Error loading device info: {e}")
    
    def run_command(self):
        command = self.command_input.text()
        if not command:
            QMessageBox.warning(self, "Error", "Please enter a command")
            return
            
        try:
            response = requests.post(
                f"http://localhost:8000/devices/{self.device_id}/run-command",
                params={"command": command},
                headers={"Authorization": f"Bearer {self.main_window.token}"}
            )
            
            if response.status_code == 200:
                result = response.json()
                self.command_output.setText(result["result"])
            else:
                error = response.json().get("detail", "Command execution failed")
                QMessageBox.warning(self, "Error", error)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to server: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.token = None
        self.setup_ui()
        self.show_login_window()
        self.mock_mode = False
        
    def setup_ui(self):
        self.setWindowTitle("Patch Management Dashboard")
        self.setMinimumSize(1000, 700)
        
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Stacked widget for different views
        self.stacked_widget = QStackedWidget()
        
        # Login window
        self.login_window = LoginWindow(self)
        self.stacked_widget.addWidget(self.login_window)
        
        # Register window
        self.register_window = RegisterWindow(self)
        self.stacked_widget.addWidget(self.register_window)
        
        # Main dashboard
        self.dashboard = QWidget()
        self.setup_dashboard()
        self.stacked_widget.addWidget(self.dashboard)
        
        # Set central layout
        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        central_widget.setLayout(layout)
        
        # Apply styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
        """)
    
    def setup_dashboard(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Navigation bar
        self.nav_bar = QFrame()
        self.nav_bar.setStyleSheet("""
            QFrame {
                background-color: #2c3e50;
                padding: 10px;
            }
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
                padding: 10px 15px;
                font-size: 14px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
        """)
        
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(10, 0, 10, 0)
        nav_layout.setSpacing(10)
        
        logo = QLabel("Patch Management")
        logo.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        logo.setStyleSheet("color: white;")
        
        self.apps_btn = QPushButton("Applications")
        self.apps_btn.clicked.connect(self.show_applications_tab)
        
        self.devices_btn = QPushButton("Devices")
        self.devices_btn.clicked.connect(self.show_devices_tab)
        
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        
        nav_layout.addWidget(logo)
        nav_layout.addWidget(self.apps_btn)
        nav_layout.addWidget(self.devices_btn)
        nav_layout.addWidget(spacer)
        nav_layout.addWidget(self.logout_btn)
        
        self.nav_bar.setLayout(nav_layout)
        
        # Content area
        self.content_stack = QStackedWidget()
        
        # Applications tab
        self.applications_tab = ApplicationsTab(self)
        self.content_stack.addWidget(self.applications_tab)
        
        # Devices tab
        self.devices_tab = DevicesTab(self)
        self.content_stack.addWidget(self.devices_tab)
        self.devices_btn.setVisible(False)
        
        # Add to main layout
        layout.addWidget(self.nav_bar)
        layout.addWidget(self.content_stack)
        
        self.dashboard.setLayout(layout)
    
    def show_login_window(self):
        self.stacked_widget.setCurrentWidget(self.login_window)
    
    def show_register_window(self):
        self.stacked_widget.setCurrentWidget(self.register_window)
    
    def show_main_window(self):
        self.stacked_widget.setCurrentWidget(self.dashboard)
        # Check if user is admin and show/hide devices button
        try:
            response = requests.get(
                "http://localhost:8000/admin-dashboard",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            is_admin = response.status_code == 200
            self.devices_btn.setVisible(is_admin)
        except:
            self.devices_btn.setVisible(False)
        self.show_applications_tab()
    
    def show_applications_tab(self):
        self.content_stack.setCurrentWidget(self.applications_tab)
        self.applications_tab.load_applications()
    
    def show_devices_tab(self):
        self.content_stack.setCurrentWidget(self.devices_tab)
        self.devices_tab.load_devices()
    
    def show_device_window(self, device_id):
        # Remove any existing device window
        for i in range(self.stacked_widget.count()):
            if isinstance(self.stacked_widget.widget(i), DeviceWindow):
                self.stacked_widget.removeWidget(self.stacked_widget.widget(i))
                break
                
        # Create and show new device window
        device_window = DeviceWindow(device_id, self)
        self.stacked_widget.addWidget(device_window)
        self.stacked_widget.setCurrentWidget(device_window)

    def return_to_devices_tab(self):
        """Return from device view to devices tab"""
        # Remove the device window from the stack
        for i in range(self.stacked_widget.count()):
            widget = self.stacked_widget.widget(i)
            if isinstance(widget, DeviceWindow):
                # Remove and delete the device window
                self.stacked_widget.removeWidget(widget)
                widget.deleteLater()
                break
        
        # Ensure we're showing the dashboard with devices tab
        self.stacked_widget.setCurrentWidget(self.dashboard)
        self.content_stack.setCurrentWidget(self.devices_tab)
        self.devices_tab.load_devices()

    def show_device_window(self, device_id):
        # Remove any existing device window
        for i in range(self.stacked_widget.count()):
            widget = self.stacked_widget.widget(i)
            if isinstance(widget, DeviceWindow):
                self.stacked_widget.removeWidget(widget)
                widget.deleteLater()
                break
                
        # Create and show new device window with proper device_id
        device_window = DeviceWindow(device_id, self)
        self.stacked_widget.addWidget(device_window)
        self.stacked_widget.setCurrentWidget(device_window)

    def return_to_devices_tab(self):
        self.stacked_widget.setCurrentWidget(self.dashboard)
    
    def set_token(self, token):
        self.token = token
    
    def logout(self):
        self.token = None
        self.show_login_window()

    

class ScanProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scanning for Updates")
        self.setFixedSize(300, 120)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        self.label = QLabel("Scanning system for updates...")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # Indeterminate mode
        
        layout.addWidget(self.label)
        layout.addWidget(self.progress)
        
        self.setLayout(layout)

class PowerShellTerminal(QWidget):
    def __init__(self, device_id, parent=None):
        super().__init__(parent)
        self.device_id = device_id
        self.main_window = parent.main_window
        self.socket = QWebSocket()
        self.setup_ui()
        self.setup_connections()
        self.connect_to_terminal()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Terminal output area
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setStyleSheet("background-color: black; color: lightgreen; font-family: monospace;")
        layout.addWidget(self.terminal_output)

        # Command input area
        command_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command and press Enter...")
        self.command_input.returnPressed.connect(self.send_command)
        command_layout.addWidget(QLabel("PS>"))
        command_layout.addWidget(self.command_input)

        layout.addLayout(command_layout)
        self.setLayout(layout)

    def setup_connections(self):
        self.socket.textMessageReceived.connect(self.display_output)
        self.socket.errorOccurred.connect(self.handle_error)

    def connect_to_terminal(self):
        try:
            url = QUrl(f"ws://localhost:8000/ws/device/{self.device_id}/terminal")
            self.socket.open(url)
        except Exception as e:
            self.terminal_output.append(f"[ERROR] Failed to connect: {str(e)}")

    def send_command(self):
        command = self.command_input.text()
        if command and self.socket.state() == QAbstractSocket.SocketState.ConnectedState:
            self.terminal_output.append(f"> {command}")  # Echo command locally
            self.socket.sendTextMessage(command)
            self.command_input.clear()

    def display_output(self, text):
        self.terminal_output.append(text)

    def handle_error(self, error):
        self.terminal_output.append(f"[ERROR] WebSocket error: {error}")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())