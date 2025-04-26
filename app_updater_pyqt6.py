import subprocess
import threading
import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject


class UpdaterSignals(QObject):
    progress = pyqtSignal(int)          #update progress bar
    status = pyqtSignal(str)            #update status message
    finished = pyqtSignal(bool, str)    #to signal when finished


class AppUpdater(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows App Updater")
        self.setFixedSize(400, 250)

        #connect signal to handler
        self.signals = UpdaterSignals()
        self.signals.progress.connect(self.set_progress)
        self.signals.status.connect(self.set_status)
        self.signals.finished.connect(self.finish_update)

        self.init_ui()      #set up interface

    def init_ui(self):
        layout = QVBoxLayout()

        #label to show app update progress
        self.status_label = QLabel("Click 'Update Apps' to begin.")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.update_button = QPushButton("Update Apps")     #update apps button
        self.update_button.clicked.connect(self.update_apps)
        layout.addWidget(self.update_button)

        self.exit_button = QPushButton("Exit")              #exit program button
        self.exit_button.clicked.connect(self.close)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    def update_apps(self):
        self.update_button.setDisabled(True)            #Disable the update button while updating
        self.signals.status.emit("Starting update...")
        self.signals.progress.emit(10)

        #Start the update process in a new thread to keep UI responsive
        thread = threading.Thread(target=self.run_updates)
        thread.start()

    def run_updates(self):
        try:
            #Check for available updates
            self.signals.status.emit("Checking for updates...")
            subprocess.run(["winget", "upgrade"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.signals.progress.emit(50)

            #Run available upgrades
            self.signals.status.emit("Installing updates...")
            subprocess.run(["winget", "upgrade", "--all"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.signals.progress.emit(100)

            #update completed or error
            self.signals.finished.emit(True, "All apps have been updated successfully.")
        except subprocess.CalledProcessError:
            self.signals.finished.emit(False, "Update failed. Make sure you're running as administrator.")
        except FileNotFoundError:
            self.signals.finished.emit(False, "Winget is not installed or not accessible.")

       #Update progress bar 
    def set_progress(self, value):
        self.progress_bar.setValue(value)

        #Update label text
    def set_status(self, text):
        self.status_label.setText(text)

        #final result of update
    def finish_update(self, success, message):
        self.update_button.setDisabled(False)           #re-enable the update button
        self.status_label.setText(message)
        icon = QMessageBox.Icon.Information if success else QMessageBox.Icon.Critical   #message box with update result
        self.show_message("Update Status", message, icon)

    def show_message(self, title, text, icon):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setIcon(icon)
        msg.exec()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AppUpdater()
    window.show()
    sys.exit(app.exec())
