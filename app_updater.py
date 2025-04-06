# -*- coding: utf-8 -*-
"""
Created on Sat Apr  5 20:13:19 2025

@author: calie
"""

import subprocess
import threading
import tkinter as tk
from tkinter import messagebox

def update_apps():
    """Runs the Winget update process and displays status messages."""
    def run_update():
        try:
            update_button.config(state=tk.DISABLED)  # Disable button during update
            status_label.config(text="Checking for updates...", fg="blue")
            
            # Check for available updates
            subprocess.run(["winget", "upgrade"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            status_label.config(text="Updating apps...", fg="blue")
            
            # Upgrade all apps
            subprocess.run(["winget", "upgrade", "--all"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            status_label.config(text="All apps are updated!", fg="green")
            messagebox.showinfo("Update Complete", "All applications have been updated successfully.")
        
        except subprocess.CalledProcessError:
            status_label.config(text="Update failed!", fg="red")
            messagebox.showerror("Error", "Failed to update apps. Run as administrator.")
        except FileNotFoundError:
            status_label.config(text="Winget not found!", fg="red")
            messagebox.showerror("Error", "Winget is not installed or accessible.")

        update_button.config(state=tk.NORMAL)  # Re-enable button

    # Run the update process in a separate thread to prevent freezing the GUI
    update_thread = threading.Thread(target=run_update)
    update_thread.start()

# Create GUI
root = tk.Tk()
root.title("App Updater")
root.geometry("300x200")

status_label = tk.Label(root, text="Click 'Update' to start", font=("Arial", 12))
status_label.pack(pady=20)

update_button = tk.Button(root, text="Update Apps", font=("Arial", 12), command=update_apps)
update_button.pack(pady=10)

exit_button = tk.Button(root, text="Exit", font=("Arial", 12), command=root.quit)
exit_button.pack(pady=10)

root.mainloop()
