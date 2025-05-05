#!/usr/bin/env python3
"""
Standalone remote scanner - no external dependencies
"""
import sys
import json
import platform
import subprocess
from typing import Dict
import subprocess

def get_windows_apps():
    """Scan Windows apps without registry dependency"""
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"],
            capture_output=True, text=True
        )
        return result.stdout if result.stdout else "No Windows apps found"
    except Exception as e:
        return f"Windows scan failed: {str(e)}"

def get_linux_apps():
    """Scan Linux apps"""
    try:
        result = subprocess.run(
            ["dpkg", "-l"],
            capture_output=True, text=True
        )
        return result.stdout if result.stdout else "No Linux packages found"
    except Exception as e:
        return f"Linux scan failed: {str(e)}"

def get_mac_apps():
    """Scan Mac apps"""
    try:
        result = subprocess.run(
            ["system_profiler", "SPApplicationsDataType"],
            capture_output=True, text=True
        )
        return result.stdout if result.stdout else "No Mac apps found"
    except Exception as e:
        return f"Mac scan failed: {str(e)}"

def check_updates():
    """Check for available updates"""
    system = platform.system().lower()
    if system == "windows":
        return {
            "apps": get_windows_apps(),
            "updates": subprocess.run(
                ["winget", "upgrade"],
                capture_output=True, text=True
            ).stdout
        }
    elif system == "linux":
        return {
            "apps": get_linux_apps(),
            "updates": subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True
            ).stdout
        }
    elif system == "darwin":
        return {
            "apps": get_mac_apps(),
            "updates": subprocess.run(
                ["brew", "outdated"],
                capture_output=True, text=True
            ).stdout
        }
    return {"error": "Unsupported OS"}

def scan_windows():
    results = {}
    try:
        # Check winget
        winget = subprocess.run(
            ["winget", "upgrade"],
            capture_output=True,
            text=True,
            shell=True
        )
        results["winget"] = winget.stdout or "No winget output"
    except Exception as e:
        results["winget_error"] = str(e)
    
    return results

def main():
    try:
        scan_results = check_updates()
        print(json.dumps({
            "status": "success",
            "os": platform.system().lower(),
            "installed_apps": scan_results.get("apps"),
            "available_updates": scan_results.get("updates")
        }))
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "message": str(e)
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()