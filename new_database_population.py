import subprocess
import re
import datetime
import platform
import plistlib
from sqlalchemy.orm import sessionmaker, Session as SessionType
from sqlalchemy import create_engine
from models import Application, Base  # Import from your models file
from models import Device

# --- Setup SQLAlchemy Session ---
engine = create_engine('mysql+pymysql://root:Sterben1999!@localhost/Patch_Management')
Session = sessionmaker(bind=engine)
session = Session()

# --- OS Detection ---
def detect_os():
    system = platform.system()
    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "mac"
    elif system == "Linux":
        return "linux"
    else:
        return "unknown"

# --- Windows Logic (PLEASE DO NOT MODIFY TOOK ME A LONG TIME TO FIGURE OUT THE PARSING) ---
if platform.system() == "Windows":
    import winreg

    def get_installed_apps_from_registry():
        apps = {}
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        ]

        for hive, path in reg_paths:
            try:
                with winreg.OpenKey(hive, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if 'DisplayVersion' in [winreg.EnumValue(subkey, j)[0] for j in range(winreg.QueryInfoKey(subkey)[1])] else None
                                if name:
                                    apps[name.strip()] = version.strip() if version else None
                        except:
                            continue
            except:
                continue
        return apps

    def get_winget_upgrades():
        upgrades = {}
        try:
            result = subprocess.run(['winget', 'upgrade'], capture_output=True, text=True)
            lines = result.stdout.splitlines()
            start_index = next((i for i, line in enumerate(lines) if line.startswith("Name") and "Id" in line), None)

            if start_index is not None:
                for line in lines[start_index + 2:]:
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) >= 5:
                        name = parts[0].strip()
                        pkg_id = parts[1].strip()
                        current_version = parts[2].strip()
                        available_version = parts[3].strip()
                        upgrades[name.lower()] = {
                            "pkg_id": pkg_id,
                            "available": available_version,
                            "current": current_version
                        }
        except Exception as e:
            print(f"Error running winget: {e}")
        return upgrades

# --- macOS Logic ---
def get_installed_apps_mac():
    apps = {}
    try:
        result = subprocess.run(["system_profiler", "SPApplicationsDataType", "-xml"], capture_output=True, text=False)
        plist = plistlib.loads(result.stdout)
        for item in plist[0]['_items']:
            name = item.get('path', '').split('/')[-1]
            version = item.get('version')
            if name and version:
                apps[name] = version
    except Exception as e:
        print(f"Error getting mac apps: {e}")
    return apps

def get_brew_upgrades():
    upgrades = {}
    try:
        result = subprocess.run(["brew", "outdated", "--verbose"], capture_output=True, text=True)
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                name, current, latest = parts[0], parts[1], parts[2]
                upgrades[name.lower()] = {
                    "pkg_id": name,
                    "available": latest,
                    "current": current
                }
    except Exception as e:
        print(f"Error with brew: {e}")
    return upgrades

# --- Linux Logic ---
def get_installed_apps_linux():
    apps = {}
    try:
        result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("ii"):
                parts = line.split()
                if len(parts) >= 3:
                    name, version = parts[1], parts[2]
                    apps[name] = version
    except Exception as e:
        print(f"Error getting Linux apps: {e}")
    return apps

def get_apt_upgrades():
    upgrades = {}
    try:
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "/" in line and "[" not in line:
                parts = line.split()
                name_version = parts[0]
                available = parts[1]
                name = name_version.split('/')[0]
                upgrades[name.lower()] = {
                    "pkg_id": name,
                    "available": available,
                    "current": "?"
                }
    except Exception as e:
        print(f"Error with apt upgrades: {e}")
    return upgrades

# ---Sync to Database ---
def sync_to_database(installed_apps, winget_upgrades):
    now = datetime.datetime.utcnow()

    for app_name, version in installed_apps.items():
        app_name_lower = app_name.lower()
        upgrade_info = winget_upgrades.get(app_name_lower)

        available = upgrade_info["available"] if upgrade_info else "No update available"
        pkg_id = upgrade_info["pkg_id"] if upgrade_info else app_name_lower.replace(" ", ".")

        existing_app = session.query(Application).filter_by(app_name=app_name).first()

        if existing_app:
            print(f"Updating {app_name} - Current: {existing_app.current_version} -> New: {version}")
            existing_app.current_version = version
            existing_app.available_update = available
            existing_app.last_checked = now
        else:
            print(f"Adding new app to DB: {app_name} - Version: {version}")
            new_app = Application(
                app_name=app_name,
                package_identifier=pkg_id,
                current_version=version,
                available_update=available,
                last_checked=now
            )
            session.add(new_app)

    session.commit()

def process_remote_scan(db: SessionType, device_id: int, scan_data: dict):
    """Process results from remote scanner"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise ValueError("Device not found")
    
    for app_name, app_data in scan_data.get("installed_apps", {}).items():
        # Update or create application records
        pass
        
    db.commit()

# --- Run Script ---
# if __name__ == "__main__":
#     os_type = detect_os()

#     if os_type == "windows":
#         print("[*] Scanning installed apps from registry...")
#         apps = get_installed_apps_from_registry()
#         print("[*] Checking winget for available upgrades...")
#         upgrades = get_winget_upgrades()
#     elif os_type == "mac":
#         print("[*] Scanning installed apps on macOS...")
#         apps = get_installed_apps_mac()
#         print("[*] Checking Homebrew for available upgrades...")
#         upgrades = get_brew_upgrades()
#     elif os_type == "linux":
#         print("[*] Scanning installed apps on Linux...")
#         apps = get_installed_apps_linux()
#         print("[*] Checking apt for available upgrades...")
#         upgrades = get_apt_upgrades()
#     else:
#         print("Unsupported OS")
#         apps, upgrades = {}, {}

#     sync_to_database(apps, upgrades)

#     print("[*] Syncing to database...")
#     sync_to_database(apps, upgrades)
#     print("[✔] Done!")

def detect_and_sync():
    os_type = detect_os()

    if os_type == "windows":
        apps = get_installed_apps_from_registry()
        upgrades = get_winget_upgrades()
    elif os_type == "mac":
        apps = get_installed_apps_mac()
        upgrades = get_brew_upgrades()
    elif os_type == "linux":
        apps = get_installed_apps_linux()
        upgrades = get_apt_upgrades()
    else:
        print("Unsupported OS")
        apps, upgrades = {}, {}

    sync_to_database(apps, upgrades)

