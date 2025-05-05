from fastapi import Depends, HTTPException
from fastapi import APIRouter
import crud
from sqlalchemy.orm import Session
from models import Session as DBSession, PatchHistory
import subprocess
from models import Session as DBSession, Application, User, Device
from auth import authenticate_user, create_access_token, get_current_admin, get_db
from fastapi.security import OAuth2PasswordRequestForm
from auth import register_user, get_current_user
from schemas import UserSignup
from datetime import datetime
from ssh_utils import SSHManager
from typing import List, Dict
from pathlib import Path
import re
import logging
import json
import platform


router= APIRouter()

logger = logging.getLogger(__name__)

def parse_results_based_on_os(os_type: str, output: str) -> dict:
    """Route to the appropriate OS-specific parser"""
    os_type = os_type.lower()
    if os_type == "windows":
        return parse_windows_scan(output)
    elif os_type == "linux":
        return parse_linux_scan(output)
    elif os_type == "mac":
        return parse_mac_scan(output)
    else:
        return {"error": f"Unsupported OS type: {os_type}"}

def parse_windows_scan(output: str) -> dict:
    """Parse Windows scan output with better error handling"""
    # First try to parse as JSON
    try:
        data = json.loads(output.strip())
    except json.JSONDecodeError:
        # If JSON parsing fails, check if it's a winget error message
        if "winget is not recognized" in output:
            return {
                "error": "winget command not found",
                "suggestion": "Install Windows Package Manager from Microsoft Store",
                "raw_output": output.strip()
            }
        return {
            "error": "Invalid JSON output from remote",
            "raw_output": output.strip()
        }
    
    # Handle PowerShell error case
    if "Error" in data:
        return {
            "error": data.get("Error", "Unknown PowerShell error"),
            "raw_output": output.strip()
        }
    
    # Parse installed applications
    installed_apps = []
    if "Apps" in data:
        for app in data["Apps"] if isinstance(data["Apps"], list) else []:
            if app.get("DisplayName"):
                installed_apps.append({
                    "name": app["DisplayName"],
                    "version": app.get("DisplayVersion", "Unknown"),
                    "publisher": app.get("Publisher", "Unknown"),
                    "install_date": app.get("InstallDate", "Unknown")
                })
    
    # Parse winget upgrades
    available_updates = []
    winget_output = data.get("Winget", "")
    if winget_output:
        for line in winget_output.splitlines():
            if line.strip() and not any(x in line for x in ["---", "Name", "Version"]):
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 5:
                    available_updates.append({
                        "name": parts[0],
                        "package_id": parts[1],
                        "current_version": parts[2],
                        "available_version": parts[3]
                    })
    
    return {
        "installed_software": installed_apps,
        "available_updates": available_updates,
        "metadata": {
            "source": "Windows Registry + winget",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    }

def parse_linux_scan(output):
    """Parse Linux scan output"""
    installed = {}
    upgradable = {}
    
    # Split output into installed and upgradable sections
    sections = output.split("No upgrades available") if "No upgrades available" in output else [output]
    
    # Parse installed packages
    for line in sections[0].splitlines():
        if line.startswith('ii'):
            parts = line.split()
            if len(parts) >= 3:
                installed[parts[1]] = parts[2]
    
    # Parse upgradable packages if available
    if len(sections) > 1:
        for line in sections[1].splitlines():
            if '/' in line and 'Listing' not in line:
                pkg = line.split('/')[0]
                version = line.split()[1]
                upgradable[pkg] = version
    
    return {
        "installed_software": installed,
        "available_updates": upgradable
    }

def parse_mac_scan(output):
    """Parse Mac scan output"""
    installed = {}
    upgradable = {}
    
    # Split output into installed and upgradable sections
    sections = output.split("No brew upgrades available") if "No brew upgrades available" in output else [output]
    
    # Parse installed applications (simplified)
    for line in sections[0].splitlines():
        if line.strip() and ':' in line:
            key, value = line.split(':', 1)
            if 'Version' in key:
                installed[key.replace('Version', '').strip()] = value.strip()
    
    # Parse brew upgrades if available
    if len(sections) > 1:
        for line in sections[1].splitlines():
            if line.strip() and ' ' in line:
                parts = line.split()
                if len(parts) >= 3:
                    upgradable[parts[0]] = {
                        "current": parts[1],
                        "available": parts[2]
                    }
    
    return {
        "installed_software": installed,
        "available_updates": upgradable
    }

def get_scan_commands():
    """Returns the OS-specific scan commands and handlers"""
    return {
        "windows": {
            "command": """
            $ErrorActionPreference = 'Stop'
            try {
                # Get installed apps
                $apps = Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
                        Where-Object { $_.DisplayName -ne $null } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
                
                # Get winget upgrades
                $wingetOutput = & {
                    $oldErrorAction = $ErrorActionPreference
                    $ErrorActionPreference = 'SilentlyContinue'
                    winget upgrade | Out-String
                    $ErrorActionPreference = $oldErrorAction
                }
                
                # Prepare clean JSON output
                [PSCustomObject]@{
                    Apps = @($apps)
                    Winget = $wingetOutput
                } | ConvertTo-Json -Depth 10 -Compress
            }
            catch {
                [PSCustomObject]@{
                    Error = $_.Exception.Message
                    RawOutput = $wingetOutput
                } | ConvertTo-Json -Depth 3 -Compress
            }
            """,
            "handler": lambda ssh, cmd: ssh.execute_windows_command(cmd)
        },
        "linux": {
            "command": ("dpkg -l 2>/dev/null || " +
                       "echo 'No dpkg available' && " +
                       "apt list --upgradable 2>/dev/null || " +
                       "echo 'No apt upgrades available'"),
            "handler": lambda ssh, cmd: ssh.execute_command(cmd)
        },
        "mac": {
            "command": "system_profiler SPApplicationsDataType && brew outdated --verbose",
            "handler": lambda ssh, cmd: ssh.execute_command(cmd)
        }
    }



# creating session function to avoid session issues
def get_db():
    db = DBSession()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------------------------------------
# home page
@router.get("/")
def homepage():
    return "PATCH MANAGEMENT DASHBOARD"

# ---------------------Applications Routes------------------------
@router.get("/admin-dashboard")
def admin_dashboard(user: User = Depends(get_current_admin)):
    return {"message": "Welcome to the admin dashboard", "user": user.username}

# all apps
@router.get("/applications")
def list_applications(db: Session = Depends(get_db)):
    return crud.get_all_apps(db)

# patch info for specific app
# @router.get("/patches/{app_id}")
# def show_patch_info(app_id: int, db: Session = Depends(get_db) ):
#     return crud.get_patch_info(db, app_id)

@router.post("/scan")
def manual_scan(db: Session = Depends(get_db), user: User = Depends(get_current_user)):  # Changed from get_current_admin
    from new_database_population import detect_and_sync  
    try:
        detect_and_sync()  # runs Windows/macOS/Linux scan depending on OS
        return {"status": "success", "message": "Scan complete and database updated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/update/{app_id}")
def update_application(
    app_id: int, 
    db: Session = Depends(get_db), 
    user: User = Depends(get_current_user)
):
    app = db.query(Application).filter(Application.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    try:
        # Detect OS and use appropriate command
        os_type = platform.system().lower()
        
        if os_type == "windows":
            command = [
                "winget", "upgrade", "--id", app.package_identifier,
                "--silent", "--accept-package-agreements", "--accept-source-agreements"
            ]
            result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=300)
            
            if result.returncode != 0:
                raise HTTPException(status_code=400, detail=result.stderr or result.stdout or "Unknown error")
                
            # Check if already up to date
            if "no available upgrade found" in result.stdout.lower():
                app.available_update = "No update available"
                db.commit()
                return {"status": "success", "message": "Already up to date"}
            
            # Get updated version
            list_cmd = ["winget", "list", "--id", app.package_identifier]
            list_result = subprocess.run(list_cmd, capture_output=True, text=True, shell=True, timeout=30)
            
            if list_result.returncode == 0:
                for line in list_result.stdout.splitlines():
                    if app.package_identifier.lower() in line.lower():
                        parts = re.split(r'\s{2,}', line.strip())
                        if len(parts) >= 3:
                            app.current_version = parts[1]
                            break
            
        elif os_type == "linux":
            command = ["sudo", "apt", "install", "--only-upgrade", app.package_identifier, "-y"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                raise HTTPException(status_code=400, detail=result.stderr or result.stdout or "Unknown error")
            
            # Get updated version
            list_cmd = ["apt", "list", "--installed", app.package_identifier]
            list_result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=30)
            
            if list_result.returncode == 0:
                for line in list_result.stdout.splitlines():
                    if app.package_identifier in line:
                        version = line.split()[1]
                        app.current_version = version
                        break
            
        elif os_type == "darwin":
            command = ["brew", "upgrade", app.package_identifier]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                raise HTTPException(status_code=400, detail=result.stderr or result.stdout or "Unknown error")
            
            # Get updated version
            list_cmd = ["brew", "info", app.package_identifier]
            list_result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=30)
            
            if list_result.returncode == 0:
                for line in list_result.stdout.splitlines():
                    if app.package_identifier in line and "stable" in line:
                        version = line.split()[1]
                        app.current_version = version
                        break
        else:
            raise HTTPException(status_code=400, detail="Unsupported operating system")

        # Update database
        app.available_update = "No update available"
        app.last_checked = datetime.utcnow()
        db.commit()

        return {
            "status": "success",
            "message": f"Application {app.app_name} updated successfully",
            "new_version": app.current_version
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Update timed out")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")



# --------------------------------------------------User Routes----------------------------------------------------------------------------------------

@router.post("/signup") 
def signup(user: UserSignup, db: Session = Depends(get_db)):
    try:
        user_created = register_user(db, user.username, user.password)
        return {"message": f"User {user_created.username} created successfully and is an admin!"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# --------------------------------------------------------------Device Routes------------------------------------------------------------------------
@router.post("/devices/{device_id}/run-command")
def run_remote_command(
    device_id: int,
    command: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run arbitrary command on remote device (admin only)"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    ssh = SSHManager(device)
    result = ssh.execute_command(command)
    
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    
    return {"status": "success", "result": result["output"]}


@router.post("/devices/{device_id}/scan")
def run_remote_scan(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    ssh = SSHManager(device)
    try:
        # All operations will reuse the same connection
        if not ssh.connect():
            raise HTTPException(500, detail="SSH connection failed")
        
        # Detect OS
        os_type, debug_info = ssh.detect_remote_os()
        if not os_type:
            raise HTTPException(500, detail=f"Could not detect remote OS. Debug: {debug_info}")
        
        # Run scan
        scan_commands = get_scan_commands()
        cmd_info = scan_commands[os_type.lower()]
        result = cmd_info["handler"](ssh, cmd_info["command"])
        
        if "error" in result:
            raise HTTPException(500, detail=f"Scan failed: {result['error']}")
            
        # Parse and return results
        parsed = parse_results_based_on_os(os_type, result["output"])
        return {"status": "success", "data": parsed}
        
    except Exception as e:
        raise HTTPException(500, detail=f"Scan failed: {str(e)}")
    finally:
        ssh.disconnect()  # Ensure connection is always closed

@router.post("/devices/{device_id}/update/{app_id}")
def update_remote_application(
    device_id: int,
    app_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update application on remote device"""
    device = db.query(Device).filter(Device.id == device_id).first()
    app = db.query(Application).filter(Application.app_id == app_id).first()
    
    if not device or not app:
        raise HTTPException(status_code=404, detail="Device or app not found")
    
    ssh = SSHManager(device)
    
    # Platform-specific update commands
    update_commands = {
        "windows": f"winget upgrade --id {app.package_identifier} --silent",
        "linux": f"sudo apt install --only-upgrade {app.package_identifier} -y",
        "mac": f"brew upgrade {app.package_identifier}"
    }
    
    # Detect remote OS
    os_result = ssh.execute_command("python3 -c 'import platform; print(platform.system().lower())'")
    if "error" in os_result:
        raise HTTPException(status_code=500, detail=f"OS detection failed: {os_result['error']}")
    
    remote_os = os_result["output"].strip()
    if remote_os not in update_commands:
        raise HTTPException(status_code=400, detail=f"Unsupported OS: {remote_os}")
    
    # Execute update (no history recording)
    update_result = ssh.execute_command(update_commands[remote_os])
    if "error" in update_result:
        raise HTTPException(status_code=500, detail=update_result["error"])
    
    return {"status": "success", "output": update_result["output"]}

# -------------------------------------------Device and DB logic routes------------------------------
# adds device to db
@router.post("/devices/add")
def add_device(
    hostname: str,
    ip_address: str,
    ssh_username: str,
    ssh_password: str,
    db: Session = Depends(get_db),
    # current_user: User = Depends(get_current_admin)
):
    """Add a new device for remote management."""
    device = Device(
        hostname=hostname,
        ip_address=ip_address,
        ssh_username=ssh_username,
        ssh_password=ssh_password,
        # user_id=current_user.id
    )
    db.add(device)
    db.commit()
    return {"message": f"Device {hostname} added successfully."}


# gets all devices saved in the db
@router.get("/devices", response_model=List[dict])
def list_devices(db: Session = Depends(get_db)):
    """List all devices."""
    devices = db.query(Device).all()
    return [
        {
            "id": device.id,
            "hostname": device.hostname,
            "ip_address": device.ip_address
        }
        for device in devices
    ]

@router.post("/devices/{device_id}/update-all")
def update_all_apps(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk update all applications"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    ssh = SSHManager(device)
    
    try:
        # Get all updatable apps
        apps = db.query(Application).filter(
            Application.device_id == device_id,
            Application.available_update != "None"
        ).all()
        
        if not apps:
            return {"status": "success", "message": "No updates available"}

        # Build update command
        package_ids = [app.package_identifier for app in apps]
        update_cmd = f"winget upgrade --id {' --id '.join(package_ids)} --silent"
        
        # Execute
        result = ssh.execute_windows_command(update_cmd)
        if "error" in result:
            raise HTTPException(500, f"Update failed: {result['error']}")

        # Update database
        for app in apps:
            app.current_version = app.available_update
            app.available_update = "None"
        db.commit()

        return {
            "status": "success",
            "updated": len(apps),
            "output": result.get("output", "")
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Update failed: {str(e)}")
    
@router.post("/update-all")
def update_all_applications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Step 1: Check for updates
        check_result = subprocess.run(
            ["winget", "upgrade"],
            capture_output=True, text=True
        )

        if check_result.returncode != 0:
            raise HTTPException(status_code=500, detail="Failed to check for updates")

        # Step 2: Install all available updates
        upgrade_result = subprocess.run(
            ["winget", "upgrade", "--all", "--silent"],
            capture_output=True, text=True
        )

        if upgrade_result.returncode == 0:
            return {"status": "success", "message": "All apps have been updated successfully"}
        else:
            return {
                "status": "failed",
                "message": "Update failed during upgrade step",
                "error": upgrade_result.stderr.strip()
            }

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Winget is not installed or not accessible")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Temp routes--------------

@router.post("/devices/{device_id}/test-ssh")
def test_ssh_connection(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")
    
    ssh = SSHManager(device)
    
    # Test basic connection
    try:
        connected = ssh.connect()
        if not connected:
            return {"status": "error", "message": "SSH connection failed"}
        
        # Test a simple command
        result = ssh.execute_command("echo 'Hello World'")
        ssh.client.close()
        
        if "error" in result:
            return {"status": "error", "message": result["error"]}
            
        return {"status": "success", "output": result["output"]}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
@router.post("/devices/{device_id}/scan-raw")
def get_raw_scan_output(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    ssh = SSHManager(device)
    try:
        if not ssh.connect():
            raise HTTPException(500, detail="SSH connection failed")
        
        os_type, _ = ssh.detect_remote_os()
        if not os_type:
            raise HTTPException(500, detail="Could not detect OS")
        
        cmd_info = get_scan_commands().get(os_type.lower())
        if not cmd_info:
            raise HTTPException(400, detail=f"Unsupported OS: {os_type}")
            
        result = cmd_info["handler"](ssh, cmd_info["command"])
        return {
            "status": "success",
            "os": os_type,
            "raw_output": result.get("output", ""),
            "error": result.get("error", None)
        }
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    finally:
        ssh.disconnect()

@router.post("/devices/{device_id}/test-connection")
def test_device_connection(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")
    
    try:
        ssh = SSHManager(device)
        result = ssh.execute_command("echo 'Connection test successful'")
        
        if "error" in result:
            raise HTTPException(400, detail=f"Connection failed: {result['error']}")
            
        return {
            "status": "success",
            "hostname": device.hostname,
            "ip_address": device.ip_address,
            "output": result["output"]
        }
    except Exception as e:
        raise HTTPException(500, detail=f"Connection test error: {str(e)}")






#  i need route for scanning for updates manually using winget --upgrade (/scan)
# route to update a specific app based on id/name using winget upgrade --id <app> (/update/{id})

