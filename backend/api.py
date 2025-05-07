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
from fastapi import WebSocket, WebSocketDisconnect, status
import asyncio


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
    if not output.strip():
        return {"error": "Empty response from remote", "raw_output": output}
    
    try:
        output = output.strip()
        if not output.startswith("{"):
            return {
                "error": "Output is not JSON",
                "raw_output": output
            }
        data = json.loads(output)
    except json.JSONDecodeError as e:
        return {
            "error": f"JSON decode error: {str(e)}",
            "raw_output": output
        }

    
    # Handle PowerShell error case
    if "Error" in data:
        return {
            "error": data.get("Error", "Unknown PowerShell error"),
            "raw_output": output.strip()
        }
    
    # Parse installed applications
    installed_apps = []
    if "InstalledApps" in data:
        if isinstance(data["InstalledApps"], list):
            installed_apps = [
                {
                    "name": app.get("DisplayName", "Unknown"),
                    "version": app.get("DisplayVersion", "Unknown"),
                    "publisher": app.get("Publisher", "Unknown"),
                    "install_date": app.get("InstallDate", "Unknown")
                }
                for app in data["InstalledApps"]
            ]
    
    # Parse winget upgrades
    available_updates = []
    if "WingetUpdates" in data and isinstance(data["WingetUpdates"], list):
        available_updates = [
            {
                "name": update.get("Name", "Unknown"),
                "package_id": update.get("PackageId", "Unknown"),
                "current_version": update.get("CurrentVersion", "Unknown"),
                "available_version": update.get("AvailableVersion", "Unknown")
            }
            for update in data["WingetUpdates"]
        ]
    
    return {
        "installed_software": installed_apps,
        "available_updates": available_updates,
        "metadata": {
            "source": "Windows Registry + winget",
            "timestamp": datetime.utcnow().isoformat()
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
                # Get installed apps from registry
                $apps = Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
                        Where-Object { $_.DisplayName -ne $null } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                        ConvertTo-Json -Depth 5 -Compress
                
                # Get winget upgrades if available
                $wingetUpdates = @()
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    $wingetOutput = winget upgrade | Out-String
                    $wingetUpdates = $wingetOutput -split "`n" | 
                                    Where-Object { $_ -match "^\S" -and $_ -notmatch "Name|---" } |
                                    ForEach-Object {
                                        $parts = $_ -split "\s{2,}"
                                        @{
                                            Name = $parts[0]
                                            PackageId = $parts[1]
                                            CurrentVersion = $parts[2]
                                            AvailableVersion = $parts[3]
                                        }
                                    }
                }
                
                # Return structured data
                @{
                    InstalledApps = ($apps | ConvertFrom-Json)
                    WingetUpdates = $wingetUpdates
                } | ConvertTo-Json -Depth 10 -Compress
            }
            catch {
                @{
                    Error = $_.Exception.Message
                    RawOutput = $_
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
def update_application(app_id: int, db: Session = Depends(get_db)):
    app = db.query(Application).filter(Application.app_id == app_id).first()
    if not app:
        raise HTTPException(404, "Application not found")

    try:
        # 1. Verify package exists
        list_cmd = f"winget list --id {app.package_identifier}"
        list_result = subprocess.run(
            list_cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=30
        )
        
        if "No installed package found" in list_result.stdout:
            raise HTTPException(
                404,
                detail=f"Package not found. Verify the ID matches exactly.\n"
                      f"Try running manually: {list_cmd}\n"
                      f"Output: {list_result.stdout}"
            )

        # 2. Execute upgrade (with progress capture)
        upgrade_cmd = (
            f"winget upgrade --id {app.package_identifier} "
            "--silent --accept-package-agreements --accept-source-agreements"
        )
        
        upgrade_result = subprocess.run(
            upgrade_cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=600  # 10 minute timeout
        )

        # 3. Verify results
        if upgrade_result.returncode != 0:
            raise HTTPException(
                500,
                detail=f"Upgrade failed (code {upgrade_result.returncode}):\n"
                      f"{upgrade_result.stderr or upgrade_result.stdout}"
            )

        # 4. Get updated version
        version_match = re.search(
            rf"{re.escape(app.package_identifier)}\s+([\d.]+)",
            list_result.stdout,
            re.IGNORECASE
        )
        
        if not version_match:
            raise HTTPException(
                500,
                detail=f"Version verification failed. Could not parse version from:\n"
                      f"{list_result.stdout}"
            )

        new_version = version_match.group(1)
        app.current_version = new_version
        app.available_update = "No update available"
        app.last_checked = datetime.utcnow()
        db.commit()

        return {
            "status": "success",
            "new_version": new_version,
            "message": f"{app.app_name} updated successfully"
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Update timed out after 10 minutes")
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Update failed: {str(e)}")



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
def run_remote_scan(device_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    ssh = SSHManager(device)
    if not ssh.connect():
        raise HTTPException(status_code=500, detail="SSH connection failed")

    try:
        script_path = str(Path(__file__).parent / "remote_scanner.py")
        result = ssh.transfer_and_execute(script_path)

        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])

        output = result.get("output", "")
        if not output.strip().startswith("{"):
            raise HTTPException(status_code=500, detail="Remote output is not valid JSON")

        parsed = json.loads(output)
        return {
            "status": "success",
            "device": {
                "hostname": device.hostname,
                "ip_address": device.ip_address
            },
            "scan_results": {
                "status": parsed.get("status", "unknown"),
                "os": parsed.get("os", "unknown"),
                "installed_software": parsed.get("installed_apps", []),
                "available_updates": parsed.get("updates", [])
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        ssh.disconnect()

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
def update_all_apps(device_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    ssh = SSHManager(device)
    if not ssh.connect():
        raise HTTPException(status_code=500, detail="SSH connection failed")

    try:
        # Update all apps via winget
        result = ssh.run_command("winget upgrade --all --accept-source-agreements --accept-package-agreements")

        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])

        return {
            "status": "success",
            "message": "All available updates installed.",
            "output": result.get("output", "")
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")
    finally:
        ssh.disconnect()

    
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

    
@router.post("/test-winget")
def test_winget():
    try:
        # Test both listing and upgrade capabilities
        list_result = subprocess.run(
            ["winget", "list", "--id", "Microsoft.WindowsTerminal"],
            capture_output=True,
            text=True,
            shell=True
        )
        
        upgrade_result = subprocess.run(
            ["winget", "upgrade", "--id", "Microsoft.WindowsTerminal", "--dry-run"],
            capture_output=True,
            text=True,
            shell=True
        )
        
        return {
            "list_output": list_result.stdout,
            "upgrade_dry_run": upgrade_result.stdout,
            "errors": {
                "list": list_result.stderr,
                "upgrade": upgrade_result.stderr
            },
            "return_codes": {
                "list": list_result.returncode,
                "upgrade": upgrade_result.returncode
            }
        }
    except Exception as e:
        return {"error": str(e)}
    





@router.post("/update-by-name/{app_name}")
def update_by_name(
    app_name: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    try:
        # 1. First try winget source
        search_cmd = f"winget list --name \"{app_name}\" --exact"
        search_result = subprocess.run(
            search_cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=30
        )

        # 2. If not found, try msstore source
        if "No installed package found" in search_result.stdout:
            search_cmd = f"winget list --name \"{app_name}\" --exact --source msstore"
            search_result = subprocess.run(
                search_cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=30
            )

        # 3. Parse package info
        match = re.search(
            r"^" + re.escape(app_name) + r"\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(\w+)",
            search_result.stdout,
            re.MULTILINE
        )

        if not match:
            raise HTTPException(
                404,
                detail={
                    "error": f"Application '{app_name}' not found",
                    "solution": f"Try manual search: winget search \"{app_name}\""
                }
            )

        package_id = match.group(1)
        source = match.group(4)

        # 4. Prepare upgrade command
        upgrade_cmd = [
            "winget", "upgrade",
            "--id", package_id,
            "--source", source,
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements"
        ]

        # 5. Run as admin (requires FastAPI to be run as admin)
        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_CONSOLE

        upgrade_result = subprocess.run(
            upgrade_cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=600,
            creationflags=creation_flags
        )

        # 6. Handle results
        if upgrade_result.returncode != 0:
            error_detail = {
                "error": "Upgrade failed",
                "returncode": upgrade_result.returncode,
                "solution": "Try these steps:\n"
                          "1. Run FastAPI as Administrator\n"
                          "2. Verify package exists: winget list --id " + package_id + "\n"
                          "3. Try manual update: " + " ".join(upgrade_cmd)
            }
            raise HTTPException(500, detail=error_detail)

        return {"status": "success", "message": f"{app_name} update completed"}

    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Update timed out")
    except Exception as e:
        raise HTTPException(500, f"Update failed: {str(e)}")
    
@router.post("/devices/{device_id}/command")
def send_command(device_id: int, command: str):
    return {"output": f"Mock output for: {command}"}




@router.websocket("/ws/device/{device_id}/terminal")
async def websocket_terminal(
    websocket: WebSocket,
    device_id: int,
    db: Session = Depends(get_db)
):
    await websocket.accept()
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        await websocket.send_text("Device not found")
        await websocket.close()
        return

    ssh = SSHManager(device)
    if not ssh.connect():
        await websocket.send_text("SSH connection failed")
        await websocket.close()
        return

    try:
        while True:
            command = await websocket.receive_text()
            result = ssh.execute_windows_command(command)
            output = result.get("output", "")
            error = result.get("error", "")
            
            if error:
                await websocket.send_text(f"[ERROR] {error}")
            elif output.strip():
                await websocket.send_text(output.strip())
            else:
                await websocket.send_text("[No output received]")

    except WebSocketDisconnect:
        ssh.disconnect()
    except Exception as e:
        await websocket.send_text(f"[ERROR] {str(e)}")
        ssh.disconnect()