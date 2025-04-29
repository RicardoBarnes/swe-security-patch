from fastapi import Depends, HTTPException
from fastapi import APIRouter
import crud
from sqlalchemy.orm import Session
from models import Session as DBSession 
import subprocess
from models import Session as DBSession, Application, User, Device
from auth import authenticate_user, create_access_token, get_current_admin
from fastapi.security import OAuth2PasswordRequestForm
from auth import register_user, get_current_user
from schemas import UserSignup
import models
from datetime import datetime
from ssh_utils import SSHManager
from typing import List


router= APIRouter()


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
@router.get("/patches/{app_id}")
def show_patch_info(app_id: int, db: Session = Depends(get_db) ):
    return crud.get_patch_info(db, app_id)

@router.post("/scan")
def manual_scan(db: Session = Depends(get_db), user: User = Depends(get_current_admin)):
    from new_database_population import detect_and_sync  
    try:
        detect_and_sync()  # runs Windows/macOS/Linux scan depending on OS
        return {"status": "success", "message": "Scan complete and database updated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update/{app_id}")
def update_application(app_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_admin)):
    app = db.query(Application).filter(Application.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    try:
        result = subprocess.run(
            ["winget", "upgrade", "--id", app.package_identifier, "--silent"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return {"status": "success", "output": result.stdout}
        else:
            return {"status": "failed", "error": result.stderr}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upgrade app: {str(e)}")
    

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
def scan_remote_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Trigger remote scan on specific device"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    ssh = SSHManager(device)
    result = ssh.transfer_and_execute("./scripts/remote_scanner.py")
    
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    
    return {"status": "success", "result": result["output"]}

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








#  i need route for scanning for updates manually using winget --upgrade (/scan)
# route to update a specific app based on id/name using winget upgrade --id <app> (/update/{id})

