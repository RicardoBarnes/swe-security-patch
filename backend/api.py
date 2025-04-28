from fastapi import FastAPI, Depends, HTTPException
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
from ssh_utils import ssh_connect_and_run
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


@router.post("/run_command_on_device/")
def run_command_on_device(device_id: int, command: str, db: Session = Depends(get_db)):
    # Fetch the device from the database
    device = db.query(models.Device).filter(models.Device.id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    # Ensure the current user has access to this device
    # current_user = db.query(models.User).filter(models.User.id == device.user_id).first()

    # if not current_user:
    #     raise HTTPException(status_code=403, detail="You do not have permission to access this device.")

    # Run the command on the remote device via SSH
    result = ssh_connect_and_run(
        device.ip_address, 
        device.ssh_username, 
        device.ssh_password, 
        command  
    )

    # Return the result from the SSH command execution
    if 'output' in result:
        return {"message": "Command executed successfully.", "output": result['output']}
    if 'error' in result:
        raise HTTPException(status_code=500, detail=f"Command execution failed: {result['error']}")
    return {"message": result.get('message', 'Unknown status')}

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

# Remote Execution
@router.post("/devices/{device_id}/run")
def run_remote_command(
    device_id: int,
    command: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run a command on a remote device."""
    device = db.query(Device).filter(Device.id == device_id).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    
    # Verify useer is admin
    if device.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied.")
    
    result = ssh_connect_and_run(
        device=device,
        command=command,
        script_path="./new_database_population.py"  # path to script
    )
    
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    
    return {"result": result}






#  i need route for scanning for updates manually using winget --upgrade (/scan)
# route to update a specific app based on id/name using winget upgrade --id <app> (/update/{id})

