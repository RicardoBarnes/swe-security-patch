from fastapi import FastAPI, Depends, HTTPException
from fastapi import APIRouter
import crud
from sqlalchemy.orm import Session
from models import Session as DBSession 
import subprocess
from models import Session as DBSession, Application, User
from auth import authenticate_user, create_access_token, get_current_admin
from fastapi.security import OAuth2PasswordRequestForm


app= APIRouter()


# creating session function to avoid session issues
def get_db():
    db = DBSession()
    try:
        yield db
    finally:
        db.close()
# --------------------------------------------------------------------------------------------------------
# home page
@app.get("/")
def homepage():
    return "PATCH MANAGEMENT DASHBOARD"

@app.get("/admin-dashboard")
def admin_dashboard(user: User = Depends(get_current_admin)):
    return {"message": "Welcome to the admin dashboard", "user": user.username}

# all apps
@app.get("/applications")
def list_applications(db: Session = Depends(get_db)):
    return crud.get_all_apps(db)

# patch info for specific app
@app.get("/patches/{app_id}")
def show_patch_info(app_id: int, db: Session = Depends(get_db) ):
    return crud.get_patch_info(db, app_id)

@app.post("/scan")
def manual_scan(db: Session = Depends(get_db), user: User = Depends(get_current_admin)):
    from new_database_population import detect_and_sync  
    try:
        detect_and_sync()  # runs Windows/macOS/Linux scan depending on OS
        return {"status": "success", "message": "Scan complete and database updated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update/{app_id}")
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

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}




#  i need route for scanning for updates manually using winget --upgrade (/scan)
# route to update a specific app based on id/name using winget upgrade --id <app> (/update/{id})

