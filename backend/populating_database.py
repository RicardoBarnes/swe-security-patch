import subprocess
from datetime import datetime
from models import session, Application, PatchHistory


def get_upgradable_apps():
    result = subprocess.run(["winget", "upgrade"], capture_output=True, text=True)

    if result.returncode != 0:
        print("Error:", result.stderr)
        raise RuntimeError("winget command failed")

    lines = result.stdout.splitlines()

    apps = []
    parsing = False
    for line in lines:
        if line.strip().startswith("Name") and "Id" in line and "Version" in line:
            parsing = True
            continue

        if parsing and line.strip():
            parts = line.split()
            if len(parts) < 5:
                continue

        #    reverse slicing for spaces in names
            source = parts[-1]
            available_version = parts[-2]
            current_version = parts[-3]
            package_identifier = parts[-4]
            app_name = " ".join(parts[:-4])

            apps.append({
                "name": app_name.strip(),
                "id": package_identifier.strip(),
                "installed": current_version.strip(),
                "available": available_version.strip()
            })

    return apps

def log_patch_history(app_id, patch_version):
    # Check if a pending patch with same version already exists
    existing_patch = session.query(PatchHistory).filter_by(
        app_id=app_id,
        patch_version=patch_version,
        status="pending"
    ).first()

    if not existing_patch:
        new_patch = PatchHistory(
            app_id=app_id,
            patch_version=patch_version,
            status="pending"
        )
        session.add(new_patch)
        session.commit()


def save_apps_to_db():
    apps = get_upgradable_apps()

    for app in apps:
        existing = session.query(Application).filter_by(package_identifier=app["id"]).first()

        if existing:
            existing.app_name = app["name"]
            existing.current_version = app["installed"]
            existing.available_update = app["available"]
            existing.last_checked = datetime.utcnow()
            app_id = existing.app_id
        else:
            new_app = Application(
                app_name=app["name"],
                package_identifier=app["id"],
                current_version=app["installed"],
                available_update=app["available"],
                last_checked=datetime.utcnow()
            )
            session.add(new_app)
            session.commit()  # commit to get ID
            app_id = new_app.app_id

        log_patch_history(app_id, app["available"])

    
def detect_applied_updates():
    print("\nChecking if any pending updates have been applied...")

    # Step 1: Get currently installed apps using winget list
    result = subprocess.run(["winget", "list"], capture_output=True, text=True)
    if result.returncode != 0:
        print("Failed to run 'winget list'")
        return

    installed_apps = {}
    for line in result.stdout.splitlines()[1:]:  # Skip headers
        parts = line.strip().split(None, 3)
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        installed_apps[name] = version

    # Step 2: Find pending patches
    pending_patches = session.query(PatchHistory).filter_by(status="pending").all()

    for patch in pending_patches:
        app = session.query(Application).filter_by(app_id=patch.app_id).first()
        if not app:
            continue

        installed_version = installed_apps.get(app.app_name)

        if installed_version == patch.patch_version:
            patch.status = "success"
            patch.installed_on = datetime.utcnow()
            session.commit()
            print(f"{app.app_name} updated to {installed_version} — history marked as success")
        else:
            print(f"{app.app_name} not updated yet (installed: {installed_version}, expected: {patch.patch_version})")


if __name__ == "__main__":
    save_apps_to_db()
    detect_applied_updates()
