"""
Standalone remote scanner
"""
import sys
import json
import platform
import subprocess


def get_windows_updates():
    """Return a list of updateable Windows apps via winget"""
    try:
        result = subprocess.run(
            ["winget", "upgrade", "--source", "winget", "--accept-source-agreements"],
            capture_output=True,
            text=True,
            check=True
        )

        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return []

        updateable_apps = []
        for line in lines[1:]:
            if not line.strip():
                continue

            parts = line.rsplit(None, 3)
            if len(parts) < 4:
                continue

            name_version_part = parts[0]
            current_version = parts[1]
            available_version = parts[2]
            source = parts[3]

            app_name = name_version_part.strip()

            updateable_apps.append({
                "name": app_name,
                "Package_ID": current_version,
                "Current_version": available_version,
                "Available Update": source
            })

        return updateable_apps

    except subprocess.CalledProcessError as e:
        return {"error": f"Winget error: {e.stderr}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def get_linux_updates():
    """Return available updates on Linux"""
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().splitlines()[1:]  # skip header
    except Exception as e:
        return {"error": f"Linux update check failed: {str(e)}"}


def get_mac_updates():
    """Return available updates on macOS"""
    try:
        result = subprocess.run(
            ["brew", "outdated"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().splitlines()
    except Exception as e:
        return {"error": f"macOS update check failed: {str(e)}"}


def main():
    os_name = platform.system().lower()

    try:
        if os_name == "windows":
            updates = get_windows_updates()
        elif os_name == "linux":
            updates = get_linux_updates()
        elif os_name == "darwin":
            updates = get_mac_updates()
        else:
            raise Exception("Unsupported OS")

        print(json.dumps({
            "status": "success",
            "os": os_name,
            "updates": updates
        }))
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "os": os_name,
            "message": str(e)
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()