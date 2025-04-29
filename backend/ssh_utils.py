import paramiko
import os
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)

class SSHManager:
    def __init__(self, device):
        self.device = device
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
    def connect(self) -> bool:
        try:
            self.client.connect(
                hostname=self.device.ip_address,
                username=self.device.ssh_username,
                password=self.device.ssh_password,
                timeout=10
            )
            return True
        except Exception as e:
            logger.error(f"SSH connection failed to {self.device.hostname}: {str(e)}")
            return False
    
    def execute_command(self, command: str) -> Dict[str, str]:
        if not self.connect():
            return {"error": "Connection failed"}
            
        try:
            # For Windows, wrap commands in PowerShell Start-Process for elevation
            if any(cmd in command.lower() for cmd in ['winget', 'choco', 'msiexec']):
                command = f"powershell Start-Process -Verb RunAs -Wait -FilePath cmd -ArgumentList '/c {command}'"
            
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
        
            if error:
                return {"error": error}
            return {"output": output}
            
        except Exception as e:
            return {"error": str(e)}
        finally:
            self.client.close()
    
    def transfer_and_execute(self, local_script: str, remote_path: str = "/tmp/") -> Dict[str, str]:
        """Improved version with absolute path handling"""
        # Convert to absolute path
        script_path = Path(local_script).absolute()
        
        # Verify file exists
        if not script_path.exists():
            error_msg = f"Script not found at {script_path}"
            logger.error(error_msg)
            return {"error": error_msg}
            
        if not self.connect():
            return {"error": "Connection failed"}
            
        try:
            sftp = self.client.open_sftp()
            remote_file = f"{remote_path}{script_path.name}"  # Uses just the filename
            
            logger.info(f"Transferring {script_path} to {self.device.hostname}:{remote_file}")
            sftp.put(str(script_path), remote_file)
            sftp.chmod(remote_file, 0o755)  # Make executable
            
            # Execute with Python 3 (or python on Windows)
            result = self.execute_command(f"python3 {remote_file}")
            
            # Cleanup
            self.execute_command(f"rm {remote_file}")
            return result
            
        except Exception as e:
            logger.error(f"Transfer/execute failed: {str(e)}")
            return {"error": str(e)}
        finally:
            self.client.close()

    def execute_windows_command(self, command: str) -> Dict[str, str]:
        """Special handling for Windows commands requiring elevation"""
        if not self.connect():
            return {"error": "Connection failed"}
        
        try:
            # Create a temporary PowerShell script
            script = f"""
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {{
                Start-Process -Verb RunAs -Wait -FilePath 'cmd.exe' -ArgumentList '/c {command} > $tempFile 2>&1'
                Get-Content $tempFile -Raw
            }} finally {{
                Remove-Item $tempFile -ErrorAction SilentlyContinue
            }}
            """
            
            stdin, stdout, stderr = self.client.exec_command(
                f"powershell -Command \"{script}\""
            )
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                return {"error": error}
            return {"output": output}
                
        except Exception as e:
            return {"error": str(e)}
        finally:
            self.client.close()

    def detect_remote_os(self):
        detection_sequence = [
        # Windows detection
        {
            "command": "ver",
            "test": lambda o: "windows" if o and "windows" in o.lower() else None,
            "name": "Windows ver command"
        },
        # macOS detection
        {
            "command": "sw_vers -productName",
            "test": lambda o: "mac" if o and ("mac" in o.lower() or "darwin" in o.lower()) else None,
            "name": "macOS sw_vers"
        },
        # Linux detection (modern systems)
        {
            "command": "cat /etc/os-release",
            "test": lambda o: "linux" if o and ("id=" in o.lower() or "linux" in o.lower()) else None,
            "name": "Linux os-release"
        },
        # Linux detection (older systems)
        {
            "command": "cat /etc/redhat-release",
            "test": lambda o: "linux" if o else None,
            "name": "RedHat release"
        },
        # Fallback to uname
        {
            "command": "uname -s",
            "test": lambda o: "linux" if o and "linux" in o.lower() else 
                            "mac" if o and "darwin" in o.lower() else None,
            "name": "uname"
        },
        # Final fallbacks
        {
            "command": "echo $OSTYPE",
            "test": lambda o: "linux" if o and "linux" in o.lower() else 
                            "mac" if o and "darwin" in o.lower() else None,
            "name": "OSTYPE"
        },
        {
            "command": "python3 -c 'import platform; print(platform.system().lower())' || python -c 'import platform; print(platform.system().lower())'",
            "test": lambda o: o.strip() if o and o.strip() in ["linux", "windows", "darwin"] else None,
            "name": "Python platform"
        }
        ]
    
        debug_info = []
        for test in detection_sequence:
            try:
                result = self.execute_command(test["command"])
                debug_info.append(f"{test['name']}: {result}")
                
                if "error" not in result and result["output"]:
                    detected = test["test"](result["output"])
                    if detected:
                        return detected, debug_info
            except Exception as e:
                debug_info.append(f"{test['name']} failed: {str(e)}")
                continue
        
        return None, debug_info
    
    def detect_os(self):
        """Detect OS and return just the string (without debug info)"""
        os_type, _ = self.detect_remote_os()  # Unpack tuple, ignore debug info
        return os_type

