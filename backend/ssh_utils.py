import paramiko
import os
import logging
from pathlib import Path
from typing import Dict
import socket

logger = logging.getLogger(__name__)

class SSHManager:
    def __init__(self, device):
        self.device = device
        self.client = None
        self.shell = None  # For interactive shell
        self.connected = False
        self.ssh = None

    def start_interactive_shell(self):
        """Start an interactive shell session"""
        if not self.connect():
            return False
        
        try:
            self.shell = self.client.invoke_shell()
            self.shell.settimeout(1)  # Small timeout for non-blocking reads
            return True
        except Exception as e:
            logger.error(f"Failed to start shell: {str(e)}")
            return False
        
    def send_shell_command(self, command):
        """Send command to interactive shell"""
        if not self.shell:
            return {"error": "No active shell session"}
        
        try:
            self.shell.send(command + "\n")
            return {"status": "command_sent"}
        except Exception as e:
            return {"error": str(e)}

    def read_shell_output(self, timeout=0.1):
        """Read output from interactive shell"""
        if not self.shell:
            return {"error": "No active shell session"}
        
        output = ""
        try:
            while True:
                if self.shell.recv_ready():
                    output += self.shell.recv(4096).decode('utf-8', errors='ignore')
                else:
                    break
        except socket.timeout:
            pass
            
        return {"output": output}

    def close_interactive_shell(self):
        """Close the interactive shell"""
        if self.shell:
            self.shell.close()
            self.shell = None

        
    def connect(self) -> bool:
        try:
            if self.connected and self.client:
                return True  # Already connected
                
            if not all([self.device.ip_address, self.device.ssh_username]):
                raise ValueError("Missing connection parameters")
                
            # Close any existing connection
            self.disconnect()
                
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.device.ip_address,
                username=self.device.ssh_username,
                password=self.device.ssh_password,
                timeout=10,
                banner_timeout=20,
                allow_agent=False,
                look_for_keys=False
            )
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"SSH connection failed to {getattr(self.device, 'hostname', 'unknown')}: {str(e)}")
            self.connected = False
            return False
    
    def disconnect(self):
        if self.client:
            try:
                self.client.close()
            except:
                pass
        self.client = None
        self.connected = False

    def run_command(self, command: str):
        if not self.connected or not self.client:
            raise Exception("SSH connection not established")
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return {"output": output, "error": error}
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}

    
    def execute_command(self, command: str, close_after: bool = False) -> Dict[str, str]:
        if not self.connected and not self.connect():
            return {"error": "SSH connection failed"}
            
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if exit_status != 0 or error:
                return {"error": error or f"Command failed with status {exit_status}"}
            return {"output": output}
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}
        finally:
            if close_after:
                self.disconnect()
    
    def transfer_and_execute(self, local_script_path: str) -> Dict[str, str]:
        """Transfers and executes remote_scanner.py on the device"""
        try:
            if not self.connect():
                return {"error": "SSH connection failed"}

            # ✅ Use a non-restricted folder like C:\Users\Public
            remote_path = "C:\\Users\\Public\\remote_scanner.py"

            # ✅ Get full local path
            script_path = Path(local_script_path).absolute()

            # ✅ Transfer file to remote device
            with self.client.open_sftp() as sftp:
                sftp.put(str(script_path), remote_path)

            # ✅ Use PowerShell to run the script using `py`
            exec_cmd = f'powershell -Command "python \\"{remote_path}\\""'
            result = self.execute_windows_command(exec_cmd)

            # Optional: Clean up after (you can remove this if debugging)
            self.execute_windows_command(f'del /f \\"{remote_path}\\"', close_after=True)

            return result
        except Exception as e:
            return {"error": f"Transfer or execution failed: {str(e)}"}
        finally:
            self.disconnect()



    def execute_windows_command(self, command: str, close_after: bool = False) -> Dict[str, str]:
        """More reliable Windows command execution with timeout"""
        try:
            if not self.connected and not self.connect():
                return {"error": "SSH connection failed"}
                
            # Set timeout and combine streams
            full_cmd = f"powershell -Command \"{command} 2>&1 | Out-String\""
            stdin, stdout, stderr = self.client.exec_command(full_cmd, timeout=30)
            
            # Wait with timeout
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='replace').strip()
            
            if exit_status != 0:
                return {"error": output}
            return {"output": output}
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}
        finally:
            if close_after:
                self.disconnect()

    # def run_command(self, command: str):
    #     try:
    #         stdin, stdout, stderr = self.ssh.exec_command(command)
    #         output = stdout.read().decode()
    #         error = stderr.read().decode()
    #         return {"output": output.strip(), "error": error.strip()}
    #     except Exception as e:
    #         return {"error": str(e)}

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

