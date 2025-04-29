import paramiko
from io import StringIO
from typing import Optional, Dict
import logging

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
    
    def execute_command(self, command: str) -> Dict:
        if not self.connect():
            return {"error": "Connection failed"}
            
        try:
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
    
    def transfer_and_execute(self, local_script: str, remote_path: str = "/tmp/") -> Dict:
        if not self.connect():
            return {"error": "Connection failed"}
            
        try:
            sftp = self.client.open_sftp()
            remote_file = f"{remote_path}{local_script.split('/')[-1]}"
            sftp.put(local_script, remote_file)
            sftp.chmod(remote_file, 0o755)  # Make executable
            
            result = self.execute_command(f"python3 {remote_file}")
            self.execute_command(f"rm {remote_file}")  # Cleanup
            return result
            
        except Exception as e:
            return {"error": str(e)}
        finally:
            self.client.close()