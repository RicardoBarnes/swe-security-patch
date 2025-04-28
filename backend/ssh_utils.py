import paramiko
from typing import Dict, Optional
from models import Device
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def ssh_connect_and_run(
    device: Device,
    command: str,
    script_path: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, str]:
    """
    Execute a command on a remote device via SSH.
    
    Args:
        device: Device model object (contains IP, username, password).
        command: The command to execute (e.g., "run_scan" or a shell command).
        script_path: Path to the script on the remote device (optional).
        timeout: SSH connection timeout (seconds).
    
    Returns:
        Dict with "output", "error", or "message".
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the device
        ssh.connect(
            device.ip_address,
            username=device.ssh_username,
            password=device.ssh_password,
            timeout=timeout
        )
        
        # If a script path is provided, execute the script with the command
        if script_path:
            full_command = f"python3 {script_path} {command}"
        else:
            full_command = command
        
        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(full_command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        ssh.close()
        
        if error:
            logger.error(f"SSH error on {device.hostname}: {error}")
            return {"error": error}
        elif output:
            logger.info(f"SSH output from {device.hostname}: {output}")
            return {"output": output}
        else:
            return {"message": "Command executed successfully (no output)."}
            
    except Exception as e:
        logger.error(f"SSH failed for {device.hostname}: {str(e)}")
        return {"error": f"SSH connection failed: {str(e)}"}