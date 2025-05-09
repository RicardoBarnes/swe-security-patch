import subprocess
import threading
import time

def run_backend():
    subprocess.run(["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"])

def run_frontend():
    time.sleep(2)  # Wait for backend to start
    subprocess.run(["python", "frontend.py"])

threading.Thread(target=run_backend).start()
threading.Thread(target=run_frontend).start()
