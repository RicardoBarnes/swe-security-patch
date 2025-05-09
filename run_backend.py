import subprocess

# Launch FastAPI using Uvicorn
subprocess.run([
    "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"
])
