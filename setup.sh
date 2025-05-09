#!/bin/bash

echo "[1/4] Creating virtual environment..."
python3 -m venv venv

echo "[2/4] Activating virtual environment..."
source venv/bin/activate

echo "[3/4] Installing dependencies..."
pip install -r requirements.txt

echo "[4/4] Starting backend and frontend in background..."
gnome-terminal -- bash -c "python3 run_backend.py; exec bash" &
gnome-terminal -- bash -c "python3 run_frontend.py; exec bash" &
