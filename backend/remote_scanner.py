#!/usr/bin/env python3
"""
Standalone script to be executed on remote devices
"""
import sys
import json
from new_database_population import detect_and_sync

def main():
    try:
        # Run the detection
        detect_and_sync()
        
        # Return results as JSON
        print(json.dumps({"status": "success"}))
        return 0
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        return 1

if __name__ == "__main__":
    sys.exit(main())