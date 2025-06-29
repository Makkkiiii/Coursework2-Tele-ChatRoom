#!/usr/bin/env python3
"""
Launch script for NiceGUI TeleChat Desktop Applications
Easily start server and client components as native desktop apps
"""

import sys
import subprocess
import time
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("🖥️ NiceGUI TeleChat Desktop Application Launcher")
        print("=" * 50)
        print("Usage:")
        print("  python launch.py server   # Start server desktop app")
        print("  python launch.py client   # Start client desktop app")
        print("  python launch.py both     # Start both server and client")
        print("  python launch.py demo     # Demo with both applications")
        return
    
    command = sys.argv[1].lower()
    
    if command == "server":
        print("🔒 Starting NiceGUI Secure Server Desktop App...")
        subprocess.run([sys.executable, "NiceGUI_Server.py"])
    
    elif command == "client":
        print("💬 Starting NiceGUI Chat Client Desktop App...")
        subprocess.run([sys.executable, "NiceGUI_Client.py"])
    
    elif command == "both":
        print("🚀 Starting both server and client desktop applications...")
        print("Server desktop window will open first")
        print("Client desktop window will open after")
        print()
        
        # Start server in background
        server_process = subprocess.Popen([sys.executable, "NiceGUI_Server.py"])
        time.sleep(3)  # Give server time to start
        
        # Start client
        try:
            subprocess.run([sys.executable, "NiceGUI_Client.py"])
        finally:
            # Clean up server when client exits
            server_process.terminate()
    
    elif command == "demo":
        print("🎬 Starting demo mode with both desktop applications...")
        print("Two desktop windows will open:")
        print("1. Server admin window")
        print("2. Client chat window")
        
        # Start server
        server_process = subprocess.Popen([sys.executable, "NiceGUI_Server.py"])
        time.sleep(3)
        
        # Start client
        try:
            subprocess.run([sys.executable, "NiceGUI_Client.py"])
        finally:
            server_process.terminate()
    
    else:
        print(f"❌ Unknown command: {command}")
        print("Use: server, client, both, or demo")

if __name__ == "__main__":
    main()
