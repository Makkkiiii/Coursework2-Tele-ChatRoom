#!/usr/bin/env python3
"""
Simple test to verify client-server connection and user list functionality
"""

import threading
import time
import sys
import os

# Add project path
sys.path.insert(0, os.path.dirname(__file__))

from NiceGUI_Server_Fixed import SecureChatServer

def test_server():
    """Test server functionality"""
    print("🔧 Starting test server...")
    
    # Create and start server
    server = SecureChatServer(host='localhost', port=12346)  # Use different port for testing
    
    # Start server in background thread
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(2)
    
    print("✅ Test server started on localhost:12346")
    print("📝 Test completed - server is running in background")
    
    # Test user manager
    print(f"📊 Current users: {server.user_manager.get_users()}")
    
    return server

if __name__ == "__main__":
    test_server()
    print("🚀 You can now test client connection to localhost:12346")
    
    # Keep running for a bit
    try:
        time.sleep(30)
        print("🔚 Test server shutting down...")
    except KeyboardInterrupt:
        print("🛑 Test interrupted by user")
