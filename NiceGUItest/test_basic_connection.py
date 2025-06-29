#!/usr/bin/env python3
"""
Simple client connection test
"""

import socket
import json
import time
import sys
import os

# Add project path
sys.path.insert(0, os.path.dirname(__file__))

from core import SecurityManager

def test_basic_connection():
    """Test basic socket connection to server"""
    print("🔧 Testing basic connection...")
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Connect to server
        sock.connect(('localhost', 12345))
        print("✅ Socket connection successful!")
        
        # Test encryption
        security_manager = SecurityManager()
        username_data = {"username": "TestUser"}
        encrypted_data = security_manager.encrypt_message(json.dumps(username_data))
        
        # Send username
        sock.send(encrypted_data.encode())
        print("✅ Username sent!")
        
        # Try to receive response
        try:
            response = sock.recv(4096)
            if response:
                encrypted_response = response.decode().strip()
                decrypted_response = security_manager.decrypt_message(encrypted_response)
                response_data = json.loads(decrypted_response)
                print(f"✅ Server response: {response_data}")
            else:
                print("❌ No response from server")
        except Exception as e:
            print(f"⚠️ Response error: {e}")
        
        sock.close()
        print("✅ Connection test completed!")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    test_basic_connection()
