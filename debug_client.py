#!/usr/bin/env python3
"""
Simple test client to debug connection issues
"""

import socket
import json
from chat_core import SecurityManager

def test_connection():
    print("🔍 Testing connection to secure server...")
    
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        print("✅ Connected to server")
        
        # Initialize security
        security = SecurityManager()
        
        # Receive welcome message
        print("📨 Waiting for welcome message...")
        data = client_socket.recv(1024)
        if data:
            encrypted_data = data.decode()
            print(f"Raw data received: {encrypted_data[:100]}...")
            
            try:
                decrypted = security.decrypt_message(encrypted_data)
                message = json.loads(decrypted)
                print(f"✅ Welcome message: {message}")
            except Exception as e:
                print(f"❌ Failed to decrypt welcome: {e}")
                print(f"Raw data was: {repr(encrypted_data)}")
        
        # Send username
        username_data = {"username": "TestUser"}
        encrypted_username = security.encrypt_message(json.dumps(username_data))
        client_socket.send(encrypted_username.encode())
        print("📤 Sent username")
        
        # Receive response
        print("📨 Waiting for login response...")
        data = client_socket.recv(1024)
        if data:
            encrypted_data = data.decode()
            print(f"Raw response: {encrypted_data[:100]}...")
            
            try:
                decrypted = security.decrypt_message(encrypted_data)
                response = json.loads(decrypted)
                print(f"✅ Login response: {response}")
            except Exception as e:
                print(f"❌ Failed to decrypt response: {e}")
                print(f"Raw data was: {repr(encrypted_data)}")
        
        client_socket.close()
        print("🔚 Connection closed")
        
    except Exception as e:
        print(f"❌ Connection error: {e}")

if __name__ == "__main__":
    test_connection()
