#!/usr/bin/env python3
"""
Simple test server for debugging message format issues
"""

import socket
import threading
import json
from chat_core import SecurityManager

class TestServer:
    def __init__(self):
        self.security = SecurityManager()
        self.running = False
    
    def start(self):
        """Start test server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', 12345))
            self.server_socket.listen(5)
            
            self.running = True
            print("🔒 Test server started on localhost:12345")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"📱 Client connected: {client_address}")
                    
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    thread.start()
                    
                except socket.error:
                    break
                    
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            if hasattr(self, 'server_socket'):
                self.server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        """Handle client connection"""
        try:
            # Send welcome message
            welcome = {
                "type": "server_message",
                "content": "🔒 Welcome to Test Server! Please send your username."
            }
            self.send_message(client_socket, welcome)
            print("📤 Sent welcome message")
            
            # Receive username
            data = client_socket.recv(1024)
            if data:
                encrypted_data = data.decode()
                print(f"📨 Received: {encrypted_data[:50]}...")
                
                try:
                    decrypted = self.security.decrypt_message(encrypted_data)
                    user_data = json.loads(decrypted)
                    username = user_data.get("username", "Unknown")
                    print(f"👤 Username: {username}")
                    
                    # Send success response
                    success = {
                        "type": "login_success",
                        "content": f"Welcome {username}! You are connected.",
                        "users": [username]
                    }
                    self.send_message(client_socket, success)
                    print("📤 Sent success response")
                    
                except Exception as e:
                    print(f"❌ Failed to process username: {e}")
                    error = {
                        "type": "error",
                        "content": "Failed to process username"
                    }
                    self.send_message(client_socket, error)
            
        except Exception as e:
            print(f"❌ Client handling error: {e}")
        finally:
            client_socket.close()
            print(f"🔚 Client {client_address} disconnected")
    
    def send_message(self, client_socket, message):
        """Send encrypted message to client"""
        try:
            json_data = json.dumps(message)
            encrypted = self.security.encrypt_message(json_data)
            client_socket.send(encrypted.encode())
        except Exception as e:
            print(f"❌ Send error: {e}")

if __name__ == "__main__":
    server = TestServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.running = False
