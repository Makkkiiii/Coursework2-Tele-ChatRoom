#!/usr/bin/env python3
"""
Test XSS Flow - Verify that XSS messages are properly handled:
1. Client sends XSS message to server
2. Server detects and blocks it
3. Server sends warning to client
4. Server logs the attempt
5. Server sends warning to all clients
"""

import socket
import json
import time
import threading

def test_xss_flow():
    """Test the complete XSS flow from client to server"""
    
    print("🧪 Testing XSS Flow...")
    print("=" * 50)
    
    # Test XSS payloads
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "javascript:alert('xss')",
        "<div onclick='alert(\"xss\")'>Click me</div>"
    ]
    
    for i, payload in enumerate(xss_payloads, 1):
        print(f"\n🎯 Test {i}: Testing XSS payload: {payload[:30]}...")
        
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)
            client_socket.connect(("localhost", 12345))
            
            # Authenticate first
            auth_data = {
                "type": "auth",
                "username": f"testuser{i}",
                "password": "testpass123"
            }
            client_socket.send(json.dumps(auth_data).encode('utf-8'))
            
            # Wait for auth response
            response = client_socket.recv(1024)
            auth_response = json.loads(response.decode('utf-8'))
            
            if auth_response.get("type") == "auth_success":
                print(f"✅ Authentication successful for testuser{i}")
                
                # Send XSS payload
                xss_message = {
                    "type": "text",
                    "content": payload
                }
                print(f"📤 Sending XSS payload to server...")
                client_socket.send(json.dumps(xss_message).encode('utf-8'))
                
                # Listen for responses
                responses_received = 0
                start_time = time.time()
                
                while responses_received < 3 and time.time() - start_time < 3:
                    try:
                        response = client_socket.recv(1024)
                        if response:
                            message_data = json.loads(response.decode('utf-8'))
                            responses_received += 1
                            
                            msg_type = message_data.get("type")
                            content = message_data.get("content", "")
                            
                            if msg_type == "warning":
                                print(f"⚠️  Warning received: {content}")
                            elif msg_type == "system":
                                print(f"🔔 System message: {content}")
                            elif msg_type == "text":
                                print(f"💬 Text message: {content}")
                            else:
                                print(f"📨 Other message ({msg_type}): {content}")
                        
                    except socket.timeout:
                        break
                    except Exception as e:
                        print(f"❌ Error receiving response: {e}")
                        break
                
                print(f"📊 Received {responses_received} responses")
                
            else:
                print(f"❌ Authentication failed for testuser{i}")
            
            client_socket.close()
            
        except Exception as e:
            print(f"❌ Test {i} failed: {e}")
        
        time.sleep(0.5)  # Brief pause between tests
    
    print(f"\n" + "=" * 50)
    print("✅ XSS Flow test completed!")
    print("\n🔍 Expected behavior:")
    print("   - Each XSS payload should be blocked by the server")
    print("   - Client should receive a 'warning' message")
    print("   - Server should log the dangerous message attempt")
    print("   - All clients should receive a system warning message")

if __name__ == "__main__":
    test_xss_flow()
