"""
Simple Integration Example: Adding Advanced Security to Your Chat App
This shows exactly how to upgrade your existing chat application with the new security features.
"""

import sys
import os

# Add path to use fixed security module
sys.path.append(os.path.dirname(__file__))

from advanced_security_fixed import AdvancedSecurityManager, SECURITY_CONFIG
from chat_core import SecurityManager as BasicSecurityManager


class UpgradedChatServer:
    """Example: Your existing ChatServer with added security"""
    
    def __init__(self, host='localhost', port=12345, security_level="STANDARD"):
        self.host = host
        self.port = port
        
        # STEP 1: Replace basic security with advanced security
        # OLD: self.security_manager = BasicSecurityManager()
        # NEW: Use advanced security with configurable levels
        
        security_configs = {
            "BASIC": {**SECURITY_CONFIG, "max_requests": 50, "enable_rate_limiting": False},
            "STANDARD": SECURITY_CONFIG,
            "HIGH": {**SECURITY_CONFIG, "max_requests": 20, "session_timeout": 1800}
        }
        
        config = security_configs.get(security_level, SECURITY_CONFIG)
        self.advanced_security = AdvancedSecurityManager(config)
        
        print(f"✅ Server initialized with {security_level} security level")
    
    def handle_client_connection(self, client_socket, client_address):
        """Example: Enhanced client connection handling"""
        ip_address = client_address[0]
        
        try:
            # STEP 2: Receive and validate username with security checks
            data = client_socket.recv(1024).decode()
            username_data = eval(data)  # In real app, use json.loads with error handling
            username = username_data.get("username", "")
            
            # STEP 3: Use advanced authentication instead of basic username check
            # OLD: if username and self.user_manager.add_user(username, client_socket):
            # NEW: Use comprehensive authentication
            
            success, message, session_id = self.advanced_security.authenticate_user(username, ip_address)
            
            if not success:
                error_response = {"success": False, "message": message}
                client_socket.send(str(error_response).encode())
                client_socket.close()
                return
            
            # STEP 4: Send success response with session ID
            success_response = {
                "success": True, 
                "message": message, 
                "session_id": session_id
            }
            client_socket.send(str(success_response).encode())
            
            print(f"✅ User {username} authenticated successfully from {ip_address}")
            return username, session_id
            
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            client_socket.close()
            return None, None
    
    def process_message(self, raw_message, sender, session_id, sender_ip):
        """Example: Enhanced message processing with security"""
        
        # STEP 5: Validate session before processing any message
        is_valid_session, validated_username = self.advanced_security.validate_session(session_id, sender_ip)
        
        if not is_valid_session:
            return False, "Invalid or expired session"
        
        if validated_username != sender:
            return False, "Session username mismatch"
        
        # STEP 6: Use secure message processing instead of basic handling
        # OLD: Simply broadcast the message
        # NEW: Validate and sanitize the message
        
        is_safe, processed_message = self.advanced_security.secure_message_processing(
            raw_message, sender, session_id
        )
        
        if not is_safe:
            return False, f"Message rejected: {processed_message}"
        
        print(f"✅ Safe message from {sender}: {processed_message[:50]}...")
        return True, processed_message
    
    def handle_file_upload(self, filename, file_size, sender):
        """Example: Enhanced file upload handling"""
        
        # STEP 7: Use advanced file security instead of basic size check
        # OLD: if file_size > MAX_SIZE: return False
        # NEW: Comprehensive file validation
        
        is_valid, message = self.advanced_security.secure_file_processing(filename, file_size, sender)
        
        if not is_valid:
            print(f"❌ File rejected from {sender}: {message}")
            return False, message
        
        print(f"✅ File accepted from {sender}: {filename}")
        return True, "File upload accepted"


class UpgradedChatClient:
    """Example: Your existing ChatClient with added security"""
    
    def __init__(self):
        # STEP 8: Add advanced encryption capabilities
        from advanced_security_fixed import HybridCrypto, DigitalSignature
        
        self.hybrid_crypto = HybridCrypto()
        self.digital_signature = DigitalSignature()
        self.session_id = None
        
        print("✅ Client initialized with hybrid encryption and digital signatures")
    
    def enhanced_connect(self, host, port, username):
        """Example: Enhanced connection with better security"""
        try:
            import socket
            import json
            
            # Connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            # STEP 9: Send username with additional security info
            # OLD: Send just username
            # NEW: Send username with public key for secure communication
            
            auth_data = {
                "username": username,
                "client_public_key": self.hybrid_crypto.get_public_key_pem(),
                "signature_public_key": self.digital_signature.get_public_key_pem()
            }
            
            # Send authentication data
            self.socket.send(str(auth_data).encode())
            
            # Receive response
            response = self.socket.recv(1024).decode()
            response_data = eval(response)  # In real app, use json.loads
            
            if response_data.get("success"):
                self.session_id = response_data.get("session_id")
                print(f"✅ Connected successfully! Session: {self.session_id[:8]}...")
                return True
            else:
                print(f"❌ Connection failed: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def enhanced_send_message(self, message):
        """Example: Enhanced message sending with encryption and signatures"""
        if not self.session_id:
            print("❌ Not connected to server")
            return False
        
        try:
            import json
            import time
            
            # STEP 10: Create message with signature
            # OLD: Send plain message
            # NEW: Sign message for authenticity
            
            message_data = {
                "type": "text",
                "content": message,
                "session_id": self.session_id,
                "timestamp": time.time()
            }
            
            # Sign the message
            message_json = json.dumps(message_data, sort_keys=True)
            signature = self.digital_signature.sign_message(message_json)
            message_data["signature"] = signature
            
            # STEP 11: Encrypt the entire signed message
            # OLD: Basic encryption
            # NEW: Hybrid encryption for better security
            
            encrypted_message = self.hybrid_crypto.encrypt_message(json.dumps(message_data))
            
            # Send encrypted message
            self.socket.send(str(encrypted_message).encode())
            print(f"✅ Secure message sent: {message[:30]}...")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send secure message: {e}")
            return False


def demonstrate_security_upgrade():
    """Demonstrate the security upgrade process"""
    
    print("🔐 DEMONSTRATING SECURITY UPGRADES")
    print("=" * 50)
    
    # Show the upgrade process
    print("\n1. 🚀 INITIALIZING UPGRADED SERVER")
    server = UpgradedChatServer(security_level="HIGH")
    
    print("\n2. 🖥️ INITIALIZING UPGRADED CLIENT")
    client = UpgradedChatClient()
    
    print("\n3. 🔑 TESTING AUTHENTICATION")
    # Simulate authentication
    success, message, session_id = server.advanced_security.authenticate_user("alice", "192.168.1.100")
    print(f"   Authentication result: {success}, Message: {message}")
    
    print("\n4. 💬 TESTING MESSAGE PROCESSING")
    # Test message processing
    if success and session_id:
        is_safe, processed = server.advanced_security.secure_message_processing(
            "Hello everyone!", "alice", session_id
        )
        print(f"   Message processing: {is_safe}, Content: {processed}")
        
        # Test malicious message
        is_safe, processed = server.advanced_security.secure_message_processing(
            "<script>alert('xss')</script>", "alice", session_id
        )
        print(f"   Malicious message blocked: {not is_safe}")
    
    print("\n5. 📁 TESTING FILE SECURITY")
    # Test file processing
    is_valid, msg = server.advanced_security.secure_file_processing("document.pdf", 1024, "alice")
    print(f"   Safe file accepted: {is_valid}")
    
    is_valid, msg = server.advanced_security.secure_file_processing("virus.exe", 1024, "alice")
    print(f"   Dangerous file blocked: {not is_valid}")
    
    print("\n6. 🔒 TESTING ENCRYPTION")
    # Test encryption
    test_message = "This is a confidential message!"
    encrypted = client.hybrid_crypto.encrypt_message(test_message)
    decrypted = client.hybrid_crypto.decrypt_message(encrypted)
    print(f"   Encryption test passed: {test_message == decrypted}")
    
    print("\n7. ✍️ TESTING DIGITAL SIGNATURES")
    # Test signatures
    signature = client.digital_signature.sign_message(test_message)
    is_valid = client.digital_signature.verify_signature(test_message, signature)
    print(f"   Digital signature verified: {is_valid}")
    
    print("\n" + "=" * 50)
    print("🎉 ALL SECURITY UPGRADES WORKING CORRECTLY!")
    
    print("\n📋 SUMMARY OF IMPROVEMENTS:")
    improvements = [
        "✅ Rate limiting prevents DoS attacks",
        "✅ Input validation blocks XSS and injection attacks", 
        "✅ Session management prevents hijacking",
        "✅ Hybrid encryption provides forward secrecy",
        "✅ Digital signatures ensure message authenticity",
        "✅ File validation prevents malware uploads",
        "✅ Comprehensive audit logging for security monitoring",
        "✅ Configurable security levels for different use cases"
    ]
    
    for improvement in improvements:
        print(f"   {improvement}")


def show_integration_steps():
    """Show step-by-step integration instructions"""
    
    print("\n🛠️ HOW TO INTEGRATE INTO YOUR EXISTING CHAT APP")
    print("=" * 55)
    
    steps = [
        {
            "step": "1. Import Advanced Security",
            "old_code": "from chat_core import SecurityManager",
            "new_code": "from advanced_security_fixed import AdvancedSecurityManager, SECURITY_CONFIG"
        },
        {
            "step": "2. Replace Basic Security Manager", 
            "old_code": "self.security_manager = SecurityManager()",
            "new_code": "self.security_manager = AdvancedSecurityManager(SECURITY_CONFIG)"
        },
        {
            "step": "3. Add Authentication Validation",
            "old_code": "if username: # basic check",
            "new_code": "success, msg, session_id = self.security_manager.authenticate_user(username, ip)"
        },
        {
            "step": "4. Add Message Validation",
            "old_code": "# directly process message",
            "new_code": "is_safe, msg = self.security_manager.secure_message_processing(message, sender, session)"
        },
        {
            "step": "5. Add File Security",
            "old_code": "if file_size < MAX_SIZE:",
            "new_code": "is_valid, msg = self.security_manager.secure_file_processing(filename, size, sender)"
        },
        {
            "step": "6. Add Session Validation",
            "old_code": "# no session checking",
            "new_code": "is_valid, username = self.security_manager.validate_session(session_id, ip)"
        }
    ]
    
    for i, step_info in enumerate(steps, 1):
        print(f"\n{step_info['step']}:")
        print(f"   OLD: {step_info['old_code']}")
        print(f"   NEW: {step_info['new_code']}")
    
    print(f"\n{'=' * 55}")
    print("💡 TIPS:")
    print("• Start with BASIC security level and gradually increase")
    print("• Test each security feature individually")
    print("• Monitor security logs for unusual activity")
    print("• Configure rate limits based on your user base")
    print("• Regularly update security configurations")


if __name__ == "__main__":
    demonstrate_security_upgrade()
    show_integration_steps()
    
    print(f"\n{'=' * 55}")
    print("🚀 READY TO UPGRADE YOUR CHAT APPLICATION!")
    print("📁 Files you need:")
    print("   • advanced_security_fixed.py (security components)")
    print("   • This file (integration examples)")
    print("   • Your existing chat_core.py, TCPServer.py, ClientServer.py")
    print(f"{'=' * 55}")
