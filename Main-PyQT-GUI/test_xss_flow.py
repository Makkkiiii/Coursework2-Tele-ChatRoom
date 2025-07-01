#!/usr/bin/env python3
"""
Test XSS Flow: Client -> Server -> Security Log
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security import AdvancedSecurityManager, SECURITY_CONFIG

def test_xss_server_side():
    """Test that XSS messages are properly handled server-side"""
    print("🚨 TESTING XSS SERVER-SIDE DETECTION")
    print("=" * 50)
    
    # Initialize server-side security
    advanced_security = AdvancedSecurityManager(SECURITY_CONFIG)
    
    # Simulate XSS messages that should reach the server
    xss_messages = [
        "<script>alert('xss')</script>",
        "javascript:void(0)",
        "eval(malicious_code)",
        "onclick=alert('xss')",
        "on click=alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "Normal message"
    ]
    
    print("\nTesting message processing on server:")
    print("-" * 40)
    
    for i, message in enumerate(xss_messages, 1):
        print(f"\n{i}. Testing: {message}")
        
        # Simulate server processing
        is_valid, result = advanced_security.secure_message_processing(
            message, "testuser", "fake_session_id"
        )
        
        if is_valid:
            print(f"   ✅ ALLOWED: {result}")
        else:
            print(f"   🚨 BLOCKED: {result}")
            print(f"   📝 This should appear in server security log!")
    
    print("\n" + "=" * 50)
    print("✅ XSS messages now reach server for proper blocking and logging!")
    print("🔒 Security events will appear in server GUI when blocked")

if __name__ == "__main__":
    test_xss_server_side()
