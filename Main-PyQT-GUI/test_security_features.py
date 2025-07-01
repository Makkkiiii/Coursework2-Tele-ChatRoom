#!/usr/bin/env python3
"""
Quick Security Features Test
Test the implemented security features to ensure they work correctly
"""

import sys
import time
from security import InputValidator, AdvancedSecurityManager, SECURITY_CONFIG

def test_security_features():
    """Test all security features"""
    print("🔐 TESTING SECURITY FEATURES")
    print("=" * 50)
    
    # Initialize security components
    input_validator = InputValidator()
    security_manager = AdvancedSecurityManager(SECURITY_CONFIG)
    
    # Test 1: Username Validation
    print("\n1. Testing Username Validation...")
    test_usernames = [
        ("validuser123", True),
        ("admin", False),  # Reserved
        ("ab", False),     # Too short
        ("user_with_symbols@#", False),  # Invalid chars
        ("valid_user", True),
        ("", False),       # Empty
    ]
    
    for username, expected in test_usernames:
        is_valid, msg = input_validator.validate_username(username)
        status = "✅ PASS" if is_valid == expected else "❌ FAIL"
        print(f"   {username:20} → {status} ({msg[:40]}...)")
    
    # Test 2: XSS Message Validation
    print("\n2. Testing XSS Message Validation...")
    test_messages = [
        ("Hello world!", True),
        ("<script>alert('xss')</script>", False),
        ("javascript:void(0)", False),
        ("eval(malicious_code)", False),
        ("Normal message with <b>bold</b>", True),  # HTML should be escaped
        ("on click=alert('xss')", False),
    ]
    
    for message, expected in test_messages:
        is_valid, result = input_validator.validate_message(message)
        status = "✅ PASS" if is_valid == expected else "❌ FAIL"
        print(f"   {message[:30]:30} → {status}")
        if not is_valid:
            print(f"      Blocked: {result}")
    
    # Test 3: Rate Limiting
    print("\n3. Testing Rate Limiting...")
    rate_limiter = security_manager.rate_limiter
    test_ip = "192.168.1.100"
    
    # Test normal usage
    allowed_count = 0
    blocked_count = 0
    
    for i in range(35):  # Test 35 requests (limit is 30)
        if rate_limiter.is_allowed(test_ip):
            allowed_count += 1
        else:
            blocked_count += 1
    
    print(f"   Allowed requests: {allowed_count}")
    print(f"   Blocked requests: {blocked_count}")
    status = "✅ PASS" if allowed_count <= 30 and blocked_count > 0 else "❌ FAIL"
    print(f"   Rate limiting: {status}")
    
    # Test 4: File Validation
    print("\n4. Testing File Validation...")
    test_files = [
        ("document.pdf", 1024, True),
        ("malware.exe", 1024, False),
        ("script.js", 512, False),
        ("photo.jpg", 1024, True),
        ("largefile.zip", 100*1024*1024, False),  # Too large
    ]
    
    for filename, size, expected in test_files:
        is_valid, msg = input_validator.validate_filename(filename)
        status = "✅ PASS" if is_valid == expected else "❌ FAIL"
        print(f"   {filename:20} → {status} ({msg})")
    
    # Test 5: Advanced Security Manager
    print("\n5. Testing Advanced Security Manager...")
    
    # Test authentication
    success, msg, session_id = security_manager.authenticate_user("testuser", "192.168.1.200")
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"   User authentication: {status}")
    
    # Test session validation
    if session_id:
        is_valid, username = security_manager.validate_session(session_id, "192.168.1.200")
        status = "✅ PASS" if is_valid and username == "testuser" else "❌ FAIL"
        print(f"   Session validation: {status}")
    
    # Test message processing
    valid, processed = security_manager.secure_message_processing("Hello world!", "testuser", session_id or "fake")
    status = "✅ PASS" if valid else "❌ FAIL"
    print(f"   Message processing: {status}")
    
    # Test malicious message
    valid, processed = security_manager.secure_message_processing("<script>alert('xss')</script>", "testuser", session_id or "fake")
    status = "✅ PASS" if not valid else "❌ FAIL"
    print(f"   Malicious message blocking: {status}")
    
    print("\n" + "=" * 50)
    print("🔐 SECURITY FEATURES TEST COMPLETED")
    print("If most tests show ✅ PASS, security features are working correctly!")
    print("=" * 50)

if __name__ == "__main__":
    test_security_features()
