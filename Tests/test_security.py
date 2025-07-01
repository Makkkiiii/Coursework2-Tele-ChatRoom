"""
Test Security Module - Enhanced Authentication and Encryption Testing
Author: Programming & Algorithm 2 - Coursework - Test Environment
"""

import hashlib
import base64
import secrets
from test_core import SecurityManager, AuthenticationManager
import socket


class TestSecuritySuite:
    """Comprehensive security testing suite with authentication"""
    
    def __init__(self):
        self.test_results = {}
        self.server_password = "TestServer2025!"
        self.security_manager = SecurityManager(self.server_password)
        self.auth_manager = AuthenticationManager(self.security_manager)
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("RUNNING ENHANCED SECURITY TESTS WITH AUTHENTICATION")
        print("=" * 60)
        
        self.test_password_authentication()
        self.test_encryption_strength()
        self.test_brute_force_resistance()
        self.test_session_management()
        self.test_message_integrity()
        self.test_salt_validation()
        self.test_authentication_manager()
        
        self.print_results()
    
    def test_password_authentication(self):
        """Test password authentication mechanism"""
        print("\n1. Testing Password Authentication...")
        
        # Test correct password
        correct_result = self.security_manager.verify_password(self.server_password)
        
        # Test wrong passwords
        wrong_passwords = [
            "wrongpassword",
            "TestServer2024!",  # Close but wrong
            "",                 # Empty
            "testserver2025!",  # Wrong case
            "TestServer2025",   # Missing special char
        ]
        
        wrong_results = [self.security_manager.verify_password(pwd) for pwd in wrong_passwords]
        
        # Test case sensitivity
        case_test = self.security_manager.verify_password("testserver2025!")
        
        success = correct_result and not any(wrong_results) and not case_test
        self.test_results["Password Authentication"] = success
        
        print(f"   ✓ Correct password accepted: {correct_result}")
        print(f"   ✓ Wrong passwords rejected: {not any(wrong_results)}")
        print(f"   ✓ Case sensitivity working: {not case_test}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_encryption_strength(self):
        """Test encryption strength and consistency"""
        print("\n2. Testing Encryption Strength...")
        
        test_messages = [
            "Simple message",
            "Message with special chars: !@#$%^&*()",
            "Very long message " * 100,
            "Unicode test: 你好世界 🌍",
            ""  # Empty message
        ]
        
        all_passed = True
        for msg in test_messages:
            try:
                encrypted = self.security_manager.encrypt_message(msg)
                decrypted = self.security_manager.decrypt_message(encrypted)
                
                # Test that encryption produces different results each time
                encrypted2 = self.security_manager.encrypt_message(msg)
                different_ciphertext = encrypted != encrypted2 if msg else True
                
                passed = (decrypted == msg) and different_ciphertext
                all_passed &= passed
                
                print(f"   ✓ '{msg[:20]}{'...' if len(msg) > 20 else ''}': {'PASS' if passed else 'FAIL'}")
            except Exception as e:
                print(f"   ✗ Error with '{msg[:20]}': {e}")
                all_passed = False
        
        self.test_results["Encryption Strength"] = all_passed
        print(f"   Result: {'PASS' if all_passed else 'FAIL'}")
    
    def test_brute_force_resistance(self):
        """Test resistance to brute force attacks"""
        print("\n3. Testing Brute Force Resistance...")
        
        import time
        
        # Test common passwords
        common_passwords = [
            "password", "123456", "admin", "root", "guest",
            "password123", "qwerty", "abc123", "test", "user"
        ]
        
        start_time = time.time()
        failed_attempts = 0
        
        for pwd in common_passwords:
            if not self.security_manager.verify_password(pwd):
                failed_attempts += 1
        
        end_time = time.time()
        time_taken = end_time - start_time
        
        # Each verification should take reasonable time due to PBKDF2
        reasonable_time = time_taken > 0.1  # Should take more than 0.1 seconds for 10 attempts
        all_rejected = failed_attempts == len(common_passwords)
        
        success = all_rejected and reasonable_time
        self.test_results["Brute Force Resistance"] = success
        
        print(f"   ✓ Common passwords rejected: {failed_attempts}/{len(common_passwords)}")
        print(f"   ✓ Time taken: {time_taken:.3f}s (should be > 0.1s)")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_session_management(self):
        """Test authentication session management"""
        print("\n4. Testing Session Management...")
        
        # Create mock sockets that inherit from object (compatible with set operations)
        class MockSocket:
            def __init__(self, socket_id):
                self.id = socket_id
        
        mock_socket1 = MockSocket(1)
        mock_socket2 = MockSocket(2)
        
        # Test authentication
        auth1 = self.auth_manager.authenticate_client(mock_socket1, self.server_password)
        auth2 = self.auth_manager.authenticate_client(mock_socket2, "wrong_password")
        
        # Test session checking
        is_auth1 = self.auth_manager.is_authenticated(mock_socket1)
        is_auth2 = self.auth_manager.is_authenticated(mock_socket2)
        
        # Test logout
        self.auth_manager.logout_client(mock_socket1)
        is_auth1_after_logout = self.auth_manager.is_authenticated(mock_socket1)
        
        success = auth1 and not auth2 and is_auth1 and not is_auth2 and not is_auth1_after_logout
        self.test_results["Session Management"] = success
        
        print(f"   ✓ Correct password authentication: {auth1}")
        print(f"   ✓ Wrong password rejection: {not auth2}")
        print(f"   ✓ Session tracking: {is_auth1 and not is_auth2}")
        print(f"   ✓ Logout functionality: {not is_auth1_after_logout}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_message_integrity(self):
        """Test message integrity and tampering detection"""
        print("\n5. Testing Message Integrity...")
        
        original_message = "Important secure message"
        encrypted = self.security_manager.encrypt_message(original_message)
        
        # Test normal decryption
        decrypted = self.security_manager.decrypt_message(encrypted)
        normal_success = decrypted == original_message
        
        # Test tampering detection by modifying encrypted data
        tampered_encrypted = encrypted[:-5] + "XXXXX"  # Modify last 5 characters
        tampered_result = self.security_manager.decrypt_message(tampered_encrypted)
        tampering_detected = "[Decryption Error:" in tampered_result
        
        # Test with completely invalid data
        invalid_result = self.security_manager.decrypt_message("invalid_base64_data!")
        invalid_detected = "[Decryption Error:" in invalid_result
        
        success = normal_success and tampering_detected and invalid_detected
        self.test_results["Message Integrity"] = success
        
        print(f"   ✓ Normal decryption: {normal_success}")
        print(f"   ✓ Tampering detection: {tampering_detected}")
        print(f"   ✓ Invalid data handling: {invalid_detected}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_salt_validation(self):
        """Test salt implementation and consistency"""
        print("\n6. Testing Salt Implementation...")
        
        # Create two SecurityManager instances with same password
        sm1 = SecurityManager(self.server_password)
        sm2 = SecurityManager(self.server_password)
        
        # They should produce same auth hashes (same salt)
        same_auth_hash = sm1.auth_hash == sm2.auth_hash
        
        # They should be able to decrypt each other's messages
        test_msg = "Cross-instance test"
        encrypted_by_sm1 = sm1.encrypt_message(test_msg)
        decrypted_by_sm2 = sm2.decrypt_message(encrypted_by_sm1)
        cross_decrypt = decrypted_by_sm2 == test_msg
        
        # Different passwords should produce different hashes
        sm3 = SecurityManager("different_password")
        different_auth_hash = sm1.auth_hash != sm3.auth_hash
        
        success = same_auth_hash and cross_decrypt and different_auth_hash
        self.test_results["Salt Implementation"] = success
        
        print(f"   ✓ Consistent auth hashes: {same_auth_hash}")
        print(f"   ✓ Cross-instance decryption: {cross_decrypt}")
        print(f"   ✓ Different passwords produce different hashes: {different_auth_hash}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_authentication_manager(self):
        """Test comprehensive authentication manager functionality"""
        print("\n7. Testing Authentication Manager...")
        
        # Test multiple client authentication
        clients = []
        for i in range(3):
            client = type('MockSocket', (), {'id': i})()
            clients.append(client)
        
        # Authenticate 2 clients correctly, 1 incorrectly
        auth_results = [
            self.auth_manager.authenticate_client(clients[0], self.server_password),
            self.auth_manager.authenticate_client(clients[1], self.server_password),
            self.auth_manager.authenticate_client(clients[2], "wrong_password")
        ]
        
        # Check counts
        expected_count = 2  # Only 2 should be authenticated
        actual_count = self.auth_manager.get_authenticated_count()
        
        # Test bulk logout
        self.auth_manager.logout_client(clients[0])
        count_after_logout = self.auth_manager.get_authenticated_count()
        
        success = (auth_results[0] and auth_results[1] and not auth_results[2] and 
                  actual_count == expected_count and count_after_logout == expected_count - 1)
        
        self.test_results["Authentication Manager"] = success
        
        print(f"   ✓ Multiple client auth: {auth_results[0] and auth_results[1]}")
        print(f"   ✓ Wrong password rejection: {not auth_results[2]}")
        print(f"   ✓ Correct count tracking: {actual_count == expected_count}")
        print(f"   ✓ Logout count update: {count_after_logout == expected_count - 1}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def print_results(self):
        """Print comprehensive test results"""
        print("\n" + "=" * 60)
        print("ENHANCED SECURITY TEST RESULTS")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results.values() if result)
        total = len(self.test_results)
        
        for test_name, result in self.test_results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{test_name:<30} {status}")
        
        print("-" * 60)
        print(f"Total: {passed}/{total} tests passed")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 ALL SECURITY TESTS PASSED! System is secure for deployment.")
        else:
            print("⚠️  Some tests failed. Review security implementation.")
        
        print("=" * 60)


if __name__ == "__main__":
    # Run comprehensive security tests
    test_suite = TestSecuritySuite()
    test_suite.run_all_tests()
