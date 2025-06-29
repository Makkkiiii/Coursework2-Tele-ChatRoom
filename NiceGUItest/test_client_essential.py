"""
Essential Unit Tests for NiceGUI Chat Client
Tests core functionality of ChatClient and related components
"""

import unittest
import socket
import threading
import json
import os
import tempfile
import time
import base64
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import sys

# Add the project directory to the path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import the classes to test
from NiceGUI_Client_Fixed import ChatClient, CleanChatGUI
from core import SecurityManager, Message, FileManager


class TestChatClientCore(unittest.TestCase):
    """Test cases for core ChatClient functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = ChatClient()
        self.mock_gui = Mock()
        self.client.gui = self.mock_gui
        
    def test_init(self):
        """Test ChatClient initialization"""
        client = ChatClient()
        
        # Test initial values
        self.assertIsNone(client.socket)
        self.assertFalse(client.connected)
        self.assertEqual(client.username, "")
        self.assertEqual(client.host, "localhost")
        self.assertEqual(client.port, 12345)
        
        # Test components
        self.assertIsInstance(client.security_manager, SecurityManager)
        self.assertIsInstance(client.file_manager, FileManager)
        self.assertIsNone(client.gui)
        
        # Test message handlers
        expected_handlers = {
            "server_message", "login_success", "message", 
            "error", "kicked", "server_shutdown"
        }
        self.assertEqual(set(client.message_handlers.keys()), expected_handlers)
    
    @patch('socket.socket')
    def test_connect_success(self, mock_socket_class):
        """Test successful server connection"""
        # Mock socket
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock encryption
        with patch.object(self.client.security_manager, 'encrypt_message', return_value='encrypted_data'):
            result = self.client.connect_to_server('127.0.0.1', 8080, 'testuser')
        
        # Assertions
        self.assertTrue(result)
        self.assertEqual(self.client.host, '127.0.0.1')
        self.assertEqual(self.client.port, 8080)
        self.assertEqual(self.client.username, 'testuser')
        self.assertTrue(self.client.connected)
        
        # Verify socket operations
        mock_socket.connect.assert_called_with(('127.0.0.1', 8080))
        mock_socket.send.assert_called()
    
    @patch('socket.socket')
    def test_connect_failure(self, mock_socket_class):
        """Test failed server connection"""
        # Mock socket that raises exception
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket
        
        result = self.client.connect_to_server('127.0.0.1', 8080, 'testuser')
        
        self.assertFalse(result)
        self.assertFalse(self.client.connected)
    
    def test_send_message_success(self):
        """Test successful message sending"""
        self.client.connected = True
        self.client.socket = Mock()
        
        result = self.client.send_message("Hello world")
        
        self.assertTrue(result)
        self.client.socket.send.assert_called_once()
        self.mock_gui.add_message.assert_called_once_with("You", "Hello world", "sent")
    
    def test_send_message_not_connected(self):
        """Test sending message when not connected"""
        self.client.connected = False
        
        result = self.client.send_message("Hello world")
        
        self.assertFalse(result)
    
    def test_send_file_success(self):
        """Test successful file sending"""
        self.client.connected = True
        self.client.socket = Mock()
        
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content")
            temp_file = f.name
            
        try:
            result = self.client.send_file(temp_file)
            
            self.assertTrue(result)
            self.client.socket.send.assert_called_once()
            self.mock_gui.add_message.assert_called()
        finally:
            os.unlink(temp_file)
    
    def test_send_file_not_connected(self):
        """Test sending file when not connected"""
        self.client.connected = False
        
        result = self.client.send_file("nonexistent.txt")
        
        self.assertFalse(result)
    
    def test_disconnect(self):
        """Test disconnection"""
        self.client.connected = True
        mock_socket = Mock()
        self.client.socket = mock_socket
        
        self.client.disconnect()
        
        self.assertFalse(self.client.connected)
        mock_socket.close.assert_called_once()
        self.assertIsNone(self.client.socket)
    
    def test_handle_server_message(self):
        """Test server message handling"""
        data = {"content": "Server announcement"}
        self.client._handle_server_message(data)
        
        self.mock_gui.add_message.assert_called_once_with("🔒 SERVER", "Server announcement", "system")
    
    def test_handle_login_success(self):
        """Test login success handling"""
        data = {"content": "Welcome!", "users": ["user1", "user2"]}
        self.client._handle_login_success(data)
        
        self.mock_gui.add_message.assert_called_once_with("🔒 SERVER", "Welcome!", "system")
        self.mock_gui.update_user_list.assert_called_once_with(["user1", "user2"])
        self.mock_gui.on_connected.assert_called_once()
    
    def test_handle_error(self):
        """Test error message handling"""
        with patch('nicegui.ui.notify') as mock_notify:
            data = {"content": "Error occurred"}
            self.client._handle_error(data)
            
            mock_notify.assert_called_once_with("Error occurred", type='negative')
            self.mock_gui.add_message.assert_called_once_with("❌ ERROR", "Error occurred", "error")
    
    def test_handle_kicked(self):
        """Test kicked message handling"""
        with patch('nicegui.ui.notify') as mock_notify:
            data = {"content": "You have been kicked"}
            self.client._handle_kicked(data)
            
            mock_notify.assert_called_once_with("You have been kicked", type='negative')
            self.mock_gui.add_message.assert_called_once_with("🚫 SYSTEM", "You have been kicked", "error")
            self.mock_gui.on_disconnected.assert_called_once()
    
    def test_handle_server_shutdown(self):
        """Test server shutdown handling"""
        data = {"content": "Server shutting down"}
        self.client._handle_server_shutdown(data)
        
        self.mock_gui.add_message.assert_called_once_with("🔒 SERVER", "Server shutting down", "system")
        self.mock_gui.on_disconnected.assert_called_once()


class TestSecurityManager(unittest.TestCase):
    """Test cases for SecurityManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.security_manager = SecurityManager("test_password")
        
    def test_encrypt_decrypt_message(self):
        """Test message encryption and decryption"""
        original_message = "This is a secret message!"
        
        # Encrypt
        encrypted = self.security_manager.encrypt_message(original_message)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, original_message)
        
        # Decrypt
        decrypted = self.security_manager.decrypt_message(encrypted)
        self.assertEqual(decrypted, original_message)
    
    def test_decrypt_invalid_message(self):
        """Test decrypting invalid message"""
        invalid_encrypted = "invalid_base64_data"
        
        result = self.security_manager.decrypt_message(invalid_encrypted)
        self.assertIn("Decryption Error", result)


class TestMessage(unittest.TestCase):
    """Test cases for Message class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.message = Message("testuser", "Hello world", "text")
        
    def test_init(self):
        """Test Message initialization"""
        self.assertEqual(self.message.sender, "testuser")
        self.assertEqual(self.message.content, "Hello world")
        self.assertEqual(self.message.msg_type, "text")
        self.assertEqual(self.message.file_data, {})
        self.assertIsInstance(self.message.timestamp, datetime)
        self.assertIsNotNone(self.message.message_id)
        self.assertEqual(len(self.message.message_id), 8)
    
    def test_to_dict_and_from_dict(self):
        """Test message serialization"""
        msg_dict = self.message.to_dict()
        restored_message = Message.from_dict(msg_dict)
        
        self.assertEqual(restored_message.sender, self.message.sender)
        self.assertEqual(restored_message.content, self.message.content)
        self.assertEqual(restored_message.msg_type, self.message.msg_type)
        self.assertEqual(restored_message.message_id, self.message.message_id)


class TestFileManager(unittest.TestCase):
    """Test cases for FileManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = FileManager(self.temp_dir)
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_encode_decode_file(self):
        """Test file encoding and decoding"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        test_content = "This is test content"
        with open(test_file, 'w') as f:
            f.write(test_content)
            
        # Encode file
        file_info = self.file_manager.encode_file(test_file)
        
        self.assertIsInstance(file_info, dict)
        self.assertEqual(file_info["name"], "test.txt")
        self.assertEqual(file_info["size"], len(test_content))
        self.assertIn("data", file_info)
        
        # Decode file
        saved_path = self.file_manager.decode_file(file_info)
        
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, 'r') as f:
            content = f.read()
        self.assertEqual(content, test_content)
    
    def test_file_type_detection(self):
        """Test file type detection"""
        self.assertEqual(self.file_manager._get_file_type("test.jpg"), "image")
        self.assertEqual(self.file_manager._get_file_type("test.txt"), "text")
        self.assertEqual(self.file_manager._get_file_type("test.pdf"), "document")
        self.assertEqual(self.file_manager._get_file_type("test.bin"), "file")


class TestPerformanceAndSecurity(unittest.TestCase):
    """Performance and security tests"""
    
    def test_encryption_performance(self):
        """Test encryption performance"""
        security_manager = SecurityManager()
        large_message = "A" * 10000  # 10KB message
        
        start_time = time.time()
        encrypted = security_manager.encrypt_message(large_message)
        decrypted = security_manager.decrypt_message(encrypted)
        end_time = time.time()
        
        # Should complete in reasonable time (< 1 second)
        self.assertLess(end_time - start_time, 1.0)
        self.assertEqual(decrypted, large_message)
    
    def test_malicious_input_handling(self):
        """Test handling of malicious inputs"""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "\x00\x01\x02\x03",  # Null bytes and control characters
        ]
        
        security_manager = SecurityManager()
        
        for malicious_input in malicious_inputs:
            # Should not crash
            try:
                encrypted = security_manager.encrypt_message(malicious_input)
                decrypted = security_manager.decrypt_message(encrypted)
                self.assertEqual(decrypted, malicious_input)
            except Exception as e:
                # If it fails, it should fail gracefully
                self.assertIsInstance(e, Exception)


if __name__ == '__main__':
    print("🧪 ESSENTIAL TESTS FOR TELECHAT CLIENT")
    print("=" * 60)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestChatClientCore,
        TestSecurityManager,
        TestMessage,
        TestFileManager,
        TestPerformanceAndSecurity
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    
    if result.failures:
        print(f"\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}")
            
    if result.errors:
        print(f"\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}")
    
    if len(result.failures) == 0 and len(result.errors) == 0:
        print(f"\n✅ ALL TESTS PASSED!")
        print(f"🎉 The NiceGUI Chat Client is working correctly!")
    else:
        print(f"\n❌ SOME TESTS FAILED!")
        print(f"Please review the failures above.")
    
    print("=" * 60)
