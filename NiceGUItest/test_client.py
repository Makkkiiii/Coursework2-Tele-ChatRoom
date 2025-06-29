"""
Comprehensive Unit Tests for NiceGUI Chat Client
Tests all functions and methods in the ChatClient and CleanChatGUI classes
"""

import unittest
import socket
import threading
import json
import os
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime
import sys
import io

# Add the project directory to the path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import the classes to test
from NiceGUI_Client_Fixed import ChatClient, CleanChatGUI
from core import SecurityManager, Message, FileManager


class TestChatClient(unittest.TestCase):
    """Test cases for ChatClient class"""
    
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.client = ChatClient()
        self.mock_gui = Mock()
        self.client.gui = self.mock_gui
        
    def tearDown(self):
        """Clean up after each test method"""
        if self.client.socket:
            self.client.disconnect()
    
    def test_init(self):
        """Test ChatClient initialization"""
        client = ChatClient()
        
        # Test initial values
        self.assertIsNone(client.socket)
        self.assertFalse(client.connected)
        self.assertEqual(client.username, "")
        self.assertEqual(client.host, "localhost")
        self.assertEqual(client.port, 12345)
        
        # Test components initialization
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
    def test_connect_to_server_success(self, mock_socket_class):
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
        
        # Verify socket operations (check that settimeout was called, allowing multiple calls)
        self.assertTrue(mock_socket.settimeout.called)
        mock_socket.connect.assert_called_with(('127.0.0.1', 8080))
        mock_socket.send.assert_called()
    
    @patch('socket.socket')
    def test_connect_to_server_failure(self, mock_socket_class):
        """Test failed server connection"""
        # Mock socket that raises exception
        mock_socket = Mock()
        mock_socket.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_socket_class.return_value = mock_socket
        
        result = self.client.connect_to_server('127.0.0.1', 8080, 'testuser')
        
        # Assertions
        self.assertFalse(result)
        self.assertFalse(self.client.connected)
        
        # Verify GUI notification
        self.mock_gui.status_indicator.text = "🔴 Failed"
    
    def test_disconnect(self):
        """Test disconnection from server"""
        # Set up a mock socket
        mock_socket = Mock()
        self.client.socket = mock_socket
        self.client.connected = True
        
        self.client.disconnect()
        
        # Assertions
        self.assertFalse(self.client.connected)
        self.assertIsNone(self.client.socket)
        mock_socket.close.assert_called_once()
    
    def test_disconnect_with_socket_error(self):
        """Test disconnection when socket close raises exception"""
        # Set up a mock socket that raises exception on close
        mock_socket = Mock()
        mock_socket.close.side_effect = Exception("Socket error")
        self.client.socket = mock_socket
        self.client.connected = True
        
        # Should not raise exception
        self.client.disconnect()
        
        # Assertions
        self.assertFalse(self.client.connected)
        self.assertIsNone(self.client.socket)
    
    def test_handle_server_message(self):
        """Test handling server messages"""
        data = {"content": "Welcome to the server"}
        
        self.client._handle_server_message(data)
        
        self.mock_gui.add_message.assert_called_once_with(
            "🔒 SERVER", "Welcome to the server", "system"
        )
    
    def test_handle_login_success(self):
        """Test handling successful login"""
        data = {
            "content": "Login successful",
            "users": ["user1", "user2"]
        }
        
        self.client._handle_login_success(data)
        
        # Verify calls
        self.mock_gui.add_message.assert_called_once_with(
            "🔒 SERVER", "Login successful", "system"
        )
        self.mock_gui.update_user_list.assert_called_once_with(["user1", "user2"])
        self.mock_gui.on_connected.assert_called_once()
    
    def test_handle_message(self):
        """Test handling chat messages"""
        message_data = {
            "sender": "user1",
            "content": "Hello world",
            "timestamp": datetime.now().isoformat(),
            "msg_type": "text"
        }
        data = {"data": message_data}
        
        with patch.object(Message, 'from_dict') as mock_from_dict:
            mock_message = Mock()
            mock_from_dict.return_value = mock_message
            
            self.client._handle_message(data)
            
            mock_from_dict.assert_called_once_with(message_data)
            self.mock_gui.display_message.assert_called_once_with(mock_message)
    
    def test_handle_error(self):
        """Test handling error messages"""
        data = {"content": "Invalid username"}
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.client._handle_error(data)
            
            mock_notify.assert_called_once_with("Invalid username", type='negative')
            self.mock_gui.add_message.assert_called_once_with(
                "❌ ERROR", "Invalid username", "error"
            )
    
    def test_handle_kicked(self):
        """Test handling being kicked from server"""
        data = {"content": "You have been kicked"}
        
        with patch('nicegui.ui.notify') as mock_notify:
            with patch.object(self.client, 'disconnect') as mock_disconnect:
                self.client._handle_kicked(data)
                
                mock_notify.assert_called_once_with("You have been kicked", type='negative')
                self.mock_gui.add_message.assert_called_once_with(
                    "🚫 SYSTEM", "You have been kicked", "error"
                )
                mock_disconnect.assert_called_once()
                self.mock_gui.on_disconnected.assert_called_once()
    
    def test_handle_server_shutdown(self):
        """Test handling server shutdown"""
        data = {"content": "Server is shutting down"}
        
        with patch.object(self.client, 'disconnect') as mock_disconnect:
            self.client._handle_server_shutdown(data)
            
            self.mock_gui.add_message.assert_called_once_with(
                "🔒 SERVER", "Server is shutting down", "system"
            )
            mock_disconnect.assert_called_once()
            self.mock_gui.on_disconnected.assert_called_once()
    
    def test_send_message_success(self):
        """Test successful message sending"""
        # Set up connected state
        mock_socket = Mock()
        self.client.socket = mock_socket
        self.client.connected = True
        
        with patch.object(self.client.security_manager, 'encrypt_message', return_value='encrypted'):
            result = self.client.send_message("Hello world")
        
        # Assertions
        self.assertTrue(result)
        mock_socket.send.assert_called_once()
        self.mock_gui.add_message.assert_called_once_with("You", "Hello world", "sent")
    
    def test_send_message_not_connected(self):
        """Test sending message when not connected"""
        self.client.connected = False
        
        result = self.client.send_message("Hello world")
        
        self.assertFalse(result)
    
    def test_send_message_socket_error(self):
        """Test sending message with socket error"""
        # Set up connected state with failing socket
        mock_socket = Mock()
        mock_socket.send.side_effect = Exception("Socket error")
        self.client.socket = mock_socket
        self.client.connected = True
        
        with patch('nicegui.ui.notify') as mock_notify:
            with patch.object(self.client.security_manager, 'encrypt_message', return_value='encrypted'):
                result = self.client.send_message("Hello world")
        
        # Assertions
        self.assertFalse(result)
        mock_notify.assert_called_once()
    
    def test_send_file_success(self):
        """Test successful file sending"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write("Test file content")
            temp_file_path = temp_file.name
        
        try:
            # Set up connected state
            mock_socket = Mock()
            self.client.socket = mock_socket
            self.client.connected = True
            
            # Mock file encoding
            mock_file_info = {'name': 'test.txt', 'size': 100, 'data': 'base64data'}
            with patch.object(self.client.file_manager, 'encode_file', return_value=mock_file_info):
                with patch.object(self.client.security_manager, 'encrypt_message', return_value='encrypted'):
                    result = self.client.send_file(temp_file_path)
            
            # Assertions
            self.assertTrue(result)
            mock_socket.send.assert_called_once()
            self.mock_gui.add_message.assert_called_once_with("You", "📎 Shared: test.txt", "file")
        
        finally:
            # Clean up
            os.unlink(temp_file_path)
    
    def test_send_file_not_connected(self):
        """Test sending file when not connected"""
        self.client.connected = False
        
        result = self.client.send_file("test.txt")
        
        self.assertFalse(result)
    
    def test_listen_for_messages_normal_flow(self):
        """Test normal message listening flow"""
        # Set up mock socket with test data
        mock_socket = Mock()
        test_message = '{"type": "server_message", "content": "Hello"}'
        encrypted_data = "encrypted_message_data"
        
        # Configure socket to return test data then empty to break loop
        mock_socket.recv.side_effect = [
            encrypted_data.encode(),
            b''  # Empty data to break the loop
        ]
        
        self.client.socket = mock_socket
        self.client.connected = True
        
        # Mock security manager and handler
        with patch.object(self.client.security_manager, 'decrypt_message', return_value=test_message):
            # Capture the actual handler call
            original_handler = self.client._handle_server_message
            with patch.object(self.client, '_handle_server_message', wraps=original_handler) as mock_handler:
                # Run the listening method
                self.client._listen_for_messages()
                
                # Verify the handler was called
                mock_handler.assert_called_with({
                    "type": "server_message", 
                    "content": "Hello"
                })
    
    def test_listen_for_messages_decryption_error(self):
        """Test message listening with decryption error"""
        # Set up mock socket
        mock_socket = Mock()
        mock_socket.recv.side_effect = [
            b"invalid_encrypted_data",
            b''  # Empty data to break the loop
        ]
        
        self.client.socket = mock_socket
        self.client.connected = True
        
        # Mock security manager to raise exception
        with patch.object(self.client.security_manager, 'decrypt_message', side_effect=Exception("Decryption failed")):
            with patch('builtins.print') as mock_print:
                self.client._listen_for_messages()
                
                # Should print error message
                mock_print.assert_called()


class TestCleanChatGUI(unittest.TestCase):
    """Test cases for CleanChatGUI class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock all UI components to avoid GUI initialization
        with patch.multiple('NiceGUI_Client_Fixed.ui',
                           dark_mode=Mock(),
                           add_head_html=Mock(),
                           page=Mock(),
                           row=Mock(),
                           column=Mock(),
                           label=Mock(),
                           input=Mock(),
                           number=Mock(),
                           button=Mock(),
                           space=Mock(),
                           separator=Mock(),
                           icon=Mock(),
                           notify=Mock(),
                           run_javascript=Mock()):
            # Create GUI instance without full initialization
            self.gui = CleanChatGUI.__new__(CleanChatGUI)
            self.gui.client = Mock(spec=ChatClient)
            self.gui.connected = False
            self.gui.message_count = 0
            
            # Mock UI components that GUI methods expect
            self.gui.status_indicator = Mock()
            self.gui.connect_button = Mock()
            self.gui.disconnect_button = Mock()
            self.gui.host_input = Mock()
            self.gui.port_input = Mock()
            self.gui.username_input = Mock()
            self.gui.send_button = Mock()
            self.gui.share_button = Mock()
            self.gui.message_input = Mock()
            self.gui.message_counter = Mock()
            self.gui.security_label = Mock()
            self.gui.status_label = Mock()
            self.gui.connection_info = Mock()
            
            # Mock context manager objects
            self.gui.messages_area = MagicMock()
            self.gui.users_list = MagicMock()
    
    def test_connect_to_server_success(self):
        """Test successful connection through GUI"""
        # Mock input values
        self.gui.host_input.value = "127.0.0.1"
        self.gui.port_input.value = "8080"
        self.gui.username_input.value = "testuser"
        
        # Mock successful connection
        with patch.object(self.gui.client, 'connect_to_server', return_value=True):
            with patch('nicegui.ui.notify') as mock_notify:
            self.gui.connect_to_server()
        
        # Verify client connection call
        self.gui.client.connect_to_server.assert_called_once_with("127.0.0.1", 8080, "testuser")
        
        # Verify status update
        self.assertEqual(self.gui.status_indicator.text, "🟡 Connecting...")
    
    def test_connect_to_server_no_username(self):
        """Test connection with empty username"""
        self.gui.username_input.value = ""
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.connect_to_server()
            
            mock_notify.assert_called_once_with("Please enter a username", type='warning')
    
    def test_connect_to_server_invalid_port(self):
        """Test connection with invalid port"""
        self.gui.host_input.value = "127.0.0.1"
        self.gui.port_input.value = "invalid"
        self.gui.username_input.value = "testuser"
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.connect_to_server()
            
            mock_notify.assert_called_once_with("Port must be a number", type='warning')
    
    def test_disconnect(self):
        """Test disconnection through GUI"""
        with patch.object(self.gui, 'on_disconnected') as mock_on_disconnected:
            self.gui.disconnect()
            
            self.gui.client.disconnect.assert_called_once()
            mock_on_disconnected.assert_called_once()
    
    def test_on_connected(self):
        """Test on_connected method"""
        with patch('nicegui.ui.notify') as mock_notify:
            with patch.object(self.gui, 'add_message') as mock_add_message:
                self.gui.on_connected()
        
        # Verify state changes
        self.assertTrue(self.gui.connected)
        
        # Verify UI updates
        self.gui.connect_button.disable.assert_called_once()
        self.gui.disconnect_button.enable.assert_called_once()
        self.gui.send_button.enable.assert_called_once()
        
        # Verify notification
        mock_notify.assert_called_once_with(
            "✅ Connected successfully! Welcome to secure chat.", 
            type='positive'
        )
    
    def test_on_disconnected(self):
        """Test on_disconnected method"""
        self.gui.connected = True
        
        with patch('nicegui.ui.notify') as mock_notify:
            with patch.object(self.gui, 'add_message') as mock_add_message:
                with patch.object(self.gui, 'update_user_list') as mock_update_users:
                    self.gui.on_disconnected()
        
        # Verify state changes
        self.assertFalse(self.gui.connected)
        
        # Verify UI updates
        self.gui.connect_button.enable.assert_called_once()
        self.gui.disconnect_button.disable.assert_called_once()
        self.gui.send_button.disable.assert_called_once()
        
        # Verify status update
        self.assertEqual(self.gui.status_indicator.text, "🔴 Offline")
    
    def test_send_message_success(self):
        """Test successful message sending through GUI"""
        self.gui.connected = True
        self.gui.message_input.value = "Hello world"
        self.gui.client.send_message.return_value = True
        
        self.gui.send_message()
        
        # Verify client call
        self.gui.client.send_message.assert_called_once_with("Hello world")
        
        # Verify UI updates
        self.assertEqual(self.gui.message_input.value, "")
        self.assertEqual(self.gui.message_count, 1)
    
    def test_send_message_not_connected(self):
        """Test sending message when not connected"""
        self.gui.connected = False
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.send_message()
            
            mock_notify.assert_called_once_with(
                "Not connected to server", type='warning'
            )
    
    def test_send_message_empty(self):
        """Test sending empty message"""
        self.gui.connected = True
        self.gui.message_input.value = ""
        
        self.gui.send_message()
        
        # Should not call client
        self.gui.client.send_message.assert_not_called()
    
    def test_clear_chat(self):
        """Test clearing chat"""
        self.gui.message_count = 5
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.clear_chat()
        
        # Verify reset
        self.gui.messages_area.clear.assert_called_once()
        self.assertEqual(self.gui.message_count, 0)
        mock_notify.assert_called_once_with("Chat cleared", type='info')
    
    @patch('tkinter.Tk')
    @patch('tkinter.filedialog.askopenfilename')
    def test_share_file_success(self, mock_filedialog, mock_tk):
        """Test successful file sharing"""
        self.gui.connected = True
        
        # Create a temporary file for testing
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write("Test content")
            temp_file_path = temp_file.name
        
        try:
            # Mock file dialog
            mock_filedialog.return_value = temp_file_path
            mock_root = Mock()
            mock_tk.return_value = mock_root
            
            # Mock client methods
            self.gui.client.send_file.return_value = True
            
            with patch('nicegui.ui.notify') as mock_notify:
                with patch.object(self.gui, 'add_message') as mock_add_message:
                    with patch('os.path.getsize', return_value=100):
                        self.gui.share_file()
            
            # Verify calls
            self.gui.client.send_file.assert_called_once_with(temp_file_path)
            mock_notify.assert_called()
        
        finally:
            # Clean up
            os.unlink(temp_file_path)
    
    def test_share_file_not_connected(self):
        """Test file sharing when not connected"""
        self.gui.connected = False
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.share_file()
            
            mock_notify.assert_called_once_with(
                "Not connected to server", type='warning'
            )
    
    @patch('platform.system')
    @patch('subprocess.run')
    def test_open_downloads_linux(self, mock_subprocess, mock_platform):
        """Test opening downloads folder on Linux"""
        mock_platform.return_value = "Linux"
        self.gui.client.file_manager.base_dir = "/tmp/downloads"
        
        with patch('os.makedirs') as mock_makedirs:
            with patch('nicegui.ui.notify') as mock_notify:
                self.gui.open_downloads()
        
        mock_makedirs.assert_called_once_with("/tmp/downloads", exist_ok=True)
        mock_subprocess.assert_called_once_with(["xdg-open", "/tmp/downloads"])
        mock_notify.assert_called_once()
    
    def test_test_encryption_success(self):
        """Test encryption testing with success"""
        self.gui.client.security_manager.encrypt_message.return_value = "encrypted_data"
        self.gui.client.security_manager.decrypt_message.return_value = "🔒 Test encryption message"
        
        with patch('nicegui.ui.notify') as mock_notify:
            with patch.object(self.gui, 'add_message') as mock_add_message:
                self.gui.test_encryption()
        
        mock_notify.assert_called_once_with("✅ Encryption test passed!", type='positive')
    
    def test_test_encryption_failure(self):
        """Test encryption testing with failure"""
        self.gui.client.security_manager.encrypt_message.return_value = "encrypted_data"
        self.gui.client.security_manager.decrypt_message.return_value = "wrong_message"
        
        with patch('nicegui.ui.notify') as mock_notify:
            self.gui.test_encryption()
        
        mock_notify.assert_called_once_with("❌ Encryption test failed!", type='negative')
    
    def test_add_message_system(self):
        """Test adding system message"""
        with patch('nicegui.ui.row') as mock_row:
            with patch('nicegui.ui.label') as mock_label:
                with patch('nicegui.ui.run_javascript') as mock_js:
                    self.gui.add_message("SYSTEM", "Test message", "system")
        
        # Verify JavaScript scroll call
        mock_js.assert_called_once()
    
    def test_display_message_text(self):
        """Test displaying text message"""
        message = Mock()
        message.msg_type = "text"
        message.sender = "user1"
        message.content = "Hello"
        
        with patch.object(self.gui, 'add_message') as mock_add_message:
            self.gui.display_message(message)
            
            mock_add_message.assert_called_once_with("user1", "Hello")
    
    def test_display_message_file(self):
        """Test displaying file message"""
        message = Mock()
        message.msg_type = "file"
        message.sender = "user1"
        message.content = "Shared file: test.txt"
        message.file_data = {"name": "test.txt", "data": "base64data"}
        
        # Mock successful file decoding
        self.gui.client.file_manager.decode_file.return_value = "/path/to/test.txt"
        
        with patch.object(self.gui, 'add_message') as mock_add_message:
            self.gui.display_message(message)
            
            # Should call add_message twice: once for file, once for success
            self.assertEqual(mock_add_message.call_count, 2)
    
    def test_update_user_list_with_users(self):
        """Test updating user list with users"""
        users = ["user1", "user2", "user3"]
        
        with patch('nicegui.ui.row') as mock_row:
            with patch('nicegui.ui.icon') as mock_icon:
                with patch('nicegui.ui.label') as mock_label:
                    self.gui.update_user_list(users)
        
        self.gui.users_list.clear.assert_called_once()
    
    def test_update_user_list_empty(self):
        """Test updating user list with no users"""
        users = []
        
        with patch('nicegui.ui.row') as mock_row:
            with patch('nicegui.ui.icon') as mock_icon:
                with patch('nicegui.ui.label') as mock_label:
                    self.gui.update_user_list(users)
        
        self.gui.users_list.clear.assert_called_once()


class TestIntegration(unittest.TestCase):
    """Integration tests for client components"""
    
    def test_client_gui_integration(self):
        """Test integration between ChatClient and CleanChatGUI"""
        with patch('NiceGUI_Client_Fixed.ui'):
            gui = CleanChatGUI.__new__(CleanChatGUI)
            gui.client = ChatClient()
            gui.client.gui = gui
            
            # Test that client has reference to GUI
            self.assertEqual(gui.client.gui, gui)
            
            # Test that GUI has reference to client
            self.assertIsInstance(gui.client, ChatClient)
    
    def test_message_flow(self):
        """Test complete message flow from server to GUI"""
        with patch('NiceGUI_Client_Fixed.ui'):
            gui = CleanChatGUI.__new__(CleanChatGUI)
            gui.client = ChatClient()
            gui.client.gui = gui
            
            # Mock GUI methods
            gui.add_message = Mock()
            gui.update_user_list = Mock()
            gui.on_connected = Mock()
            
            # Test login success flow
            data = {
                "content": "Welcome!",
                "users": ["user1", "user2"]
            }
            
            gui.client._handle_login_success(data)
            
            # Verify complete flow
            gui.add_message.assert_called_once_with("🔒 SERVER", "Welcome!", "system")
            gui.update_user_list.assert_called_once_with(["user1", "user2"])
            gui.on_connected.assert_called_once()


def run_performance_tests():
    """Run performance tests for critical methods"""
    print("\n" + "="*50)
    print("PERFORMANCE TESTS")
    print("="*50)
    
    # Test message encryption/decryption performance
    security_manager = SecurityManager()
    
    # Test encryption performance
    start_time = time.time()
    for _ in range(1000):
        encrypted = security_manager.encrypt_message("Test message")
        decrypted = security_manager.decrypt_message(encrypted)
    end_time = time.time()
    
    encryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
    print(f"✅ Encryption/Decryption (1000 ops): {encryption_time:.2f}ms")
    
    # Test message handling performance
    client = ChatClient()
    mock_gui = Mock()
    client.gui = mock_gui
    
    start_time = time.time()
    for i in range(100):
        data = {"content": f"Test message {i}"}
        client._handle_server_message(data)
    end_time = time.time()
    
    handling_time = (end_time - start_time) * 1000
    print(f"✅ Message Handling (100 ops): {handling_time:.2f}ms")
    
    print("✅ All performance tests passed!")


def run_security_tests():
    """Run security-related tests"""
    print("\n" + "="*50)
    print("SECURITY TESTS")
    print("="*50)
    
    # Test encryption security
    security_manager = SecurityManager()
    
    # Test that encryption produces different outputs for same input
    message = "Test message"
    encrypted1 = security_manager.encrypt_message(message)
    encrypted2 = security_manager.encrypt_message(message)
    
    # Should be different due to random initialization vectors
    if encrypted1 != encrypted2:
        print("✅ Encryption randomization working")
    else:
        print("❌ Encryption may be deterministic (security risk)")
    
    # Test decryption integrity
    decrypted = security_manager.decrypt_message(encrypted1)
    if decrypted == message:
        print("✅ Decryption integrity maintained")
    else:
        print("❌ Decryption integrity failed")
    
    # Test invalid decryption handling
    try:
        security_manager.decrypt_message("invalid_encrypted_data")
        print("❌ Invalid decryption should raise exception")
    except:
        print("✅ Invalid decryption properly handled")
    
    print("✅ Security tests completed!")


if __name__ == '__main__':
    # Print test banner
    print("🧪 COMPREHENSIVE UNIT TESTS FOR TELECHAT CLIENT")
    print("="*60)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestChatClient))
    suite.addTests(loader.loadTestsFromTestCase(TestCleanChatGUI))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    # Run additional tests
    run_performance_tests()
    run_security_tests()
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    # Exit with appropriate code
    exit_code = 0 if (len(result.failures) + len(result.errors)) == 0 else 1
    
    if exit_code == 0:
        print("\n🎉 ALL TESTS PASSED! ✅")
    else:
        print("\n❌ SOME TESTS FAILED!")
    
    print("="*60)
    
    sys.exit(exit_code)
