"""
Test Script for Advanced Chat Application
Tests all core components and data structures
"""

import sys
import os
import unittest
from datetime import datetime
import tempfile
import threading
import time

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from chat_core import (
    SecurityManager, Message, MessageQueue, UserManager,
    FileManager, ChatHistory
)


class TestSecurityManager(unittest.TestCase):
    """Test encryption and decryption functionality"""
    
    def setUp(self):
        self.security_manager = SecurityManager("test_password")
    
    def test_encryption_decryption(self):
        """Test message encryption and decryption"""
        original_message = "Hello, this is a test message with special chars: !@#$%^&*()"
        
        # Encrypt message
        encrypted = self.security_manager.encrypt_message(original_message)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, original_message)
        
        # Decrypt message
        decrypted = self.security_manager.decrypt_message(encrypted)
        self.assertEqual(decrypted, original_message)
    
    def test_encryption_with_unicode(self):
        """Test encryption with unicode characters"""
        unicode_message = "测试消息 🚀 émojis and ñoñó characters"
        
        encrypted = self.security_manager.encrypt_message(unicode_message)
        decrypted = self.security_manager.decrypt_message(encrypted)
        
        self.assertEqual(decrypted, unicode_message)
    
    def test_invalid_decryption(self):
        """Test decryption of invalid data"""
        invalid_data = "invalid_encrypted_data"
        result = self.security_manager.decrypt_message(invalid_data)
        self.assertTrue(result.startswith("[Decryption Error"))


class TestMessage(unittest.TestCase):
    """Test Message class functionality"""
    
    def test_message_creation(self):
        """Test basic message creation"""
        msg = Message("TestUser", "Test content", "text")
        
        self.assertEqual(msg.sender, "TestUser")
        self.assertEqual(msg.content, "Test content")
        self.assertEqual(msg.msg_type, "text")
        self.assertIsInstance(msg.timestamp, datetime)
        self.assertIsInstance(msg.message_id, str)
    
    def test_message_serialization(self):
        """Test message to/from dictionary conversion"""
        original_msg = Message(
            "TestUser", 
            "Test content", 
            "file",
            {"name": "test.txt", "size": 100}
        )
        
        # Convert to dictionary
        msg_dict = original_msg.to_dict()
        self.assertIsInstance(msg_dict, dict)
        self.assertEqual(msg_dict["sender"], "TestUser")
        self.assertEqual(msg_dict["content"], "Test content")
        
        # Convert back from dictionary
        restored_msg = Message.from_dict(msg_dict)
        self.assertEqual(restored_msg.sender, original_msg.sender)
        self.assertEqual(restored_msg.content, original_msg.content)
        self.assertEqual(restored_msg.msg_type, original_msg.msg_type)
        self.assertEqual(restored_msg.message_id, original_msg.message_id)


class TestMessageQueue(unittest.TestCase):
    """Test MessageQueue data structure"""
    
    def setUp(self):
        self.queue = MessageQueue()
    
    def test_queue_operations(self):
        """Test basic queue operations"""
        # Test empty queue
        self.assertTrue(self.queue.empty())
        
        # Add messages
        msg1 = Message("User1", "Message 1")
        msg2 = Message("User2", "Message 2")
        
        self.queue.put(msg1)
        self.queue.put(msg2)
        
        self.assertFalse(self.queue.empty())
        
        # Get messages (FIFO)
        retrieved_msg1 = self.queue.get(timeout=1.0)
        self.assertEqual(retrieved_msg1.content, "Message 1")
        
        retrieved_msg2 = self.queue.get(timeout=1.0)
        self.assertEqual(retrieved_msg2.content, "Message 2")
        
        self.assertTrue(self.queue.empty())
    
    def test_queue_thread_safety(self):
        """Test queue thread safety"""
        messages_sent = []
        messages_received = []
        
        def producer():
            for i in range(10):
                msg = Message(f"User{i}", f"Message {i}")
                messages_sent.append(msg.content)
                self.queue.put(msg)
                time.sleep(0.01)
        
        def consumer():
            for _ in range(10):
                try:
                    msg = self.queue.get(timeout=2.0)
                    messages_received.append(msg.content)
                except:
                    break
        
        # Start threads
        producer_thread = threading.Thread(target=producer)
        consumer_thread = threading.Thread(target=consumer)
        
        producer_thread.start()
        consumer_thread.start()
        
        producer_thread.join()
        consumer_thread.join()
        
        # Verify all messages were processed
        self.assertEqual(len(messages_sent), 10)
        self.assertEqual(len(messages_received), 10)
        self.assertEqual(set(messages_sent), set(messages_received))


class TestUserManager(unittest.TestCase):
    """Test UserManager functionality"""
    
    def setUp(self):
        self.user_manager = UserManager()
    
    def test_user_operations(self):
        """Test basic user operations"""
        # Mock socket
        class MockSocket:
            pass
        
        mock_socket = MockSocket()
        
        # Add user
        self.assertTrue(self.user_manager.add_user("TestUser", mock_socket)) # type: ignore
        self.assertTrue(self.user_manager.user_exists("TestUser"))
        self.assertIn("TestUser", self.user_manager.get_users())
        
        # Try to add duplicate user
        self.assertFalse(self.user_manager.add_user("TestUser", mock_socket)) # type: ignore
        
        # Get user socket
        retrieved_socket = self.user_manager.get_user_socket("TestUser")
        self.assertEqual(retrieved_socket, mock_socket)
        
        # Remove user
        self.user_manager.remove_user("TestUser")
        self.assertFalse(self.user_manager.user_exists("TestUser"))
        self.assertNotIn("TestUser", self.user_manager.get_users())
    
    def test_thread_safety(self):
        """Test user manager thread safety"""
        class MockSocket:
            def __init__(self, name):
                self.name = name
        
        def add_users(start_id, count):
            for i in range(start_id, start_id + count):
                username = f"User{i}"
                socket = MockSocket(username)
                self.user_manager.add_user(username, socket) # type: ignore
        
        # Add users from multiple threads
        threads = []
        for i in range(0, 50, 10):
            thread = threading.Thread(target=add_users, args=(i, 10))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all users were added
        users = self.user_manager.get_users()
        self.assertEqual(len(users), 50)


class TestFileManager(unittest.TestCase):
    """Test FileManager functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = FileManager(self.temp_dir)
    
    def test_file_encoding_decoding(self):
        """Test file encoding and decoding"""
        # Create test file
        test_content = b"This is test file content with binary data \x00\x01\x02"
        test_file_path = os.path.join(self.temp_dir, "test_file.txt")
        
        with open(test_file_path, 'wb') as f:
            f.write(test_content)
        
        # Encode file
        file_info = self.file_manager.encode_file(test_file_path)
        
        self.assertIsInstance(file_info, dict)
        self.assertEqual(file_info["name"], "test_file.txt")
        self.assertEqual(file_info["size"], len(test_content))
        self.assertIn("data", file_info)
        self.assertIn("type", file_info)
        
        # Decode file
        decoded_path = self.file_manager.decode_file(file_info)
        self.assertTrue(os.path.exists(decoded_path))
        
        # Verify content
        with open(decoded_path, 'rb') as f:
            decoded_content = f.read()
        
        self.assertEqual(decoded_content, test_content)
    
    def test_file_type_detection(self):
        """Test file type detection"""
        test_files = {
            "image.jpg": "image",
            "document.pdf": "document",
            "script.py": "text",
            "archive.zip": "file"
        }
        
        for filename, expected_type in test_files.items():
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write("test content")
            
            detected_type = self.file_manager._get_file_type(file_path)
            self.assertEqual(detected_type, expected_type)
    
    def test_large_file_rejection(self):
        """Test rejection of files that are too large"""
        # Create a file larger than the limit
        large_file_path = os.path.join(self.temp_dir, "large_file.txt")
        large_content = b"x" * (self.file_manager.max_file_size + 1)
        
        with open(large_file_path, 'wb') as f:
            f.write(large_content)
        
        # Should raise an exception
        with self.assertRaises(Exception) as context:
            self.file_manager.encode_file(large_file_path)
        
        self.assertIn("File too large", str(context.exception))


class TestChatHistory(unittest.TestCase):
    """Test ChatHistory data structure"""
    
    def setUp(self):
        self.chat_history = ChatHistory(max_messages=100)
    
    def test_message_storage(self):
        """Test message storage and retrieval"""
        # Add messages
        messages = []
        for i in range(10):
            msg = Message(f"User{i}", f"Message {i}")
            messages.append(msg)
            self.chat_history.add_message(msg)
        
        # Get all messages
        retrieved = self.chat_history.get_messages()
        self.assertEqual(len(retrieved), 10)
        
        # Get limited messages
        limited = self.chat_history.get_messages(limit=5)
        self.assertEqual(len(limited), 5)
        
        # Verify order (most recent last)
        self.assertEqual(limited[-1].content, "Message 9")
    
    def test_message_search(self):
        """Test message search functionality"""
        # Add test messages
        messages = [
            Message("Alice", "Hello everyone!"),
            Message("Bob", "How are you doing?"),
            Message("Alice", "I'm working on Python project"),
            Message("Charlie", "Python is awesome"),
            Message("Bob", "See you later")
        ]
        
        for msg in messages:
            self.chat_history.add_message(msg)
        
        # Search by content
        python_msgs = self.chat_history.search_messages("Python")
        self.assertEqual(len(python_msgs), 2)
        
        # Search by sender
        alice_msgs = self.chat_history.search_messages("Alice")
        self.assertEqual(len(alice_msgs), 2)
        
        # Case insensitive search
        hello_msgs = self.chat_history.search_messages("hello")
        self.assertEqual(len(hello_msgs), 1)
    
    def test_user_messages(self):
        """Test getting messages from specific user"""
        # Add messages from different users
        for i in range(5):
            msg1 = Message("Alice", f"Alice message {i}")
            msg2 = Message("Bob", f"Bob message {i}")
            self.chat_history.add_message(msg1)
            self.chat_history.add_message(msg2)
        
        # Get Alice's messages
        alice_msgs = self.chat_history.get_user_messages("Alice")
        self.assertEqual(len(alice_msgs), 5)
        for msg in alice_msgs:
            self.assertEqual(msg.sender, "Alice")
        
        # Get Bob's messages
        bob_msgs = self.chat_history.get_user_messages("Bob")
        self.assertEqual(len(bob_msgs), 5)
        for msg in bob_msgs:
            self.assertEqual(msg.sender, "Bob")
    
    def test_message_limit(self):
        """Test message limit functionality"""
        history = ChatHistory(max_messages=5)
        
        # Add more messages than the limit
        for i in range(10):
            msg = Message(f"User{i}", f"Message {i}")
            history.add_message(msg)
        
        # Should only keep the most recent 5 messages
        messages = history.get_messages()
        self.assertEqual(len(messages), 5)
        self.assertEqual(messages[0].content, "Message 5")
        self.assertEqual(messages[-1].content, "Message 9")
    
    def test_clear_history(self):
        """Test clearing chat history"""
        # Add some messages
        for i in range(5):
            msg = Message(f"User{i}", f"Message {i}")
            self.chat_history.add_message(msg)
        
        self.assertEqual(len(self.chat_history.get_messages()), 5)
        
        # Clear history
        self.chat_history.clear_history()
        self.assertEqual(len(self.chat_history.get_messages()), 0)


def run_all_tests():
    """Run all tests and display results"""
    print("=" * 60)
    print("ADVANCED CHAT APPLICATION - COMPONENT TESTING")
    print("=" * 60)
    print()
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestSecurityManager,
        TestMessage,
        TestMessageQueue,
        TestUserManager,
        TestFileManager,
        TestChatHistory
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
    
    print("\n" + "=" * 60)
    
    if result.wasSuccessful():
        print("🎉 ALL TESTS PASSED! The chat application components are working correctly.")
    else:
        print("❌ Some tests failed. Please check the implementation.")
    
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    # Test individual components
    success = run_all_tests()
    
    if success:
        print("\n✅ Core components tested successfully!")
        print("🚀 You can now run the chat application:")

    else:
        print("\n❌ Some tests failed. Please check the implementation before running the application.")
    
    input("\nPress Enter to exit...")
