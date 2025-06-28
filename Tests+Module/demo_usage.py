"""
Advanced Chat Application - Usage Examples
This file demonstrates how to use the core components programmatically
"""

from chat_core import SecurityManager, Message, MessageQueue, UserManager, FileManager, ChatHistory
from datetime import datetime
import os

def demo_encryption():
    """Demonstrate encryption functionality"""
    print("🔐 ENCRYPTION DEMO")
    print("-" * 40)
    
    # Create security manager
    security = SecurityManager("my_secret_password")
    
    # Encrypt some messages
    messages = [
        "Hello, this is a secure message!",
        "File transfer: document.pdf",
        "User Alice joined the chat",
        "Special characters: !@#$%^&*()_+ 🚀"
    ]
    
    for msg in messages:
        encrypted = security.encrypt_message(msg)
        decrypted = security.decrypt_message(encrypted)
        
        print(f"Original:  {msg}")
        print(f"Encrypted: {encrypted[:50]}...")
        print(f"Decrypted: {decrypted}")
        print(f"✅ Match: {msg == decrypted}")
        print()

def demo_message_system():
    """Demonstrate message creation and queue operations"""
    print("💬 MESSAGE SYSTEM DEMO")
    print("-" * 40)
    
    # Create message queue
    queue = MessageQueue()
    
    # Create different types of messages
    text_msg = Message("Alice", "Hello everyone!", "text")
    file_msg = Message("Bob", "Sharing document", "file", {"name": "doc.pdf", "size": 1024})
    system_msg = Message("System", "Server started", "system")
    
    # Add to queue
    for msg in [text_msg, file_msg, system_msg]:
        queue.put(msg)
        print(f"✅ Added: [{msg.msg_type}] {msg.sender}: {msg.content}")
    
    print(f"📊 Queue empty: {queue.empty()}")
    
    # Process queue
    print("\n📤 Processing messages:")
    while not queue.empty():
        msg = queue.get()
        print(f"📨 [{msg.timestamp.strftime('%H:%M:%S')}] {msg.sender}: {msg.content}")
    
    print(f"📊 Queue empty after processing: {queue.empty()}")

def demo_user_management():
    """Demonstrate user management"""
    print("\n👥 USER MANAGEMENT DEMO")
    print("-" * 40)
    
    # Create user manager
    users = UserManager()
    
    # Simulate adding users (with mock sockets)
    class MockSocket:
        def __init__(self, name):
            self.name = name
    
    # Add users
    user_list = ["Alice", "Bob", "Charlie", "Diana"]
    for username in user_list:
        socket = MockSocket(username)
        success = users.add_user(username, socket)
        print(f"➕ Added {username}: {'✅' if success else '❌'}")
    
    # Try to add duplicate
    duplicate_result = users.add_user("Alice", MockSocket("Alice2"))
    print(f"➕ Added duplicate Alice: {'✅' if duplicate_result else '❌'}")
    
    # Show current users
    current_users = users.get_users()
    print(f"👥 Current users: {current_users}")
    print(f"📊 Total users: {len(current_users)}")
    
    # Remove a user
    users.remove_user("Bob")
    print(f"➖ Removed Bob")
    print(f"👥 Users after removal: {users.get_users()}")

def demo_file_operations():
    """Demonstrate file encoding/decoding"""
    print("\n📁 FILE OPERATIONS DEMO")
    print("-" * 40)
    
    # Create file manager
    file_manager = FileManager("demo_files")
    
    # Create a test file
    test_file = os.path.join("demo_files", "test_document.txt")
    os.makedirs("demo_files", exist_ok=True)
    
    test_content = """This is a test document for the chat application.
It contains multiple lines and special characters: !@#$%^&*()
This demonstrates the file sharing capability of our chat system.
🚀 Unicode support is also included! 
"""
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    print(f"📝 Created test file: {test_file}")
    print(f"📊 File size: {os.path.getsize(test_file)} bytes")
    
    # Encode file (simulate sending)
    try:
        file_info = file_manager.encode_file(test_file)
        print(f"✅ File encoded successfully")
        print(f"📊 File info: {file_info['name']}, {file_info['size']} bytes, type: {file_info['type']}")
        
        # Decode file (simulate receiving)
        decoded_path = file_manager.decode_file(file_info)
        print(f"✅ File decoded to: {decoded_path}")
        
        # Verify content
        with open(decoded_path, 'r', encoding='utf-8') as f:
            decoded_content = f.read()
        
        print(f"✅ Content match: {test_content == decoded_content}")
        
    except Exception as e:
        print(f"❌ File operation error: {e}")

def demo_chat_history():
    """Demonstrate chat history and search"""
    print("\n📚 CHAT HISTORY DEMO")
    print("-" * 40)
    
    # Create chat history
    history = ChatHistory(max_messages=50)
    
    # Add sample conversation
    conversation = [
        ("Alice", "Hello everyone! How's the project going?"),
        ("Bob", "Hey Alice! I'm working on the Python implementation"),
        ("Charlie", "The encryption part is really interesting"),
        ("Alice", "Yes! The Fernet encryption is quite secure"),
        ("Diana", "I love the GUI design, very modern"),
        ("Bob", "The file sharing feature works perfectly"),
        ("System", "User Eve joined the chat"),
        ("Eve", "Hi all! What are we discussing?"),
        ("Alice", "We're talking about our Python chat application"),
        ("Charlie", "It has encryption, file sharing, and great GUI"),
    ]
    
    # Add messages to history
    for sender, content in conversation:
        msg_type = "system" if sender == "System" else "text"
        message = Message(sender, content, msg_type)
        history.add_message(message)
        print(f"📝 Added: [{sender}] {content}")
    
    # Demonstrate search functionality
    print(f"\n🔍 SEARCH DEMOS:")
    
    search_terms = ["Python", "encryption", "Alice", "GUI"]
    for term in search_terms:
        results = history.search_messages(term)
        print(f"🔍 Search '{term}': {len(results)} results")
        for msg in results:
            print(f"   📌 {msg.sender}: {msg.content}")
    
    # Get messages from specific user
    alice_messages = history.get_user_messages("Alice")
    print(f"\n👤 Alice's messages ({len(alice_messages)}):")
    for msg in alice_messages:
        print(f"   📝 {msg.content}")
    
    print(f"\n📊 Total messages in history: {len(history.get_messages())}")

def main():
    """Run all demonstrations"""
    print("🚀 ADVANCED CHAT APPLICATION - COMPONENT DEMONSTRATIONS")
    print("=" * 70)
    print()
    
    try:
        demo_encryption()
        demo_message_system()
        demo_user_management()
        demo_file_operations()
        demo_chat_history()
        
        print("\n" + "=" * 70)
        print("🎉 ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        print("\n📋 COMPONENT SUMMARY:")
        print("✅ SecurityManager - Encryption/Decryption")
        print("✅ Message & MessageQueue - Message handling")
        print("✅ UserManager - User management with thread safety")
        print("✅ FileManager - File encoding/decoding")
        print("✅ ChatHistory - Message storage and search")
        print("\n🎯 PROGRAMMING CONCEPTS DEMONSTRATED:")
        print("✅ Object-Oriented Programming (OOP)")
        print("✅ Data Structures (Queue, Dictionary, List)")
        print("✅ Algorithms (Search, Encryption, File Processing)")
        print("✅ Thread Safety and Concurrency")
        print("✅ Error Handling and Validation")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
    
    print("\n🚀 Ready to run the full chat application!")

if __name__ == "__main__":
    main()
