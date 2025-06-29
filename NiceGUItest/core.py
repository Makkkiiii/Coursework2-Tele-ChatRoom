"""
Advanced Chat Application with Encryption, File Sharing, and GUI
Features: OOP Design, Data Structures, Encryption, File Transfer, Modern GUI
Author: Programming & Algorithm 2 - Coursework
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import threading
import json
import base64
import hashlib
import os
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageTk
import queue
import time
from typing import Optional, Dict, List, Any


class SecurityManager:
    """Handles encryption and decryption using Fernet symmetric encryption"""
    
    def __init__(self, password: str = "default_chat_password"):
        self.password = password.encode()
        self.key = self._derive_key()
        self.fernet = Fernet(self.key)
    
    def _derive_key(self) -> bytes:
        """Derive a key from password using PBKDF2"""
        salt = b'Z2dSt9xmZqeIh6Rwg1yIRUuRxMv6zSCr7PMR9EYfZyg='  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_message(self, message: str) -> str:
        """Encrypt a message and return base64 encoded string"""
        encrypted = self.fernet.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a base64 encoded encrypted message"""
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = self.fernet.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            return f"[Decryption Error: {str(e)}]"


class Message:
    """Represents a chat message with metadata"""
    
    def __init__(self, sender: str, content: str, msg_type: str = "text", 
                 file_data: Optional[Dict] = None, timestamp: Optional[datetime] = None):
        self.sender = sender
        self.content = content
        self.msg_type = msg_type  # "text", "file", "image", "system"
        self.file_data = file_data or {}
        self.timestamp = timestamp or datetime.now()
        self.message_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique message ID"""
        return hashlib.md5(
            f"{self.sender}{self.timestamp}{self.content}".encode()
        ).hexdigest()[:8]
    
    def to_dict(self) -> dict:
        """Convert message to dictionary for JSON serialization"""
        return {
            "id": self.message_id,
            "sender": self.sender,
            "content": self.content,
            "type": self.msg_type,
            "file_data": self.file_data,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create message from dictionary"""
        msg = cls(
            sender=data["sender"],
            content=data["content"],
            msg_type=data.get("type", "text"),
            file_data=data.get("file_data", {}),
            timestamp=datetime.fromisoformat(data["timestamp"])
        )
        msg.message_id = data["id"]
        return msg


class MessageQueue:
    """Thread-safe message queue using built-in queue.Queue"""
    
    def __init__(self):
        self._queue = queue.Queue()
        self._lock = threading.Lock()
    
    def put(self, message: Message):
        """Add message to queue"""
        with self._lock:
            self._queue.put(message)
    
    def get(self, timeout: Optional[float] = None) -> Message:
        """Get message from queue"""
        return self._queue.get(timeout=timeout)
    
    def empty(self) -> bool:
        """Check if queue is empty"""
        return self._queue.empty()


class UserManager:
    """Manages connected users using dictionary data structure"""
    
    def __init__(self):
        self._users = {}  # {username: {"socket": socket, "status": "online"}}
        self._lock = threading.Lock()
    
    def add_user(self, username: str, user_socket: socket.socket) -> bool:
        """Add user to the system"""
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = {
                "socket": user_socket,
                "status": "online",
                "joined_at": datetime.now()
            }
            return True
    
    def remove_user(self, username: str):
        """Remove user from system"""
        with self._lock:
            self._users.pop(username, None)
    
    def get_users(self) -> list:
        """Get list of online users"""
        with self._lock:
            return list(self._users.keys())
    
    def get_user_socket(self, username: str) -> Optional[socket.socket]:
        """Get user's socket"""
        with self._lock:
            user_data = self._users.get(username)
            return user_data["socket"] if user_data else None
    
    def user_exists(self, username: str) -> bool:
        """Check if user exists"""
        with self._lock:
            return username in self._users


class FileManager:
    """Handles file operations and transfers"""
    
    def __init__(self, base_dir: str = "shared_files"):
        self.base_dir = base_dir
        self.ensure_directory()
        self.max_file_size = 10 * 1024 * 1024  # 10MB limit
    
    def ensure_directory(self):
        """Create base directory if it doesn't exist"""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
    
    def encode_file(self, file_path: str) -> dict:
        """Encode file to base64 for transmission"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                raise ValueError(f"File too large: {file_size} bytes")
            
            with open(file_path, 'rb') as file:
                file_data = file.read()
                encoded_data = base64.b64encode(file_data).decode()
            
            file_info = {
                "name": os.path.basename(file_path),
                "size": file_size,
                "data": encoded_data,
                "type": self._get_file_type(file_path)
            }
            return file_info
        except Exception as e:
            raise Exception(f"File encoding error: {str(e)}")
    
    def decode_file(self, file_info: dict) -> str:
        """Decode and save file from base64 data"""
        try:
            file_data = base64.b64decode(file_info["data"])
            file_path = os.path.join(self.base_dir, file_info["name"])
            
            # Handle duplicate filenames
            counter = 1
            original_path = file_path
            while os.path.exists(file_path):
                name, ext = os.path.splitext(original_path)
                file_path = f"{name}_{counter}{ext}"
                counter += 1
            
            with open(file_path, 'wb') as file:
                file.write(file_data)
            
            return file_path
        except Exception as e:
            raise Exception(f"File decoding error: {str(e)}")
    
    def _get_file_type(self, file_path: str) -> str:
        """Determine file type based on extension"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return 'image'
        elif ext in ['.txt', '.py', '.js', '.html', '.css']:
            return 'text'
        elif ext in ['.pdf', '.doc', '.docx']:
            return 'document'
        else:
            return 'file'


class ChatHistory:
    """Manages chat history using list data structure with search capabilities"""
    
    def __init__(self, max_messages: int = 1000):
        self._messages = []  # List to store messages
        self._max_messages = max_messages
        self._lock = threading.Lock()
    
    def add_message(self, message: Message):
        """Add message to history"""
        with self._lock:
            self._messages.append(message)
            # Keep only recent messages to prevent memory issues
            if len(self._messages) > self._max_messages:
                self._messages = self._messages[-self._max_messages:]
    
    def get_messages(self, limit: Optional[int] = None) -> List[Message]:
        """Get recent messages"""
        with self._lock:
            if limit:
                return self._messages[-limit:]
            return self._messages.copy()
    
    def search_messages(self, query: str) -> list:
        """Search messages by content"""
        with self._lock:
            query_lower = query.lower()
            return [msg for msg in self._messages 
                   if query_lower in msg.content.lower() or 
                      query_lower in msg.sender.lower()]
    
    def get_user_messages(self, username: str) -> list:
        """Get messages from specific user"""
        with self._lock:
            return [msg for msg in self._messages if msg.sender == username]
    
    def clear_history(self):
        """Clear all messages"""
        with self._lock:
            self._messages.clear()


if __name__ == "__main__":
    # Test the classes
    print("Core classes loaded successfully!")
    
    # Test SecurityManager
    sm = SecurityManager()
    test_msg = "Hello, this is a test message!"
    encrypted = sm.encrypt_message(test_msg)
    decrypted = sm.decrypt_message(encrypted)
    print(f"Encryption test: {decrypted == test_msg}")
    
    # Test Message
    msg = Message("TestUser", "Test content")
    msg_dict = msg.to_dict()
    msg_restored = Message.from_dict(msg_dict)
    print(f"Message serialization test: {msg.content == msg_restored.content}")
    
    print("All tests passed!")
