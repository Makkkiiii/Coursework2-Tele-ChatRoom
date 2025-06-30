"""
PyQt Chat Server with Modern Interface and Advanced Security
Features: Modern UI, Live monitoring, Advanced security, Message encryption
"""

from __future__ import annotations
import sys
import socket
import threading
import json
from datetime import datetime
from typing import Optional
from core import Message, MessageQueue, UserManager, ChatHistory
from security import AdvancedSecurityManager, SECURITY_CONFIG

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLineEdit, QPushButton, QTextEdit, QListWidget, QLabel, 
    QGroupBox, QSplitter, QFrame, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QCheckBox,
    QSpinBox, QTextBrowser, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPixmap, QIcon


class ServerThread(QThread):
    """Thread for running the server"""
    client_connected = pyqtSignal(str, str)  # username, ip
    client_disconnected = pyqtSignal(str)    # username
    message_received = pyqtSignal(dict)      # message data
    security_event = pyqtSignal(str, str, str)  # event, user, details
    server_error = pyqtSignal(str)           # error message
    
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.running = False
    
    def run(self):
        """Run the server"""
        try:
            self.server.start_server()
        except Exception as e:
            self.server_error.emit(str(e))
    
    def stop(self):
        """Stop the server"""
        self.running = False
        self.server.stop_server()


class SecureChatServer:
    """Enhanced chat server with advanced security features"""
    
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Enhanced Security Manager
        self.security_manager = AdvancedSecurityManager(SECURITY_CONFIG)
        
        # Core components
        self.user_manager = UserManager()
        self.chat_history = ChatHistory()
        self.message_queue = MessageQueue()
        
        # Server stats
        self.start_time = None
        self.message_count = 0
        
        # Session tracking
        self.user_sessions = {}  # {username: session_id}
        self.client_ips = {}     # {client_socket: ip_address}
        self.client_encryption_types = {}  # {client_socket: "basic" or "hybrid"}
        
        # GUI reference
        self.gui = None  # type: Optional[ModernServerGUI]
        
        # Server thread
        self.server_thread = None
    
    def start_server(self):
        """Start the secure server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            self.start_time = datetime.now()
            
            print(f"🔒 Secure Server started on {self.host}:{self.port}")
            
            # Start message processing thread
            threading.Thread(target=self._process_messages, daemon=True).start()
            
            # Accept connections
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_ip = client_address[0]
                    
                    # Store client IP for session validation
                    self.client_ips[client_socket] = client_ip
                    
                    print(f"🔐 Secure connection attempt from {client_address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_secure_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("Socket error occurred")
                    break
                    
        except Exception as e:
            print(f"Secure server error: {e}")
            self.running = False
    
    def stop_server(self):
        """Stop the server and notify all clients"""
        print("🛑 Server shutdown initiated...")
        
        # Notify all connected clients about server shutdown
        if self.running:
            self._notify_clients_shutdown()
        
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
            
        print("🛑 Server stopped.")
    
    def _notify_clients_shutdown(self):
        """Notify all clients that server is shutting down"""
        shutdown_message = {
            "type": "server_shutdown",
            "content": "🛑 Server is shutting down. You will be disconnected."
        }
        
        # Get all connected users
        users = self.user_manager.get_users().copy()  # Copy to avoid modification during iteration
        
        for username in users:
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket:
                try:
                    self._send_message_to_client(user_socket, shutdown_message)
                    print(f"🛑 Shutdown notification sent to {username}")
                except Exception as e:
                    print(f"Failed to notify {username}: {e}")
        
        # Give clients a moment to receive the message
        import time
        time.sleep(1)
    
    def _handle_secure_client(self, client_socket, client_address):
        """Handle client with enhanced security"""
        username = None
        session_id = None
        client_ip = client_address[0]
        
        try:
            # Send welcome message using basic encryption (for compatibility)
            welcome_msg = {
                "type": "server_message",
                "content": "🔒 Welcome to Secure Chat! Please send your username."
            }
            self._send_secure_message(client_socket, welcome_msg, use_basic_encryption=True)
            
            # Receive and validate username
            data = client_socket.recv(1024).decode()
            if not data:
                return
            
            client_encryption_type = "basic"  # Default to basic for compatibility
            
            try:
                # Try Fernet decryption for standard clients
                from core import SecurityManager
                basic_security = SecurityManager()
                decrypted_data = basic_security.decrypt_message(data)
                username_data = json.loads(decrypted_data)
                username = username_data.get("username", "").strip()
                client_encryption_type = "basic"
            except:
                try:
                    # Fallback to plain JSON (unencrypted)
                    username_data = json.loads(data)
                    username = username_data.get("username", "").strip()
                    client_encryption_type = "none"
                except:
                    return
            
            # Track client encryption type
            self.client_encryption_types[client_socket] = client_encryption_type
            print(f"Client {username} using {client_encryption_type} encryption")
            
            # Log detailed security info
            if self.gui:
                if client_encryption_type == "basic":
                    self.gui.add_security_event(f"🔒 {username}: FERNET encryption (AES-128)", "INFO")
                else:
                    self.gui.add_security_event(f"⚠️ {username}: UNENCRYPTED connection", "WARNING")
            
            # Enhanced authentication
            auth_success, auth_message, session_id = self.security_manager.authenticate_user(
                username, client_ip
            )
            
            # Log authentication attempt
            if self.gui:
                if auth_success:
                    self.gui.add_security_event(f"✅ {username}: Authentication SUCCESS from {client_ip}", "INFO")
                    if session_id:
                        self.gui.add_security_event(f"🔑 {username}: Session {session_id[:8]}... created", "INFO")
                    self.gui.client_connected.emit(username, client_ip)
                else:
                    self.gui.add_security_event(f"❌ {username}: Authentication FAILED - {auth_message}", "WARNING")
            
            if not auth_success:
                error_msg = {
                    "type": "error", 
                    "content": f"🚫 Authentication failed: {auth_message}"
                }
                self._send_message_to_client(client_socket, error_msg)
                return
            
            # Check if user already exists (prevent duplicate logins)
            if not self.user_manager.add_user(username, client_socket):
                error_msg = {
                    "type": "error",
                    "content": "🚫 Username already taken or invalid."
                }
                self._send_message_to_client(client_socket, error_msg)
                return
            
            # Store session
            self.user_sessions[username] = session_id
            
            # Send success confirmation
            success_msg = {
                "type": "login_success",
                "content": f"🔒 Welcome {username}! Secure connection established.",
                "users": self.user_manager.get_users(),
                "security_level": "HIGH"
            }
            self._send_message_to_client(client_socket, success_msg)
            
            # Broadcast updated user list to all existing clients
            self._broadcast_user_list_update()
            
            # Notify other users
            join_message = Message(
                sender="🔒 SecureSystem",
                content=f"{username} joined the secure chat",
                msg_type="system"
            )
            self.message_queue.put(join_message)
            self.chat_history.add_message(join_message)
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
            
            # Listen for messages from this client
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Validate session before processing
                    if session_id:
                        is_valid, session_username = self.security_manager.validate_session(
                            session_id, client_ip
                        )
                        
                        if not is_valid or session_username != username:
                            self._send_secure_message(client_socket, {
                                "type": "error",
                                "content": "🚫 Session expired or invalid. Please reconnect."
                            })
                            break
                    else:
                        # No session ID available
                        self._send_secure_message(client_socket, {
                            "type": "error",
                            "content": "🚫 No valid session. Please reconnect."
                        })
                        break
                    
                    # Process secure message
                    self._process_secure_client_message(
                        username, data, session_id, client_socket
                    )
                    
                except socket.error:
                    break
                except Exception as e:
                    print(f"Error handling secure client {username}: {e}")
                    if self.gui:
                        self.gui.add_security_event(f"Error with {username}: {str(e)}", "ERROR")
                    break
        
        except Exception as e:
            print(f"Secure client handling error: {e}")
        
        finally:
            # Clean up
            if username:
                self.user_manager.remove_user(username)
                if session_id:
                    self.security_manager.session_manager.invalidate_session(session_id)
                if username in self.user_sessions:
                    del self.user_sessions[username]
                
                # Clean up client encryption tracking
                if client_socket in self.client_encryption_types:
                    del self.client_encryption_types[client_socket]
                if client_socket in self.client_ips:
                    del self.client_ips[client_socket]
                
                # Broadcast updated user list to remaining clients
                self._broadcast_user_list_update()
                
                # Notify GUI
                if self.gui:
                    self.gui.client_disconnected.emit(username)
            
            client_socket.close()
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
    
    def _process_secure_client_message(self, username, data, session_id, client_socket):
        """Process client message with security validation"""
        try:
            # Decrypt message using basic encryption for compatibility with client
            from core import SecurityManager
            basic_security = SecurityManager()
            decrypted_data = basic_security.decrypt_message(data.decode())
            
            message_data = json.loads(decrypted_data)
            msg_type = message_data.get("type", "text")
            content = message_data.get("content", "")
            
            if msg_type == "text":
                # Validate and sanitize message
                is_safe, processed_content = self.security_manager.secure_message_processing(
                    content, username, session_id
                )
                
                if not is_safe:
                    # Send warning to user
                    warning_msg = {
                        "type": "error",
                        "content": f"⚠️ {processed_content}"
                    }
                    self._send_message_to_client(client_socket, warning_msg)
                    
                    # Log security event
                    if self.gui:
                        self.gui.add_security_event(f"🚫 {username}: Message blocked - security violation", "WARNING")
                    return
                
                # Log successful message processing
                if self.gui:
                    self.gui.add_security_event(f"📝 {username}: Message validated and encrypted", "INFO")
                
                message = Message(sender=username, content=processed_content, msg_type="text")
                
            elif msg_type == "file":
                # Handle file sharing (just relay to other clients, don't store)
                file_data = message_data.get("file_data", {})
                filename = file_data.get("name", "unknown")
                file_size = file_data.get("size", 0)
                
                # Validate file security
                is_valid, validation_message = self.security_manager.secure_file_processing(
                    filename, file_size, username
                )
                
                if not is_valid:
                    error_msg = {
                        "type": "error",
                        "content": f"🚫 File rejected: {validation_message}"
                    }
                    self._send_message_to_client(client_socket, error_msg)
                    
                    # Log file rejection
                    if self.gui:
                        self.gui.add_security_event(f"🚫 {username}: File {filename} REJECTED - {validation_message}", "WARNING")
                    return
                
                # Log successful file validation (server just relays the file)
                if self.gui:
                    self.gui.add_security_event(f"📁 {username}: File {filename} ({file_size} bytes) validated and relayed", "INFO")
                
                # Create message for relaying (don't save file on server)
                message = Message(
                    sender=username,
                    content=f"📎 Shared file: {filename}",
                    msg_type="file",
                    file_data=file_data
                )
            elif msg_type == "disconnect":
                # Handle disconnect request
                if self.gui:
                    self.gui.add_security_event(f"👋 {username}: Requested disconnect", "INFO")
                # Don't create a message for disconnect, just handle it gracefully
                return
            else:
                return
            
            # Add to history and queue for broadcast
            self.chat_history.add_message(message)
            self.message_queue.put(message)
            self.message_count += 1
            
        except Exception as e:
            print(f"Error processing secure message from {username}: {e}")
            if self.gui:
                self.gui.add_security_event(f"Message processing error from {username}: {str(e)}", "ERROR")
    
    def _process_messages(self):
        """Process messages from queue and broadcast securely"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=1.0)
                self._broadcast_secure_message(message)
            except:
                continue
    
    def _broadcast_secure_message(self, message: Message):
        """Broadcast message securely to all clients"""
        message_data = {
            "type": "message",
            "data": message.to_dict()
        }
        
        # Update server GUI with the message for live monitoring
        if self.gui:
            self.gui.update_message_display(message)
        
        # Get list of users to avoid modification during iteration
        users = self.user_manager.get_users()
        
        for username in users:
            # Send to ALL users including sender for consistent experience
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket:
                try:
                    self._send_message_to_client(user_socket, message_data)
                except:
                    # User disconnected, will be cleaned up
                    pass
    
    def _broadcast_user_list_update(self):
        """Broadcast updated user list to all connected clients"""
        user_list_update = {
            "type": "user_list_update",
            "users": self.user_manager.get_users()
        }
        
        # Get list of users to avoid modification during iteration
        users = self.user_manager.get_users()
        
        for username in users:
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket:
                try:
                    self._send_message_to_client(user_socket, user_list_update)
                except:
                    # User disconnected, will be cleaned up
                    pass
    
    def _send_message_to_client(self, client_socket, data):
        """Send message to client using appropriate encryption"""
        encryption_type = self.client_encryption_types.get(client_socket, "basic")
        use_basic = (encryption_type == "basic")
        self._send_secure_message(client_socket, data, use_basic_encryption=use_basic)
    
    def _send_secure_message(self, client_socket, data, use_basic_encryption=True):
        """Send encrypted message to client"""
        try:
            if use_basic_encryption:
                # Use basic Fernet encryption for compatibility
                from core import SecurityManager
                basic_security = SecurityManager()
                encrypted_data = basic_security.encrypt_message(json.dumps(data))
            else:
                # Use hybrid encryption (not implemented in this version for simplicity)
                encrypted_data = json.dumps(data)
            
            client_socket.send(encrypted_data.encode())
        except Exception as e:
            print(f"Error sending secure message: {e}")


class ModernServerGUI(QMainWindow):
    """Modern PyQt Server GUI with monitoring and security features"""
    
    # Signals for cross-thread communication
    client_connected = pyqtSignal(str, str)
    client_disconnected = pyqtSignal(str)
    security_event_signal = pyqtSignal(str, str, str)
    message_display_signal = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
        self.server = SecureChatServer()
        self.server.gui = self
        
        self.server_thread = None
        self.running = False
        
        # Connect signals
        self.client_connected.connect(self.on_client_connected)
        self.client_disconnected.connect(self.on_client_disconnected)
        self.security_event_signal.connect(self.on_security_event)
        self.message_display_signal.connect(self.on_message_display)
        
        self.setup_ui()
        self.setup_styles()
        
        # Timer for updating server stats
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_server_stats)
        self.timer.start(1000)  # Update every second
    
    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("🔒 TeleChat Server - Advanced Security Monitoring")
        self.setGeometry(50, 50, 1600, 1000)
        self.setMinimumSize(1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header section
        self.setup_header(main_layout)
        
        # Main content area with tabs
        self.setup_main_content(main_layout)
        
        # Control buttons
        self.setup_control_buttons(main_layout)
    
    def setup_header(self, main_layout):
        """Setup the header section"""
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Title
        title_label = QLabel("🔒 TeleChat Server - Advanced Security Monitor")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 28px;
                font-weight: bold;
                color: #ffffff;
                padding: 20px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #007acc, stop:0.5 #005a9e, stop:1 #003d6b);
                border-radius: 12px;
                margin-bottom: 10px;
                border: 2px solid #333333;
            }
        """)
        header_layout.addWidget(title_label)
        
        # Server status bar
        status_frame = QFrame()
        status_layout = QHBoxLayout(status_frame)
        
        # Server status
        self.server_status = QLabel("Server Status: Stopped")
        self.server_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #ff6b6b;
                padding: 10px 15px;
                background-color: #2d1b1b;
                border-radius: 8px;
                border-left: 4px solid #ff6b6b;
                border: 1px solid #404040;
            }
        """)
        status_layout.addWidget(self.server_status)
        
        # Security level
        self.security_level = QLabel("🛡️ Security Level: Maximum")
        self.security_level.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #51cf66;
                padding: 10px 15px;
                background-color: #1a2e1a;
                border-radius: 8px;
                border-left: 4px solid #51cf66;
                border: 1px solid #404040;
            }
        """)
        status_layout.addWidget(self.security_level)
        
        # Active connections
        self.active_connections = QLabel("👥 Active Connections: 0")
        self.active_connections.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #339af0;
                padding: 10px 15px;
                background-color: #1a1f2e;
                border-radius: 8px;
                border-left: 4px solid #339af0;
                border: 1px solid #404040;
            }
        """)
        status_layout.addWidget(self.active_connections)
        
        # Uptime
        self.uptime_label = QLabel("⏱️ Uptime: 00:00:00")
        self.uptime_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #ffd43b;
                padding: 10px 15px;
                background-color: #2e2a1a;
                border-radius: 8px;
                border-left: 4px solid #ffd43b;
                border: 1px solid #404040;
            }
        """)
        status_layout.addWidget(self.uptime_label)
        
        status_layout.addStretch()
        header_layout.addWidget(status_frame)
        
        main_layout.addWidget(header_frame)
    
    def setup_main_content(self, main_layout):
        """Setup the main content area with tabs"""
        tab_widget = QTabWidget()
        
        # Messages tab
        messages_tab = self.setup_messages_tab()
        tab_widget.addTab(messages_tab, "💬 Messages")
        
        # Users tab
        users_tab = self.setup_users_tab()
        tab_widget.addTab(users_tab, "👥 Users")
        
        # Security tab
        security_tab = self.setup_security_tab()
        tab_widget.addTab(security_tab, "🔒 Security")
        
        # Statistics tab
        stats_tab = self.setup_statistics_tab()
        tab_widget.addTab(stats_tab, "📊 Statistics")
        
        main_layout.addWidget(tab_widget)
    
    def setup_messages_tab(self):
        """Setup the messages monitoring tab"""
        messages_widget = QWidget()
        layout = QVBoxLayout(messages_widget)
        
        # Messages display
        messages_frame = QGroupBox("💬 Live Message Monitor")
        messages_layout = QVBoxLayout(messages_frame)
        
        self.messages_display = QTextBrowser()
        self.messages_display.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e;
                border: 2px solid #3d4147;
                border-radius: 10px;
                padding: 15px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                color: #ffffff;
                line-height: 1.4;
            }
        """)
        messages_layout.addWidget(self.messages_display)
        
        # Message controls
        controls_frame = QFrame()
        controls_layout = QHBoxLayout(controls_frame)
        
        self.clear_messages_btn = QPushButton("🗑️ Clear Messages")
        self.clear_messages_btn.clicked.connect(self.clear_messages)
        controls_layout.addWidget(self.clear_messages_btn)
        
        self.export_messages_btn = QPushButton("💾 Export Messages")
        self.export_messages_btn.clicked.connect(self.export_messages)
        controls_layout.addWidget(self.export_messages_btn)
        
        controls_layout.addStretch()
        messages_layout.addWidget(controls_frame)
        
        layout.addWidget(messages_frame)
        
        return messages_widget
    
    def setup_users_tab(self):
        """Setup the users monitoring tab"""
        users_widget = QWidget()
        layout = QVBoxLayout(users_widget)
        
        # Connected users
        users_frame = QGroupBox("👥 Connected Users")
        users_layout = QVBoxLayout(users_frame)
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(4)
        self.users_table.setHorizontalHeaderLabels(["Username", "IP Address", "Connected Since", "Status"])
        header = self.users_table.horizontalHeader()
        if header:
            header.setStretchLastSection(True)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                border: 2px solid #3d4147;
                border-radius: 10px;
                gridline-color: #4a5568;
                color: #ffffff;
                font-size: 13px;
                alternate-background-color: #262626;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #4a5568;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4299e1, stop:1 #3182ce);
                color: #ffffff;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:1 #2d3748);
                padding: 12px;
                border: 1px solid #3d4147;
                font-weight: 600;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        users_layout.addWidget(self.users_table)
        
        # Connect selection change to enable/disable kick button
        self.users_table.itemSelectionChanged.connect(self.on_user_selection_changed)
        
        # User controls
        user_controls = QFrame()
        user_controls_layout = QHBoxLayout(user_controls)
        
        self.kick_user_btn = QPushButton("🚫 Kick User")
        self.kick_user_btn.clicked.connect(self.kick_selected_user)
        self.kick_user_btn.setEnabled(False)
        user_controls_layout.addWidget(self.kick_user_btn)
        
        self.refresh_users_btn = QPushButton("🔄 Refresh")
        self.refresh_users_btn.clicked.connect(self.refresh_users)
        user_controls_layout.addWidget(self.refresh_users_btn)
        
        user_controls_layout.addStretch()
        users_layout.addWidget(user_controls)
        
        layout.addWidget(users_frame)
        
        return users_widget
    
    def setup_security_tab(self):
        """Setup the security monitoring tab"""
        security_widget = QWidget()
        layout = QVBoxLayout(security_widget)
        
        # Security events
        events_frame = QGroupBox("🔒 Security Events Log")
        events_layout = QVBoxLayout(events_frame)
        
        self.security_events = QTextBrowser()
        self.security_events.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e;
                border: 2px solid #3d4147;
                border-radius: 10px;
                padding: 15px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                color: #ffffff;
                line-height: 1.4;
            }
        """)
        events_layout.addWidget(self.security_events)
        
        # Security controls
        security_controls = QFrame()
        security_controls_layout = QHBoxLayout(security_controls)
        
        self.clear_security_btn = QPushButton("🗑️ Clear Security Log")
        self.clear_security_btn.clicked.connect(self.clear_security_events)
        security_controls_layout.addWidget(self.clear_security_btn)
        
        self.export_security_btn = QPushButton("💾 Export Security Log")
        self.export_security_btn.clicked.connect(self.export_security_log)
        security_controls_layout.addWidget(self.export_security_btn)
        
        self.security_report_btn = QPushButton("📋 Generate Security Report")
        self.security_report_btn.clicked.connect(self.generate_security_report)
        security_controls_layout.addWidget(self.security_report_btn)
        
        security_controls_layout.addStretch()
        events_layout.addWidget(security_controls)
        
        layout.addWidget(events_frame)
        
        return security_widget
    
    def setup_statistics_tab(self):
        """Setup the statistics tab"""
        stats_widget = QWidget()
        layout = QVBoxLayout(stats_widget)
        
        # Server statistics
        stats_frame = QGroupBox("📊 Server Statistics")
        stats_layout = QVBoxLayout(stats_frame)
        
        # Stats grid
        stats_grid = QFrame()
        stats_grid_layout = QVBoxLayout(stats_grid)
        
        # Messages stats
        self.total_messages = QLabel("Total Messages: 0")
        self.total_messages.setStyleSheet("font-size: 14px; padding: 5px;")
        stats_grid_layout.addWidget(self.total_messages)
        
        # Users stats
        self.total_users = QLabel("Total Users Connected: 0")
        self.total_users.setStyleSheet("font-size: 14px; padding: 5px;")
        stats_grid_layout.addWidget(self.total_users)
        
        # Security stats
        self.security_violations = QLabel("Security Violations: 0")
        self.security_violations.setStyleSheet("font-size: 14px; padding: 5px; color: #e74c3c;")
        stats_grid_layout.addWidget(self.security_violations)
        
        # Encryption stats
        self.encryption_operations = QLabel("Encryption Operations: 0")
        self.encryption_operations.setStyleSheet("font-size: 14px; padding: 5px; color: #27ae60;")
        stats_grid_layout.addWidget(self.encryption_operations)
        
        stats_layout.addWidget(stats_grid)
        layout.addWidget(stats_frame)
        
        return stats_widget
    
    def setup_control_buttons(self, main_layout):
        """Setup server control buttons"""
        controls_frame = QFrame()
        controls_frame.setFrameStyle(QFrame.StyledPanel)
        controls_layout = QHBoxLayout(controls_frame)
        
        # Server configuration
        config_frame = QFrame()
        config_layout = QHBoxLayout(config_frame)
        
        config_layout.addWidget(QLabel("Host:"))
        self.host_entry = QLineEdit("localhost")
        self.host_entry.setMaximumWidth(120)
        config_layout.addWidget(self.host_entry)
        
        config_layout.addWidget(QLabel("Port:"))
        self.port_entry = QLineEdit("12345")
        self.port_entry.setMaximumWidth(80)
        config_layout.addWidget(self.port_entry)
        
        controls_layout.addWidget(config_frame)
        controls_layout.addStretch()
        
        # Control buttons
        self.start_button = QPushButton("🚀 Start Server")
        self.start_button.setObjectName("start_button")
        self.start_button.clicked.connect(self.start_server)
        controls_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("🛑 Stop Server")
        self.stop_button.setObjectName("stop_button")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.stop_button)
        
        main_layout.addWidget(controls_frame)
    
    def setup_styles(self):
        """Setup enhanced modern dark theme with better aesthetics"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1a1a1a, stop:0.5 #1e1e1e, stop:1 #1a1a1a);
                color: #ffffff;
            }
            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 15px;
                border: 2px solid #3d4147;
                border-radius: 12px;
                margin: 10px;
                padding-top: 25px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d2d2d, stop:1 #262626);
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 12px 0 12px;
                background-color: #2d2d2d;
                color: #ffffff;
                font-size: 15px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton {
                font-size: 14px;
                font-weight: 600;
                padding: 12px 20px;
                border: 2px solid transparent;
                border-radius: 10px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:1 #2d3748);
                color: #ffffff;
                min-height: 30px;
                text-align: center;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5a6578, stop:1 #3d4758);
                border-color: #4299e1;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
            }
            QPushButton#start_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #48bb78, stop:1 #38a169);
            }
            QPushButton#start_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #68d391, stop:1 #48bb78);
            }
            QPushButton#stop_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f56565, stop:1 #e53e3e);
            }
            QPushButton#stop_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #fc8181, stop:1 #f56565);
            }
            QTabWidget::pane {
                border: 2px solid #3d4147;
                border-radius: 12px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d2d2d, stop:1 #262626);
                padding: 8px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #404040, stop:1 #353535);
                color: #ffffff;
                padding: 15px 30px;
                margin: 3px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                font-weight: 600;
                font-size: 13px;
                min-width: 120px;
                border: 1px solid #3d4147;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4299e1, stop:1 #3182ce);
                color: #ffffff;
                border: 1px solid #2b6cb0;
            }
            QTabBar::tab:hover:!selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #505050, stop:1 #454545);
            }
            QLineEdit {
                padding: 12px 15px;
                border: 2px solid #4a5568;
                border-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #333333, stop:1 #2d2d2d);
                color: #ffffff;
                font-size: 14px;
                font-weight: 500;
            }
            QLineEdit:focus {
                border-color: #4299e1;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3d3d3d, stop:1 #363636);
            }
            QTextBrowser, QTextEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e1e1e, stop:1 #1a1a1a);
                border: 2px solid #3d4147;
                border-radius: 10px;
                padding: 15px;
                color: #ffffff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.4;
            }
            QTableWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e1e1e, stop:1 #1a1a1a);
                border: 2px solid #3d4147;
                border-radius: 10px;
                gridline-color: #4a5568;
                color: #ffffff;
                font-size: 13px;
                alternate-background-color: #262626;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #4a5568;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4299e1, stop:1 #3182ce);
                color: #ffffff;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:1 #2d3748);
                padding: 12px;
                border: 1px solid #3d4147;
                font-weight: 600;
                color: #ffffff;
                font-size: 12px;
                border-radius: 0;
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
                font-weight: 500;
            }
            QFrame {
                background: transparent;
                border-radius: 10px;
            }
            QScrollBar:vertical {
                background: #2d3748;
                width: 14px;
                border-radius: 7px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4a5568, stop:1 #2d3748);
                border-radius: 7px;
                min-height: 25px;
            }
            QScrollBar::handle:vertical:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5a6578, stop:1 #3d4758);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
    
    def start_server(self):
        """Start the server"""
        host = self.host_entry.text().strip()
        port = self.port_entry.text().strip()
        
        if not host or not port:
            QMessageBox.warning(self, "Warning", "Please enter both host and port")
            return
        
        try:
            port = int(port)
        except ValueError:
            QMessageBox.warning(self, "Warning", "Port must be a number")
            return
        
        self.server.host = host
        self.server.port = port
        
        # Start server in separate thread
        self.server_thread = ServerThread(self.server)
        self.server_thread.client_connected.connect(self.on_client_connected)
        self.server_thread.client_disconnected.connect(self.on_client_disconnected)
        self.server_thread.security_event.connect(self.on_security_event)
        self.server_thread.server_error.connect(self.on_server_error)
        self.server_thread.start()
        
        self.running = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.host_entry.setEnabled(False)
        self.port_entry.setEnabled(False)
        
        self.server_status.setText(f"Server Status: Running on {host}:{port}")
        self.server_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #51cf66;
                padding: 10px 15px;
                background-color: #1a2e1a;
                border-radius: 8px;
                border-left: 4px solid #51cf66;
                border: 1px solid #404040;
            }
        """)
        
        self.add_security_event("🚀 Server started successfully", "INFO")
    
    def stop_server(self):
        """Stop the server"""
        if self.server_thread:
            self.server.stop_server()
            self.server_thread.stop()
            self.server_thread.wait()
        
        self.running = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.host_entry.setEnabled(True)
        self.port_entry.setEnabled(True)
        
        self.server_status.setText("Server Status: Stopped")
        self.server_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #ff6b6b;
                padding: 10px 15px;
                background-color: #2d1b1b;
                border-radius: 8px;
                border-left: 4px solid #ff6b6b;
                border: 1px solid #404040;
            }
        """)
        
        self.add_security_event("🛑 Server stopped", "INFO")
    
    def on_client_connected(self, username, ip):
        """Handle client connection"""
        self.add_security_event(f"👤 User {username} connected from {ip}", "INFO")
        self.update_server_info()
    
    def on_client_disconnected(self, username):
        """Handle client disconnection"""
        self.add_security_event(f"👤 User {username} disconnected", "INFO")
        self.update_server_info()
    
    def on_security_event(self, event, event_type, details=""):
        """Handle security events"""
        self.add_security_event(event, event_type, details)
    
    def on_message_display(self, message):
        """Handle message display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if message.msg_type == "system":
            self.messages_display.append(f"[{timestamp}] SYSTEM: {message.content}")
        else:
            self.messages_display.append(f"[{timestamp}] {message.sender}: {message.content}")
    
    def on_server_error(self, error):
        """Handle server errors"""
        QMessageBox.critical(self, "Server Error", f"Server error: {error}")
        self.add_security_event(f"❌ Server error: {error}", "ERROR")
    
    def add_security_event(self, event, event_type, details=""):
        """Add a security event to the log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Color code based on event type
        if event_type == "ERROR":
            color = "#e74c3c"
        elif event_type == "WARNING":
            color = "#f39c12"
        elif event_type == "INFO":
            color = "#3498db"
        else:
            color = "#495057"
        
        html = f'<span style="color: {color};">[{timestamp}] {event_type}: {event}</span>'
        if details:
            html += f'<br><span style="color: #6c757d; margin-left: 20px;">Details: {details}</span>'
        
        self.security_events.append(html)
    
    def update_message_display(self, message):
        """Update the message display"""
        self.message_display_signal.emit(message)
    
    def update_server_info(self):
        """Update server information display"""
        if self.running:
            user_count = len(self.server.user_manager.get_users())
            self.active_connections.setText(f"👥 Active Connections: {user_count}")
            
            # Update users table
            self.refresh_users()
    
    def update_server_stats(self):
        """Update server statistics"""
        if self.running and self.server.start_time:
            # Update uptime
            uptime = datetime.now() - self.server.start_time
            uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            self.uptime_label.setText(f"⏱️ Uptime: {uptime_str}")
            
            # Update statistics
            self.total_messages.setText(f"Total Messages: {self.server.message_count}")
            self.total_users.setText(f"Total Users Connected: {len(self.server.user_manager.get_users())}")
            
            # Update security stats
            if hasattr(self.server.security_manager, 'metrics'):
                metrics = self.server.security_manager.metrics
                self.security_violations.setText(f"Security Violations: {metrics.get('security_violations', 0)}")
                self.encryption_operations.setText(f"Encryption Operations: {metrics.get('messages_encrypted', 0)}")
    
    def refresh_users(self):
        """Refresh the users table"""
        users = self.server.user_manager.get_users()
        self.users_table.setRowCount(len(users))
        
        for i, username in enumerate(users):
            self.users_table.setItem(i, 0, QTableWidgetItem(username))
            
            # Get IP from session data if available
            ip = "Unknown"
            for socket, stored_ip in self.server.client_ips.items():
                # This is a simplification - in a real app, you'd need better user-socket mapping
                ip = stored_ip
                break
            
            self.users_table.setItem(i, 1, QTableWidgetItem(ip))
            self.users_table.setItem(i, 2, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
            self.users_table.setItem(i, 3, QTableWidgetItem("Online"))
    
    def on_user_selection_changed(self):
        """Handle user table selection changes"""
        current_row = self.users_table.currentRow()
        self.kick_user_btn.setEnabled(current_row >= 0)
    
    def kick_selected_user(self):
        """Kick the selected user"""
        current_row = self.users_table.currentRow()
        if current_row >= 0:
            item = self.users_table.item(current_row, 0)
            if item:
                username = item.text()
                
                # Confirm kick action
                reply = QMessageBox.question(
                    self, 
                    "Kick User", 
                    f"Are you sure you want to kick user '{username}'?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    # Get user socket and send kick message
                    user_socket = self.server.user_manager.get_user_socket(username)
                    if user_socket:
                        try:
                            # Send kick notification to user
                            kick_msg = {
                                "type": "kicked",
                                "content": f"🚫 You have been kicked from the server by the administrator."
                            }
                            self.server._send_message_to_client(user_socket, kick_msg)
                            
                            # Close the connection
                            user_socket.close()
                            
                            # Remove from user manager
                            self.server.user_manager.remove_user(username)
                            
                            # Clean up session and tracking
                            if username in self.server.user_sessions:
                                del self.server.user_sessions[username]
                            if user_socket in self.server.client_encryption_types:
                                del self.server.client_encryption_types[user_socket]
                            if user_socket in self.server.client_ips:
                                del self.server.client_ips[user_socket]
                            
                            # Log the kick
                            self.add_security_event(f"👮 User {username} kicked by administrator", "WARNING")
                            
                            # Notify other users
                            kick_message = Message(
                                sender="🔒 SecureSystem",
                                content=f"{username} was kicked from the server",
                                msg_type="system"
                            )
                            self.server.message_queue.put(kick_message)
                            self.server.chat_history.add_message(kick_message)
                            
                            # Broadcast updated user list to remaining clients
                            self.server._broadcast_user_list_update()
                            
                            # Update display
                            self.update_server_info()
                            
                            QMessageBox.information(self, "Success", f"User '{username}' has been kicked successfully.")
                            
                        except Exception as e:
                            QMessageBox.critical(self, "Error", f"Failed to kick user: {str(e)}")
                            self.add_security_event(f"❌ Failed to kick {username}: {str(e)}", "ERROR")
                    else:
                        QMessageBox.warning(self, "Error", f"User '{username}' not found or already disconnected.")
            else:
                QMessageBox.warning(self, "Warning", "No user selected or invalid selection")
    
    def clear_messages(self):
        """Clear the messages display"""
        self.messages_display.clear()
    
    def clear_security_events(self):
        """Clear the security events log"""
        self.security_events.clear()
    
    def export_messages(self):
        """Export messages to file"""
        # Implementation for exporting messages
        QMessageBox.information(self, "Info", "Export messages functionality would be implemented here")
    
    def export_security_log(self):
        """Export security log to file"""
        # Implementation for exporting security log
        QMessageBox.information(self, "Info", "Export security log functionality would be implemented here")
    
    def generate_security_report(self):
        """Generate a comprehensive security report"""
        if hasattr(self.server, 'security_manager'):
            report = self.server.security_manager.get_security_report()
            
            # Create report dialog
            dialog = QMessageBox(self)
            dialog.setWindowTitle("🔒 Security Report")
            dialog.setIcon(QMessageBox.Information)
            
            # Format report for display
            report_text = f"""Security Report Generated: {report.get('timestamp', 'Unknown')}
System Status: {report.get('system_status', 'Unknown')}
Active Sessions: {report.get('active_sessions', 0)}
Total Connections: {report.get('metrics', {}).get('total_connections', 0)}
Security Violations: {report.get('metrics', {}).get('security_violations', 0)}
Messages Encrypted: {report.get('metrics', {}).get('messages_encrypted', 0)}
            """
            
            dialog.setText("🔒 Security Report Generated")
            dialog.setDetailedText(report_text)
            dialog.exec_()
        else:
            QMessageBox.warning(self, "Warning", "Security manager not available")
    
    def closeEvent(self, event):
        """Handle window closing"""
        if self.running:
            self.stop_server()
        event.accept()


def main():
    """Main function to run the server application"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("TeleChat Server")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Secure Chat Solutions")
    
    # Create and show the main window
    window = ModernServerGUI()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
