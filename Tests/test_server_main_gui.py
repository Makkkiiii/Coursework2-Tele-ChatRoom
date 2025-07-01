"""
Test Server with Password Authentication - Using Main GUI Design
Features: Socket Programming, Threading, Authentication, Encryption, Original Main GUI Design
Author: Programming & Algorithm 2 - Coursework - Test Environment
"""

import sys
import socket
import threading
import json
import time
from datetime import datetime
from typing import Optional
from test_core import (SecurityManager, AuthenticationManager, UserManager, 
                      MessageQueue, ChatHistory, FileManager, Message)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLineEdit, QPushButton, QTextEdit, QListWidget, QLabel, 
    QGroupBox, QSplitter, QFrame, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QCheckBox,
    QSpinBox, QTextBrowser, QMessageBox, QInputDialog, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEventLoop
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


class SecureChatServerWithAuth:
    """Enhanced chat server with password authentication"""
    
    def __init__(self, host='localhost', port=12345, server_password=None):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Password Authentication
        self.server_password = server_password
        self.security_manager = SecurityManager(server_password) # type: ignore
        self.auth_manager = AuthenticationManager(self.security_manager)
        
        # Core components
        self.user_manager = UserManager()
        self.chat_history = ChatHistory()
        self.message_queue = MessageQueue()
        self.file_manager = FileManager("test_received_files")
        
        # Server stats
        self.start_time = None
        self.message_count = 0
        
        # Session tracking
        self.client_ips = {}     # {client_socket: ip_address}
        self.kicked_users = set()  # Track usernames that were kicked
        
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
            
            print(f"🔒 Secure Server with Authentication started on {self.host}:{self.port}")
            
            # Start message processing thread
            threading.Thread(target=self._process_messages, daemon=True).start()
            
            # Accept connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.client_ips[client_socket] = address[0]
                    
                    # Handle client in separate thread
                    threading.Thread(
                        target=self._handle_client_with_auth,
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                    
                except socket.error:
                    if self.running:
                        print("Socket error during accept")
                    break
                    
        except Exception as e:
            print(f"Server error: {e}")
            if self.gui:
                self.gui.add_security_event(f"❌ Server error: {e}", "ERROR")
    
    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    def _handle_client_with_auth(self, client_socket, address):
        """Handle client connection with authentication"""
        username = None
        authenticated = False
        client_ip = address[0]
        
        try:
            # Send authentication challenge
            auth_challenge = {
                "type": "auth_challenge",
                "message": "Password required for chat access",
                "server_name": "Test Chat Server"
            }
            self._send_message_to_client(client_socket, auth_challenge)
            
            # Log connection attempt
            if self.gui:
                self.gui.add_security_event(f"📡 Connection attempt from {client_ip}", "INFO")
            
            # Authentication loop
            auth_attempts = 0
            max_attempts = 3
            
            while not authenticated and auth_attempts < max_attempts and self.running:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break
                    
                    message = json.loads(data)
                    
                    if message.get("type") == "auth_attempt":
                        auth_attempts += 1
                        password = message.get("password", "")
                        proposed_username = message.get("username", f"User_{address[1]}")
                        
                        # Authenticate using our auth manager
                        if self.auth_manager.authenticate_client(client_socket, password):
                            if not self.user_manager.user_exists(proposed_username):
                                username = proposed_username
                                authenticated = True
                                
                                # Add authenticated user
                                self.user_manager.add_user(username, client_socket, True)
                                
                                auth_response = {
                                    "type": "auth_success",
                                    "message": f"Welcome to Test Chat Server, {username}!",
                                    "username": username
                                }
                                self._send_message_to_client(client_socket, auth_response)
                                
                                # Log successful authentication
                                if self.gui:
                                    self.gui.add_security_event(f"✅ {username} authenticated successfully from {client_ip}", "INFO")
                                    self.gui.client_connected.emit(username, client_ip)
                                
                                # Broadcast join message
                                join_message = Message(
                                    sender="SYSTEM",
                                    content=f"🟢 {username} joined the chat",
                                    msg_type="system"
                                )
                                self.message_queue.put(join_message)
                                self.chat_history.add_message(join_message)
                                
                            else:
                                error_response = {
                                    "type": "auth_error",
                                    "message": f"Username '{proposed_username}' is already taken"
                                }
                                self._send_message_to_client(client_socket, error_response)
                        else:
                            remaining = max_attempts - auth_attempts
                            error_msg = f"❌ Incorrect password. {remaining} attempts remaining." if remaining > 0 else "❌ Access denied."
                            
                            error_response = {
                                "type": "auth_error",
                                "message": error_msg
                            }
                            self._send_message_to_client(client_socket, error_response)
                            
                            # Log failed authentication
                            if self.gui:
                                self.gui.add_security_event(f"❌ Authentication failed for {proposed_username} from {client_ip} (attempt {auth_attempts})", "WARNING")
                
                except (json.JSONDecodeError, Exception):
                    break
            
            if not authenticated:
                final_response = {
                    "type": "auth_rejected",
                    "message": "🚫 Access denied. Connection closed."
                }
                self._send_message_to_client(client_socket, final_response)
                
                # Log rejected connection
                if self.gui:
                    self.gui.add_security_event(f"🚫 Connection rejected from {client_ip} - authentication failed", "WARNING")
                return
            
            # Handle authenticated messages
            while self.running and authenticated:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break
                    
                    # Verify client is still authenticated
                    if not self.auth_manager.is_authenticated(client_socket):
                        error_msg = {
                            "type": "error",
                            "content": "🚫 Session expired. Please reconnect."
                        }
                        self._send_message_to_client(client_socket, error_msg)
                        break
                    
                    message_data = json.loads(data)
                    self._process_authenticated_message(username, message_data, client_socket)
                    
                except (json.JSONDecodeError, Exception):
                    break
        
        except Exception as e:
            print(f"Error handling client: {e}")
        
        finally:
            # Clean up
            if username:
                self.user_manager.remove_user(username)
                self.auth_manager.logout_client(client_socket)
                
                # Check if user was kicked
                was_kicked = username in self.kicked_users
                
                # Broadcast appropriate leave/kick message
                if was_kicked:
                    leave_message = Message(
                        sender="SYSTEM",
                        content=f"👮 {username} was kicked from the chat",
                        msg_type="system"
                    )
                    # Remove from kicked users after processing
                    self.kicked_users.discard(username)
                else:
                    leave_message = Message(
                        sender="SYSTEM",
                        content=f"👋🔴 {username} left the chat",
                        msg_type="system"
                    )
                
                self.message_queue.put(leave_message)
                self.chat_history.add_message(leave_message)
                
                # Log disconnection
                if self.gui:
                    if was_kicked:
                        self.gui.add_security_event(f"👮 {username} was kicked from {client_ip}", "WARNING")
                    else:
                        self.gui.add_security_event(f"👋 {username} disconnected from {client_ip}", "INFO")
                    self.gui.client_disconnected.emit(username)
            
            # Clean up tracking
            if client_socket in self.client_ips:
                del self.client_ips[client_socket]
            
            try:
                client_socket.close()
            except:
                pass
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
    
    def _process_authenticated_message(self, username, message_data, client_socket):
        """Process authenticated client messages"""
        msg_type = message_data.get("type", "text")
        
        if msg_type == "text":
            content = message_data.get("content", "")
            if content.strip():
                message = Message(username, content, "text")
                self.chat_history.add_message(message)
                self.message_queue.put(message)
                self.message_count += 1
                
                # Log message received
                if self.gui:
                    self.gui.add_security_event(f"📝 Message from {username}: {content[:50]}{'...' if len(content) > 50 else ''}", "INFO")
        
        elif msg_type == "file":
            try:
                file_info = message_data.get("file_data", {})
                filename = file_info.get("name", "unknown")
                
                # Save file
                file_path = self.file_manager.decode_file(file_info)
                
                file_message = Message(username, f"Shared file: {filename}", "file", file_info)
                self.chat_history.add_message(file_message)
                self.message_queue.put(file_message)
                
                # Log file transfer
                if self.gui:
                    self.gui.add_security_event(f"📎 File shared by {username}: {filename}", "INFO")
                
            except Exception as e:
                error_msg = Message("SYSTEM", f"File transfer error: {str(e)}", "system")
                self._send_message_to_client(client_socket, {"type": "message", "data": error_msg.to_dict()})
                
                if self.gui:
                    self.gui.add_security_event(f"❌ File transfer error from {username}: {str(e)}", "ERROR")
        
        elif msg_type == "get_users":
            users = self.user_manager.get_users(authenticated_only=True)
            response = {
                "type": "user_list",
                "users": users,
                "count": len(users)
            }
            self._send_message_to_client(client_socket, response)
    
    def _process_messages(self):
        """Process messages from queue and broadcast"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=1.0)
                self._broadcast_message(message)
            except:
                continue
    
    def _broadcast_message(self, message: Message):
        """Broadcast message to authenticated users"""
        message_data = {
            "type": "message",
            "data": message.to_dict()
        }
        
        # Update server GUI
        if self.gui:
            self.gui.update_message_display(message)
        
        # Send to authenticated users only
        for username in self.user_manager.get_users(authenticated_only=True):
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket and self.auth_manager.is_authenticated(user_socket):
                try:
                    self._send_message_to_client(user_socket, message_data)
                except:
                    pass
    
    def _send_message_to_client(self, client_socket, data):
        """Send message to client"""
        try:
            message_json = json.dumps(data)
            client_socket.send(message_json.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")


class ModernServerGUI(QMainWindow):
    """Modern PyQt Server GUI with Password Authentication"""
    
    # Signals for cross-thread communication
    client_connected = pyqtSignal(str, str)
    client_disconnected = pyqtSignal(str)
    security_event_signal = pyqtSignal(str, str, str)
    message_display_signal = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
        
        # Get server password first
        self.server_password = self._get_server_password()
        if not self.server_password:
            sys.exit()
        
        # Initialize server with password
        self.server = SecureChatServerWithAuth(server_password=self.server_password)
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
    
    def _get_server_password(self):
        """Get server password using modern dialog"""
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        # Create and show the modern password dialog
        password_dialog = ModernPasswordDialog()
        
        if password_dialog.exec_():
            return password_dialog.get_password()
        else:
            return None
    
    def setup_ui(self):
        """Setup the main UI - using original main GUI design"""
        self.setWindowTitle("🔒 TeleChat Server - Advanced Security Monitoring (With Password Auth)")
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
        title_label = QLabel("🔒 TeleChat Server - Advanced Security Monitor (Password Protected)")
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
        
        # Password protection indicator
        self.password_protection = QLabel("🔐 Password Protection: Enabled")
        self.password_protection.setStyleSheet("""
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
        status_layout.addWidget(self.password_protection)
        
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
        users_frame = QGroupBox("👥 Connected Users (Authenticated)")
        users_layout = QVBoxLayout(users_frame)
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(4)
        self.users_table.setHorizontalHeaderLabels(["Username", "IP Address", "Connected Since", "Auth Status"])
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
        
        # Authentication section
        auth_frame = QGroupBox("🔑 Authentication Events")
        auth_layout = QVBoxLayout(auth_frame)
        
        self.auth_events = QTextBrowser()
        self.auth_events.setMaximumHeight(200)
        self.auth_events.setStyleSheet("""
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
        auth_layout.addWidget(self.auth_events)
        layout.addWidget(auth_frame)
        
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
        
        # Authentication stats
        self.auth_attempts = QLabel("Authentication Attempts: 0")
        self.auth_attempts.setStyleSheet("font-size: 14px; padding: 5px; color: #e74c3c;")
        stats_grid_layout.addWidget(self.auth_attempts)
        
        # Messages stats
        self.total_messages = QLabel("Total Messages: 0")
        self.total_messages.setStyleSheet("font-size: 14px; padding: 5px;")
        stats_grid_layout.addWidget(self.total_messages)
        
        # Users stats
        self.total_users = QLabel("Total Users Connected: 0")
        self.total_users.setStyleSheet("font-size: 14px; padding: 5px;")
        stats_grid_layout.addWidget(self.total_users)
        
        # Authenticated sessions
        self.authenticated_sessions = QLabel("Authenticated Sessions: 0")
        self.authenticated_sessions.setStyleSheet("font-size: 14px; padding: 5px; color: #27ae60;")
        stats_grid_layout.addWidget(self.authenticated_sessions)
        
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
        
        # Password hash display
        password_hash_short = self.server.security_manager.auth_hash[:16] + "..."
        config_layout.addWidget(QLabel(f"Password Hash: {password_hash_short}"))
        
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
        """Setup enhanced modern dark theme - same as main GUI"""
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
        
        self.add_security_event("🚀 Server started successfully with password protection", "INFO")
    
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
        self.add_auth_event(f"✅ {username} - Authentication successful from {ip}")
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
        if message.msg_type == "system":
            self.messages_display.append(f"SYSTEM: {message.content}")
        else:
            timestamp = datetime.now().strftime("%I:%M %p")
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
    
    def add_auth_event(self, event):
        """Add authentication event"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.auth_events.append(f"[{timestamp}] {event}")
    
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
            self.authenticated_sessions.setText(f"Authenticated Sessions: {self.server.auth_manager.get_authenticated_count()}")
    
    def refresh_users(self):
        """Refresh the users table"""
        users = self.server.user_manager.get_users(authenticated_only=True)
        self.users_table.setRowCount(len(users))
        
        for i, username in enumerate(users):
            self.users_table.setItem(i, 0, QTableWidgetItem(username))
            
            # Get IP from session data if available
            ip = "Unknown"
            user_socket = self.server.user_manager.get_user_socket(username)
            if user_socket and user_socket in self.server.client_ips:
                ip = self.server.client_ips[user_socket]
            
            self.users_table.setItem(i, 1, QTableWidgetItem(ip))
            self.users_table.setItem(i, 2, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
            self.users_table.setItem(i, 3, QTableWidgetItem("✅ Authenticated"))
    
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
                    # Get user socket and kick
                    user_socket = self.server.user_manager.get_user_socket(username)
                    if user_socket:
                        try:
                            # Mark user as kicked
                            self.server.kicked_users.add(username)
                            
                            # Send kick notification
                            kick_msg = {
                                "type": "kicked",
                                "content": f"🚫 You have been kicked from the server by the administrator."
                            }
                            self.server._send_message_to_client(user_socket, kick_msg)
                            
                            # Close connection
                            user_socket.close()
                            
                            # Log the kick
                            self.add_security_event(f"👮 User {username} kicked by administrator", "WARNING")
                            
                            QMessageBox.information(self, "Success", f"User '{username}' has been kicked successfully.")
                            
                        except Exception as e:
                            QMessageBox.critical(self, "Error", f"Failed to kick user: {str(e)}")
                            self.add_security_event(f"❌ Failed to kick {username}: {str(e)}", "ERROR")
                    else:
                        QMessageBox.warning(self, "Error", f"User '{username}' not found or already disconnected.")
    
    def clear_messages(self):
        """Clear the messages display"""
        self.messages_display.clear()
        self.add_security_event("📝 Message history cleared", "INFO")
    
    def export_messages(self):
        """Export messages to file"""
        QMessageBox.information(self, "Export", "Message export functionality would be implemented here")
    
    def clear_security_events(self):
        """Clear security events"""
        self.security_events.clear()
        self.auth_events.clear()
        self.add_security_event("🗑️ Security logs cleared", "INFO")
    
    def export_security_log(self):
        """Export security log"""
        QMessageBox.information(self, "Export", "Security log export functionality would be implemented here")


class ModernPasswordDialog(QDialog):
    """Modern, always-editable password dialog for server setup"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("TeleChat Server - Password Setup")
        self.setModal(True)
        self.setFixedSize(550, 450)

        # Layout with much more spacing
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 40)
        layout.setSpacing(20)

        # Title
        title = QLabel("🔒 Set Server Password")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #fff; padding: 10px;")
        layout.addWidget(title)
        
        # Add some space after title
        layout.addSpacing(20)

        # Password field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password (min 4 chars)")
        self.password_input.textChanged.connect(self._validate)
        self.password_input.returnPressed.connect(self._handle_enter)
        self.password_input.setMinimumHeight(50)
        layout.addWidget(self.password_input)
        
        # Add space between fields
        layout.addSpacing(10)

        # Confirm password field
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Confirm password")
        self.confirm_input.textChanged.connect(self._validate)
        self.confirm_input.returnPressed.connect(self._handle_enter)
        self.confirm_input.setMinimumHeight(50)
        layout.addWidget(self.confirm_input)
        
        # Add space after confirm field
        layout.addSpacing(15)

        # Show/hide password
        self.show_checkbox = QCheckBox("Show passwords")
        self.show_checkbox.toggled.connect(self._toggle_visibility)
        layout.addWidget(self.show_checkbox)
        
        # Add space after checkbox
        layout.addSpacing(10)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 14px; color: #ccc; min-height: 30px; padding: 8px;")
        layout.addWidget(self.status_label)
        
        # Add flexible space to push buttons down
        layout.addStretch()

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)
        
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setMinimumHeight(45)
        cancel_btn.setMinimumWidth(120)
        btn_layout.addWidget(cancel_btn)
        
        self.ok_btn = QPushButton("🚀 Create Server")
        self.ok_btn.setEnabled(False)
        self.ok_btn.clicked.connect(self._accept)
        self.ok_btn.setMinimumHeight(45)
        self.ok_btn.setMinimumWidth(160)
        btn_layout.addWidget(self.ok_btn)
        
        layout.addLayout(btn_layout)

        # Style
        self.setStyleSheet("""
            QDialog { 
                background: #2b2b2b; 
                color: #ffffff; 
            }
            QLineEdit { 
                padding: 15px 20px; 
                font-size: 18px; 
                border: 2px solid #666666; 
                border-radius: 8px; 
                background: #ffffff; 
                color: #000000;
                selection-background-color: #4299e1;
                selection-color: #ffffff;
                min-height: 20px;
            }
            QLineEdit:focus { 
                border-color: #4299e1; 
                background: #ffffff;
                color: #000000;
            }
            QLineEdit::placeholder {
                color: #999999;
            }
            QPushButton { 
                padding: 12px 25px; 
                font-size: 16px; 
                font-weight: bold;
                border-radius: 8px; 
                background: #4299e1; 
                color: #ffffff; 
                border: none;
                min-height: 15px;
            }
            QPushButton:disabled { 
                background: #666666; 
                color: #cccccc; 
            }
            QPushButton:hover:!disabled { 
                background: #2563eb; 
            }
            QPushButton:pressed {
                background: #1e40af;
            }
            QCheckBox { 
                color: #ffffff; 
                font-size: 16px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid #666666;
                background: #ffffff;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #4299e1;
                background: #4299e1;
                border-radius: 3px;
            }
            QLabel {
                color: #ffffff;
            }
        """)

        # Focus and initial validation
        QTimer.singleShot(100, self.password_input.setFocus)
        QTimer.singleShot(200, self._validate)  # Show initial status message

    def _handle_enter(self):
        """Handle Enter key press in password fields"""
        if self.sender() == self.password_input:
            # Move to confirm field if password field pressed Enter
            self.confirm_input.setFocus()
        elif self.sender() == self.confirm_input:
            # Try to accept if confirm field pressed Enter and passwords are valid
            if self.ok_btn.isEnabled():
                self._accept()

    def _validate(self):
        pw = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if len(pw) == 0:
            self.status_label.setText("Enter a password (minimum 4 characters)")
            self.status_label.setStyleSheet("color: #cccccc; font-size: 14px; font-weight: normal;")
            self.ok_btn.setEnabled(False)
            return
            
        if len(pw) < 4:
            self.status_label.setText("❌ Password must be at least 4 characters")
            self.status_label.setStyleSheet("color: #ff6b6b; font-size: 14px; font-weight: bold;")
            self.ok_btn.setEnabled(False)
            return
            
        if len(confirm) == 0:
            self.status_label.setText("Please confirm your password")
            self.status_label.setStyleSheet("color: #ffa726; font-size: 14px; font-weight: normal;")
            self.ok_btn.setEnabled(False)
            return
            
        if pw != confirm:
            self.status_label.setText("❌ Passwords do not match")
            self.status_label.setStyleSheet("color: #ff6b6b; font-size: 14px; font-weight: bold;")
            self.ok_btn.setEnabled(False)
            return
            
        # All good!
        self.status_label.setText("✅ Password confirmed - Ready to create server!")
        self.status_label.setStyleSheet("color: #4caf50; font-size: 14px; font-weight: bold;")
        self.ok_btn.setEnabled(True)

    def _toggle_visibility(self, checked):
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)

    def _accept(self):
        self.accept()

    def get_password(self):
        return self.password_input.text()


def main():
    """Main function"""
    import os
    # Suppress Qt warnings
    import sys
    os.environ['QT_LOGGING_RULES'] = '*=false'
    os.environ['QT_DEBUG_CONSOLE'] = '0'
    os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--disable-logging'
    
    # Redirect Qt warnings to null
    import io
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    
    app = QApplication(sys.argv)
    
    # Restore stderr after app creation
    sys.stderr = old_stderr
    
    # Set application properties
    app.setApplicationName("TeleChat Server - Test with Auth")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Secure Chat Solutions - Test Environment")
    
    try:
        # Create and show the main window
        window = ModernServerGUI()
        window.show()
        
        # Run the application
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
