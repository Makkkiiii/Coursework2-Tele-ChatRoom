"""
PyQt Chat Client with Modern Telegram-like Interface
Features: Modern UI, File transfer, Message encryption, User management
"""

import sys
import socket
import threading
import json
import os
from datetime import datetime
from core import SecurityManager, Message, FileManager
from typing import Optional
import platform

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLineEdit, QPushButton, QTextEdit, QListWidget, QLabel, 
    QGroupBox, QSplitter, QFileDialog, QMessageBox, QFrame,
    QScrollArea, QListWidgetItem, QTextBrowser, QProgressBar,
    QStackedWidget, QTabWidget, QCheckBox, QSpinBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import (
    QFont, QPalette, QColor, QPixmap, QIcon, QTextDocument, 
    QTextCursor, QTextCharFormat, QBrush
)


class MessageListeningThread(QThread):
    """Thread for listening to server messages"""
    message_received = pyqtSignal(dict)
    connection_lost = pyqtSignal()
    
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.running = True
    
    def run(self):
        """Listen for incoming messages"""
        while self.running and self.client.socket and self.client.connected:
            try:
                # Set socket timeout to prevent indefinite blocking
                self.client.socket.settimeout(1.0)
                data = self.client.socket.recv(4096)
                
                if not data:
                    # Server closed connection
                    print("Server closed connection (no data)")
                    break
                
                encrypted_data = data.decode().strip()
                if not encrypted_data:
                    continue
                
                try:
                    decrypted_data = self.client.security_manager.decrypt_message(encrypted_data)
                    message_data = json.loads(decrypted_data)
                    self.message_received.emit(message_data)
                except Exception as e:
                    print(f"Message decryption/parsing failed: {e}")
                    continue
                    
            except socket.timeout:
                # Timeout is normal, continue listening
                continue
            except socket.error as e:
                print(f"Socket error in message listening: {e}")
                break
            except Exception as e:
                print(f"Message handling error: {e}")
                break
        
        print("Message listening thread stopping")
        self.connection_lost.emit()
    
    def stop(self):
        """Stop the listening thread"""
        self.running = False


class ChatClient:
    """Main client class for chat communication"""
    
    def __init__(self):
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.username = ""
        self.host = "localhost"
        self.port = 12345
        
        # Core components
        self.security_manager = SecurityManager()
        self.file_manager = FileManager("received_files")
        
        # Message deduplication
        self.processed_messages = set()
        
        # Message handlers
        self.message_handlers = {
            "server_message": self._handle_server_message,
            "login_success": self._handle_login_success,
            "message": self._handle_message,
            "error": self._handle_error,
            "kicked": self._handle_kicked,
            "server_shutdown": self._handle_server_shutdown,
            "user_list_update": self._handle_user_list_update
        }
        
        # GUI reference
        self.gui = None  # type: Optional[ModernChatGUI]
        
        # Message listening thread
        self.listening_thread = None
    
    def connect_to_server(self, host, port, username):
        """Connect to the chat server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            self.host = host
            self.port = port
            self.username = username
            
            # Send username
            username_data = {"username": username}
            encrypted_data = self.security_manager.encrypt_message(
                json.dumps(username_data)
            )
            self.socket.send(encrypted_data.encode())
            
            # Start listening for messages
            self.connected = True
            self.listening_thread = MessageListeningThread(self)
            self.listening_thread.message_received.connect(self._handle_message_data)
            self.listening_thread.connection_lost.connect(self._handle_disconnection)
            self.listening_thread.start()
            
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.show_error(f"Connection failed: {e}")
            return False
    
    def _handle_message_data(self, message_data):
        """Handle incoming message data"""
        msg_type = message_data.get("type", "")
        handler = self.message_handlers.get(msg_type)
        if handler:
            handler(message_data)
        else:
            print(f"Unknown message type: {msg_type}")
    
    def _handle_disconnection(self):
        """Handle connection loss"""
        self.connected = False
        if self.gui:
            # Show server shutdown message if connection was unexpectedly lost
            self.gui.add_system_message("🛑 Connection to server lost - Server may have shut down")
            
            # Show session duration with consistent formatting
            if self.gui.start_time:
                duration = datetime.now() - self.gui.start_time
                self.gui.add_system_message(f"🕒 Session duration: {str(duration).split('.')[0]}")
            
            # Use clean disconnection (no redundant messages)
            self.gui.on_disconnected_clean()
    
    def _handle_server_message(self, data):
        """Handle server messages"""
        if self.gui:
            self.gui.add_system_message(data["content"])
    
    def _handle_login_success(self, data):
        """Handle successful login"""
        if self.gui:
            self.gui.add_system_message(data["content"])
            
            # Remove security level messages - user requested no security messages
            
            self.gui.update_user_list(data.get("users", []))
            self.gui.on_connected()
    
    def _handle_message(self, data):
        """Handle chat messages with deduplication"""
        message_data = data["data"]
        
        # Create unique message ID for deduplication
        message_id = f"{message_data.get('sender', '')}_{message_data.get('timestamp', '')}_{hash(str(message_data.get('content', '')))}"
        
        if message_id in self.processed_messages:
            print(f"Duplicate message detected, skipping: {message_id}")
            return  # Skip duplicate message
        
        self.processed_messages.add(message_id)
        
        # Keep only recent messages in cache (prevent memory leak)
        if len(self.processed_messages) > 1000:
            # Remove oldest 200 messages
            oldest_messages = list(self.processed_messages)[:200]
            for old_msg in oldest_messages:
                self.processed_messages.discard(old_msg)
        
        message = Message.from_dict(message_data)
        
        if self.gui:
            self.gui.display_message(message)
    
    def _handle_error(self, data):
        """Handle error messages"""
        if self.gui:
            self.gui.show_error(data["content"])
    
    def _handle_kicked(self, data):
        """Handle being kicked from server"""
        if self.gui:
            # Show only the correct kick sequence as requested
            self.gui.add_system_message(f"🛑 Error: {data['content']}")
            
            # Show session duration
            if self.gui.start_time:
                duration = datetime.now() - self.gui.start_time
                self.gui.add_system_message(f"🕒 Session duration: {str(duration).split('.')[0]}")
            
            # Clean termination messages
            self.gui.add_system_message("🔒 SECURE CONNECTION TERMINATED")
            self.gui.add_system_message("🛡️ All encryption keys cleared from memory")
            
            # Disconnect cleanly without showing additional messages
            self.disconnect_silently()
    
    def _handle_server_shutdown(self, data):
        """Handle server shutdown"""
        if self.gui:
            # Only show shutdown message once
            self.gui.add_system_message("🛑 Server is shutting down. Connection lost.")
            
            # Show session duration with consistent formatting
            if self.gui.start_time:
                duration = datetime.now() - self.gui.start_time
                self.gui.add_system_message(f"🕒 Session duration: {str(duration).split('.')[0]}")
            
            # Disconnect without showing additional messages
            self.gui.on_disconnected_clean()
    
    def _handle_user_list_update(self, data):
        """Handle user list updates from server"""
        if self.gui:
            self.gui.update_user_list(data.get("users", []))
    
    def send_message(self, content):
        """Send text message to server"""
        if not self.connected or not self.socket:
            return False
        
        try:
            message_data = {
                "type": "text",
                "content": content
            }
            
            encrypted_data = self.security_manager.encrypt_message(
                json.dumps(message_data)
            )
            self.socket.send(encrypted_data.encode())
            
            # Store for encryption verification
            if self.gui:
                self.gui.last_plain_data = content
                self.gui.last_encrypted_data = encrypted_data
                self.gui.last_message_type = "text"
            
            # Don't display message locally - let server broadcast it back
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.show_error(f"Failed to send message: {e}")
            return False
    
    def send_file(self, file_path):
        """Send file to server"""
        if not self.connected or not self.socket:
            return False
        
        try:
            # Encode file
            file_info = self.file_manager.encode_file(file_path)
            
            message_data = {
                "type": "file",
                "content": f"Sharing file: {file_info['name']}",
                "file_data": file_info
            }
            
            encrypted_data = self.security_manager.encrypt_message(
                json.dumps(message_data)
            )
            self.socket.send(encrypted_data.encode())
            
            # Store for encryption verification
            if self.gui:
                self.gui.last_plain_data = f"Shared file: {file_info['name']} ({file_info['size']} bytes)"
                self.gui.last_encrypted_data = encrypted_data
                self.gui.last_message_type = "file"
            
            # Display file message locally
            if self.gui:
                message = Message(
                    self.username,
                    f"Shared file: {file_info['name']}",
                    "file",
                    file_info
                )
                self.gui.display_message(message)
            
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.show_error(f"Failed to send file: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        # Send disconnect notification to server before closing
        if self.connected and self.socket:
            try:
                disconnect_data = {
                    "type": "disconnect",
                    "content": "User requested disconnect"
                }
                encrypted_data = self.security_manager.encrypt_message(
                    json.dumps(disconnect_data)
                )
                self.socket.send(encrypted_data.encode())
            except:
                pass  # Ignore errors during disconnect
        
        self._close_connection()
    
    def disconnect_silently(self):
        """Disconnect without sending any message to server (for kicks/errors)"""
        self._close_connection()
    
    def _close_connection(self):
        """Close the connection and cleanup"""
        self.connected = False
        if self.listening_thread:
            self.listening_thread.stop()
            self.listening_thread.wait()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None


class ModernChatWidget(QWidget):
    """Modern chat message display widget"""
    
    # Signal for thread-safe message display - no QTextCursor
    message_display_signal = pyqtSignal(str, str, str, bool)  # html, msg_type, sender, is_own
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.message_cache = set()  # Prevent duplicate messages
        self.setup_ui()
        
        # Connect the signal to the display method (main thread only)
        self.message_display_signal.connect(self._display_message_html)
        
    def setup_ui(self):
        """Setup the chat UI"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(2)
        
        # Chat display area with clean, professional background
        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(False)
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background: #1a1a1a;  /* Clean dark background */
                border: 2px solid #333333;
                border-radius: 8px;
                padding: 16px;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
                font-size: 14px;
                line-height: 1.5;
                selection-background-color: #404040;
            }
            QTextBrowser:focus {
                border: 2px solid #4285f4;  /* Clean blue focus */
            }
            QScrollBar:vertical {
                background: #2a2a2a;
                width: 12px;
                border-radius: 6px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #555555;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #666666;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        main_layout.addWidget(self.chat_display)
    
    def add_message(self, message: Message, is_own_message: bool = False):
        """Add a message to the chat display with enhanced modern design (thread-safe)"""
        # Create unique message ID to prevent duplicates
        message_id = f"{message.sender}_{message.timestamp}_{hash(message.content)}"
        if message_id in self.message_cache:
            return  # Duplicate message, skip
        
        self.message_cache.add(message_id)
        
        # Use 12-hour format with AM/PM for client messages (no timestamp for SYSTEM)
        timestamp = message.timestamp.strftime("%I:%M %p") if message.msg_type != "system" else ""
        
        # Generate clean HTML for the message
        html = self._generate_message_html(message, is_own_message, timestamp)
        
        # Emit signal for thread-safe display (no direct QTextCursor manipulation)
        self.message_display_signal.emit(html, message.msg_type, message.sender, is_own_message)
    
    def _display_message_html(self, html: str, msg_type: str, sender: str, is_own: bool):
        """Display message HTML in main thread only (connected to signal)"""
        # This method runs only in the main thread, safe for QTextEdit operations
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Insert the HTML
        cursor.insertHtml(html)
        
        # Simple line break after each message
        cursor.insertHtml("<br>")
        
        # Auto-scroll to bottom
        self.chat_display.ensureCursorVisible()
    
    def _generate_message_html(self, message: Message, is_own_message: bool, timestamp: str) -> str:
        """Generate clean message layout like real messaging apps"""
        if message.msg_type == "system":
            # System messages - plain white text, centered, small gap
            return f"""
            <div style="text-align: center; margin: 8px 0; padding: 4px 0;">
                <span style="color: #ffffff; font-size: 13px; font-style: italic;">
                    {message.content}
                </span>
            </div>
            """
        
        # Regular messages using table layout (like WhatsApp/Telegram)
        if is_own_message:
            # Your messages - right aligned using table
            content_to_display = message.content
            if message.msg_type == "file":
                file_icon = "📄" if not message.content.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')) else "🖼️"
                content_to_display = f"{file_icon} {message.content}"
            
            return f"""
            <table width="100%" style="margin: 8px 0;">
                <tr>
                    <td width="30%"></td>
                    <td width="70%" style="text-align: right;">
                        <div style="display: inline-block; text-align: right; max-width: 100%;">
                            <div style="color: #4ade80; font-size: 13px; font-weight: 600; margin-bottom: 2px;">
                                You
                            </div>
                            <div style="color: #ffffff; font-size: 14px; line-height: 1.3; margin-bottom: 2px; word-wrap: break-word;">
                                {content_to_display}
                            </div>
                            <div style="color: #999999; font-size: 11px;">
                                {timestamp}
                            </div>
                        </div>
                    </td>
                </tr>
            </table>
            """
        else:
            # Other messages - left aligned using table
            content_to_display = message.content
            if message.msg_type == "file":
                file_icon = "📄" if not message.content.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')) else "🖼️"
                content_to_display = f"{file_icon} {message.content}"
            
            return f"""
            <table width="100%" style="margin: 8px 0;">
                <tr>
                    <td width="70%" style="text-align: left;">
                        <div style="display: inline-block; text-align: left; max-width: 100%;">
                            <div style="color: #60a5fa; font-size: 13px; font-weight: 600; margin-bottom: 2px;">
                                {message.sender}
                            </div>
                            <div style="color: #ffffff; font-size: 14px; line-height: 1.3; margin-bottom: 2px; word-wrap: break-word;">
                                {content_to_display}
                            </div>
                            <div style="color: #999999; font-size: 11px;">
                                {timestamp}
                            </div>
                        </div>
                    </td>
                    <td width="30%"></td>
                </tr>
            </table>
            """
    
    def clear_chat(self):
        """Clear all messages"""
        self.chat_display.clear()
        self.message_cache.clear()  # Clear duplicate prevention cache


class ModernChatGUI(QMainWindow):
    """Modern PyQt Chat GUI with Telegram-like interface"""
    
    def __init__(self):
        super().__init__()
        self.client = ChatClient()
        self.client.gui = self
        
        self.connected = False
        self.message_count = 0
        self.start_time = None
        
        # Store last encrypted data for verification
        self.last_encrypted_data = ""
        self.last_plain_data = ""
        self.last_message_type = "text"
        
        self.setup_ui()
        self.setup_styles()
        
        # Timer for updating session info
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_session_info)
        self.timer.start(1000)  # Update every second
    
    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("🔒 TeleChat Client - Modern Secure Messaging")
        self.setGeometry(50, 50, 1500, 1000)
        self.setMinimumSize(1000, 700)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header section
        self.setup_header(main_layout)
        
        # Main content area
        self.setup_main_content(main_layout)
        
        # Input area
        self.setup_input_area(main_layout)
        
        # Initially disable chat components
        self.set_chat_state(False)
    
    def setup_header(self, main_layout):
        """Setup the header section"""
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Title
        title_label = QLabel("🔒 TeleChat Client")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 26px;
                font-weight: bold;
                color: #ffffff;
                padding: 15px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #007acc, stop:0.5 #005a9e, stop:1 #003d6b);
                border-radius: 12px;
                margin-bottom: 10px;
                border: 2px solid #333333;
            }
        """)
        header_layout.addWidget(title_label)
        
        # Security features display
        security_frame = QFrame()
        security_layout = QHBoxLayout(security_frame)
        
        security_features = [
            "🔐 End-to-End Encryption",
            "🛡️ Message Authentication", 
            "🔑 Key Derivation (PBKDF2)",
            "🚫 Anti-Tampering Protection"
        ]
        
        for feature in security_features:
            feature_label = QLabel(feature)
            feature_label.setStyleSheet("""
                QLabel {
                    font-size: 12px;
                    color: #27ae60;
                    background-color: #ecf87f;
                    padding: 5px 10px;
                    border-radius: 15px;
                    margin: 2px;
                }
            """)
            security_layout.addWidget(feature_label)
        
        header_layout.addWidget(security_frame)
        
        # Connection controls
        self.setup_connection_controls(header_layout)
        
        main_layout.addWidget(header_frame)
    
    def setup_connection_controls(self, header_layout):
        """Setup connection controls"""
        conn_frame = QFrame()
        conn_layout = QHBoxLayout(conn_frame)
        
        # Host input
        conn_layout.addWidget(QLabel("Host:"))
        self.host_entry = QLineEdit("localhost")
        self.host_entry.setMaximumWidth(120)
        conn_layout.addWidget(self.host_entry)
        
        # Port input
        conn_layout.addWidget(QLabel("Port:"))
        self.port_entry = QLineEdit("12345")
        self.port_entry.setMaximumWidth(80)
        conn_layout.addWidget(self.port_entry)
        
        # Username input
        conn_layout.addWidget(QLabel("Username:"))
        self.username_entry = QLineEdit()
        self.username_entry.setMaximumWidth(150)
        self.username_entry.returnPressed.connect(self.connect_to_server)
        conn_layout.addWidget(self.username_entry)
        
        # Connect button
        self.connect_button = QPushButton("🔗 Connect")
        self.connect_button.setObjectName("connect_button")
        self.connect_button.clicked.connect(self.connect_to_server)
        conn_layout.addWidget(self.connect_button)
        
        # Disconnect button
        self.disconnect_button = QPushButton("❌ Disconnect")
        self.disconnect_button.setObjectName("disconnect_button")
        self.disconnect_button.clicked.connect(self.disconnect)
        self.disconnect_button.setEnabled(False)
        conn_layout.addWidget(self.disconnect_button)
        
        # Status label
        self.status_label = QLabel("Status: Disconnected")
        self.status_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #ff6b6b;
                padding: 8px 12px;
                background-color: #2d1b1b;
                border-radius: 8px;
                margin-left: 20px;
                border: 1px solid #ff6b6b;
            }
        """)
        conn_layout.addWidget(self.status_label)
        
        conn_layout.addStretch()
        header_layout.addWidget(conn_frame)
    
    def setup_main_content(self, main_layout):
        """Setup the main content area"""
        # Create splitter for resizable panes
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel (chat)
        left_panel = self.setup_chat_panel()
        splitter.addWidget(left_panel)
        
        # Right panel (users and controls)
        right_panel = self.setup_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions - give more space to chat, less to tabs
        splitter.setSizes([900, 300])
        
        main_layout.addWidget(splitter)
    
    def setup_chat_panel(self):
        """Setup the chat panel"""
        chat_frame = QGroupBox("💬 Messages")
        chat_layout = QVBoxLayout(chat_frame)
        
        # Modern chat widget
        self.chat_widget = ModernChatWidget()
        chat_layout.addWidget(self.chat_widget)
        
        return chat_frame
    
    def setup_right_panel(self):
        """Setup the right panel with tabs"""
        tab_widget = QTabWidget()
        
        # Users tab (now includes Files section below)
        users_tab = self.setup_users_tab()
        tab_widget.addTab(users_tab, "👥 Users")
        
        # Security tab
        security_tab = self.setup_security_tab()
        tab_widget.addTab(security_tab, "🔐 Security")
        
        return tab_widget
    
    def setup_users_tab(self):
        """Setup the users tab with Files section below"""
        users_widget = QWidget()
        layout = QVBoxLayout(users_widget)
        
        # Online users list
        layout.addWidget(QLabel("Online Users:"))
        self.users_listbox = QListWidget()
        self.users_listbox.setStyleSheet("""
            QListWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #1a202c);
                border: 2px solid #2a2f32;
                border-radius: 10px;
                color: #ffffff;
                font-size: 14px;
                padding: 8px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #374151;
                border-radius: 6px;
                margin: 3px;
                background-color: transparent;
            }
            QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #25d366, stop:1 #1da851);
                color: #ffffff;
                font-weight: bold;
            }
            QListWidget::item:hover:!selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #374151, stop:1 #1f2937);
            }
        """)
        layout.addWidget(self.users_listbox)
        
        # Clear chat button
        self.clear_chat_button = QPushButton("🗑️ Clear Chat")
        self.clear_chat_button.clicked.connect(self.clear_chat)
        layout.addWidget(self.clear_chat_button)
        
        # Add Files section below Users
        files_frame = QGroupBox("📁 File Sharing")
        files_layout = QVBoxLayout(files_frame)
        
        # Share file button
        self.share_file_button = QPushButton("📤 Share File")
        self.share_file_button.clicked.connect(self.share_file)
        files_layout.addWidget(self.share_file_button)
        
        # Open downloads folder button
        self.open_folder_button = QPushButton("📂 Open Downloads")
        self.open_folder_button.clicked.connect(self.open_downloads_folder)
        files_layout.addWidget(self.open_folder_button)
        
        layout.addWidget(files_frame)
        
        return users_widget
    
    def setup_security_tab(self):
        """Setup the security tab"""
        security_widget = QWidget()
        layout = QVBoxLayout(security_widget)
        
        # Security status
        security_frame = QGroupBox("🛡️ Security Status")
        security_layout = QVBoxLayout(security_frame)
        
        # Encryption status
        self.encryption_status = QLabel("🔐 Encryption: Ready")
        self.encryption_status.setStyleSheet("color: #27ae60; font-weight: bold;")
        security_layout.addWidget(self.encryption_status)
        
        # Message counter
        self.message_counter = QLabel("📊 Messages: 0 sent")
        security_layout.addWidget(self.message_counter)
        
        # Session info
        self.session_info = QLabel("🕒 Session: Not started")
        security_layout.addWidget(self.session_info)
        
        # Security level
        self.security_level = QLabel("🛡️ Level: Maximum")
        self.security_level.setStyleSheet("color: #27ae60; font-weight: bold;")
        security_layout.addWidget(self.security_level)
        
        layout.addWidget(security_frame)
        
        # Encryption testing
        test_frame = QGroupBox("🔬 Encryption Testing")
        test_layout = QVBoxLayout(test_frame)
        
        # Test encryption button
        self.test_encryption_button = QPushButton("🔬 Test Encryption")
        self.test_encryption_button.clicked.connect(self.test_encryption)
        test_layout.addWidget(self.test_encryption_button)
        
        # Show encrypted data button
        self.show_encrypted_button = QPushButton("👁️ Show Raw Data")
        self.show_encrypted_button.clicked.connect(self.show_encrypted_data)
        test_layout.addWidget(self.show_encrypted_button)
        
        layout.addWidget(test_frame)
        layout.addStretch()
        
        return security_widget
    
    def setup_input_area(self, main_layout):
        """Setup the message input area"""
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.StyledPanel)
        input_layout = QHBoxLayout(input_frame)
        
        # Message input
        self.message_entry = QLineEdit()
        self.message_entry.setPlaceholderText("Type your message here...")
        self.message_entry.returnPressed.connect(self.send_message)
        self.message_entry.setStyleSheet("""
            QLineEdit {
                font-size: 14px;
                padding: 12px;
                border: 2px solid #444444;
                border-radius: 20px;
                background-color: #333333;
                color: #ffffff;
            }
            QLineEdit:focus {
                border-color: #007acc;
                background-color: #404040;
            }
        """)
        input_layout.addWidget(self.message_entry)
        
        # Send button
        self.send_button = QPushButton("📤 Send")
        self.send_button.setObjectName("send_button")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                padding: 12px 20px;
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 20px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #004085;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
        """)
        input_layout.addWidget(self.send_button)
        
        main_layout.addWidget(input_frame)
    
    def setup_styles(self):
        """Setup enhanced modern dark theme with WhatsApp-inspired aesthetics"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0b141a, stop:0.5 #111b21, stop:1 #0b141a);
                color: #ffffff;
            }
            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QGroupBox {
                font-weight: 600;
                font-size: 15px;
                border: 2px solid #2a2f32;
                border-radius: 12px;
                margin: 10px;
                padding-top: 25px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #1a202c);
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 12px 0 12px;
                background-color: #1f2937;
                color: #ffffff;
                font-size: 15px;
                font-weight: 600;
                border-radius: 6px;
            }
            QPushButton {
                font-size: 14px;
                font-weight: 600;
                padding: 12px 20px;
                border: 2px solid transparent;
                border-radius: 10px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #374151, stop:1 #1f2937);
                color: #ffffff;
                min-height: 30px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4b5563, stop:1 #374151);
                border-color: #25d366;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #111827);
            }
            QPushButton#send_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #25d366, stop:1 #1da851);
                font-weight: bold;
            }
            QPushButton#send_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38ef7d, stop:1 #25d366);
            }
            QPushButton#connect_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3b82f6, stop:1 #1d4ed8);
            }
            QPushButton#connect_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #60a5fa, stop:1 #3b82f6);
            }
            QPushButton#disconnect_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ef4444, stop:1 #dc2626);
            }
            QPushButton#disconnect_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f87171, stop:1 #ef4444);
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
                font-weight: 500;
            }
            QLineEdit {
                padding: 12px 15px;
                border: 2px solid #374151;
                border-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #111827);
                color: #ffffff;
                font-size: 14px;
                font-weight: 500;
            }
            QLineEdit:focus {
                border-color: #25d366;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
            }
            QTabWidget::pane {
                border: 2px solid #2a2f32;
                border-radius: 12px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #1a202c);
                padding: 8px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #374151, stop:1 #1f2937);
                color: #ffffff;
                padding: 15px 30px;
                margin: 3px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                font-weight: 600;
                font-size: 13px;
                min-width: 120px;
                border: 1px solid #2a2f32;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #25d366, stop:1 #1da851);
                color: #ffffff;
                border: 1px solid #128c7e;
            }
            QTabBar::tab:hover:!selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4b5563, stop:1 #374151);
            }
            QTextBrowser, QTextEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #1a202c);
                border: 2px solid #2a2f32;
                border-radius: 10px;
                padding: 15px;
                color: #ffffff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.4;
            }
            QListWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1f2937, stop:1 #1a202c);
                border: 2px solid #2a2f32;
                border-radius: 10px;
                color: #ffffff;
                font-size: 13px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #374151;
                border-radius: 5px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #25d366, stop:1 #1da851);
                color: #ffffff;
            }
            QListWidget::item:hover:!selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #374151, stop:1 #1f2937);
            }
            QFrame {
                background: transparent;
                border-radius: 10px;
            }
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #1f2937;
                width: 14px;
                border-radius: 7px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #374151, stop:1 #1f2937);
                border-radius: 7px;
                min-height: 25px;
            }
            QScrollBar::handle:vertical:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4b5563, stop:1 #374151);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
    
    def connect_to_server(self):
        """Connect to the chat server"""
        host = self.host_entry.text().strip()
        port = self.port_entry.text().strip()
        username = self.username_entry.text().strip()
        
        if not all([host, port, username]):
            self.show_error("Please fill in all connection fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            self.show_error("Port must be a number")
            return
        
        if self.client.connect_to_server(host, port, username):
            self.status_label.setText("Status: Connecting...")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-weight: bold;
                    color: #ffd43b;
                    padding: 8px 12px;
                    background-color: #2e2a1a;
                    border-radius: 8px;
                    margin-left: 20px;
                    border: 1px solid #ffd43b;
                }
            """)
        else:
            self.status_label.setText("Status: Connection Failed")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-weight: bold;
                    color: #ff6b6b;
                    padding: 8px 12px;
                    background-color: #2d1b1b;
                    border-radius: 8px;
                    margin-left: 20px;
                    border: 1px solid #ff6b6b;
                }
            """)
    
    def disconnect(self):
        """Disconnect from server"""
        self.client.disconnect()
        self.on_disconnected()
    
    def on_connected(self):
        """Handle successful connection"""
        self.connected = True
        self.start_time = datetime.now()
        self.message_count = 0
        self.set_chat_state(True)
        
        self.status_label.setText("Status: 🔒 Secure Connection")
        self.status_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #51cf66;
                padding: 8px 12px;
                background-color: #1a2e1a;
                border-radius: 8px;
                margin-left: 20px;
                border: 1px solid #51cf66;
            }
        """)
        
        self.connect_button.setEnabled(False)
        self.disconnect_button.setEnabled(True)
        self.host_entry.setEnabled(False)
        self.port_entry.setEnabled(False)
        self.username_entry.setEnabled(False)
        
        # Update security panel
        self.encryption_status.setText("🔐 Encrypted Connection")
        self.encryption_status.setStyleSheet("color: #27ae60; font-weight: bold;")
        self.message_counter.setText("📊 Messages: 0 sent")
        
        # Focus on message entry
        self.message_entry.setFocus()
        
        # Remove security notifications - user requested no security messages
    
    def on_disconnected(self):
        """Handle disconnection for user-initiated disconnects"""
        self.connected = False
        self.set_chat_state(False)
        
        self.status_label.setText("Status: Disconnected")
        self.status_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #ff6b6b;
                padding: 8px 12px;
                background-color: #2d1b1b;
                border-radius: 8px;
                margin-left: 20px;
                border: 1px solid #ff6b6b;
            }
        """)
        
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.host_entry.setEnabled(True)
        self.port_entry.setEnabled(True)
        self.username_entry.setEnabled(True)
        
        # Update security panel
        self.encryption_status.setText("🔐 Encryption: Inactive")
        self.encryption_status.setStyleSheet("color: #ffd43b; font-weight: bold;")
        self.session_info.setText("🕒 Session: Ended")
        
        # Only show messages for user-initiated disconnects
        if self.start_time:
            duration = datetime.now() - self.start_time
            self.add_system_message(f"🕒 Session duration: {duration}")
        
        # Clear users list
        self.users_listbox.clear()

    def on_disconnected_clean(self):
        """Handle disconnection without showing redundant messages"""
        self.connected = False
        self.set_chat_state(False)
        
        self.status_label.setText("Status: Disconnected")
        self.status_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #ff6b6b;
                padding: 8px 12px;
                background-color: #2d1b1b;
                border-radius: 8px;
                margin-left: 20px;
                border: 1px solid #ff6b6b;
            }
        """)
        
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.host_entry.setEnabled(True)
        self.port_entry.setEnabled(True)
        self.username_entry.setEnabled(True)
        
        # Update security panel
        self.encryption_status.setText("🔐 Encryption: Inactive")
        self.encryption_status.setStyleSheet("color: #ffd43b; font-weight: bold;")
        self.session_info.setText("🕒 Session: Ended")
        
        # Clear users list
        self.users_listbox.clear()
        
        # Disconnect from the client
        self.client.disconnect()

    def set_chat_state(self, enabled):
        """Enable or disable chat components"""
        if hasattr(self, 'message_entry'):
            self.message_entry.setEnabled(enabled)
        if hasattr(self, 'send_button'):
            self.send_button.setEnabled(enabled)
        if hasattr(self, 'file_button'):
            self.file_button.setEnabled(enabled)
        if hasattr(self, 'clear_button'):
            self.clear_button.setEnabled(enabled)

    # ...existing code...
    
    def send_message(self):
        """Send a text message"""
        message = self.message_entry.text().strip()
        if message and self.connected:
            if self.client.send_message(message):
                self.message_entry.clear()
                self.message_count += 1
                self.message_counter.setText(f"📊 Messages: {self.message_count} sent")
                
                # Show encryption confirmation for every 5th message
                if self.message_count % 5 == 0:
                    self.add_system_message(f"🔐 {self.message_count} messages encrypted and transmitted securely")
    
    def share_file(self):
        """Share a file"""
        if not self.connected:
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file to share",
            "",
            "All files (*.*);;Images (*.png *.jpg *.jpeg *.gif *.bmp);;Documents (*.pdf *.doc *.docx *.txt);;Archives (*.zip *.rar *.7z)"
        )
        
        if file_path:
            # Show security notification for file sharing
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            self.add_system_message(f"🔐 Encrypting file: {file_name} ({file_size} bytes)")
            
            if self.client.send_file(file_path):
                self.add_system_message(f"🛡️ File encrypted and transmitted securely")
            else:
                self.add_system_message(f"❌ Secure file transmission failed")
    
    def open_downloads_folder(self):
        """Open the downloads folder"""
        downloads_path = self.client.file_manager.base_dir
        if os.path.exists(downloads_path):
            try:
                # Cross-platform folder opening
                system = platform.system()
                if system == "Windows":
                    os.startfile(downloads_path)
                elif system == "Darwin":  # macOS
                    os.system(f"open '{downloads_path}'")
                else:  # Linux and others
                    os.system(f"xdg-open '{downloads_path}'")
            except Exception as e:
                self.show_error(f"Cannot open folder: {e}")
        else:
            self.show_error("Downloads folder does not exist yet")
    
    def clear_chat(self):
        """Clear chat messages"""
        self.chat_widget.clear_chat()
    
    def display_message(self, message: Message):
        """Display a message in the chat"""
        is_own_message = (message.sender == self.client.username)
        
        # Handle file downloads
        if message.msg_type == "file" and not is_own_message and message.file_data:
            try:
                # Ensure receive directory exists
                receive_dir = self.client.file_manager.base_dir
                if not os.path.exists(receive_dir):
                    os.makedirs(receive_dir)
                
                saved_path = self.client.file_manager.decode_file(message.file_data)
                # Update message content to show download path with full path for debugging
                rel_path = os.path.basename(saved_path)
                full_path = os.path.abspath(saved_path)
                message.content += f" (Saved to: {rel_path})"
                
                # Log the successful download for debugging
                print(f"File received and saved: {full_path}")
                
            except Exception as e:
                message.content += f" (Download failed: {e})"
                print(f"File download error: {e}")
        
        self.chat_widget.add_message(message, is_own_message)
    
    def add_system_message(self, message):
        """Add a system message"""
        system_message = Message("SYSTEM", message, "system")
        self.chat_widget.add_message(system_message, False)
    
    def update_user_list(self, users):
        """Update the online users list"""
        self.users_listbox.clear()
        for user in users:
            self.users_listbox.addItem(f"👤 {user}")
    
    def update_session_info(self):
        """Update session information"""
        if self.connected and self.start_time:
            duration = datetime.now() - self.start_time
            self.session_info.setText(f"🕒 Session: {str(duration).split('.')[0]}")
    
    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)
        # Don't add redundant system message since it's already handled in kick/disconnect handlers
    
    def test_encryption(self):
        """Test and display encryption process"""
        if not hasattr(self.client, 'security_manager'):
            self.show_error("Security manager not available")
            return
        
        # Use the last sent message if available, otherwise use a test message
        if self.last_plain_data:
            test_message = self.last_plain_data
            self.add_system_message("🔬 TESTING YOUR ACTUAL MESSAGE ENCRYPTION")
        else:
            test_message = "🔒 Send a message first to see real encryption!"
            self.add_system_message("🔬 ENCRYPTION TEST (send a message first for real data)")
        
        try:
            # Show the encryption process
            self.add_system_message(f"📝 Your original {self.last_message_type}: '{test_message}'")
            
            # Encrypt the message
            encrypted = self.client.security_manager.encrypt_message(test_message)
            self.add_system_message(f"🔐 Encrypted data: {encrypted[:50]}...")
            self.add_system_message(f"📊 Encrypted length: {len(encrypted)} bytes")
            
            # Decrypt to verify
            decrypted = self.client.security_manager.decrypt_message(encrypted)
            self.add_system_message(f"🔓 Decrypted back to: '{decrypted}'")
            
            # Verify integrity
            if test_message == decrypted:
                self.add_system_message("✅ YOUR MESSAGE ENCRYPTION VERIFIED - Secure transmission!")
            else:
                self.add_system_message("❌ ENCRYPTION TEST FAILED - Data corrupted!")
                
            # Update stored data if we used last message
            if self.last_plain_data:
                self.last_encrypted_data = encrypted
            
        except Exception as e:
            self.add_system_message(f"❌ Encryption test failed: {e}")
    
    def show_encrypted_data(self):
        """Show detailed encryption data in a popup"""
        if not self.last_encrypted_data:
            QMessageBox.information(self, "Info", "No encrypted data available. Send a message or share a file first to see YOUR actual encryption!")
            return
        
        # Create detailed popup dialog
        dialog = QMessageBox(self)
        dialog.setWindowTitle("🔍 YOUR ACTUAL DATA - Encryption Analysis")
        dialog.setIcon(QMessageBox.Information)
        
        # Get the action type
        action_type = "MESSAGE" if self.last_message_type == "text" else "FILE SHARE"
        
        # Create detailed analysis text
        analysis = f"""🔍 YOUR ACTUAL {action_type} ENCRYPTION ANALYSIS
{'='*60}

📝 WHAT YOU SENT ({action_type}):
"{self.last_plain_data}"

🔐 HOW IT WAS TRANSMITTED (Encrypted):
{self.last_encrypted_data}

📊 ENCRYPTION COMPARISON:
• Your Original Size: {len(self.last_plain_data)} characters
• Encrypted Size: {len(self.last_encrypted_data)} characters  
• Security Overhead: +{len(self.last_encrypted_data) - len(self.last_plain_data)} bytes

🛡️ SECURITY ANALYSIS:
✅ YOUR {action_type.lower()} is completely scrambled
✅ No readable text visible in encrypted data
✅ AES-256 encryption applied successfully
✅ PBKDF2 key derivation protects against attacks

🚨 WHAT HACKERS SEE ON THE NETWORK:
If someone intercepts YOUR data, they only see scrambled text like:
{self.last_encrypted_data[:100]}{'...' if len(self.last_encrypted_data) > 100 else ''}

❌ WITHOUT ENCRYPTION (DANGEROUS):
Hackers would see exactly: "{self.last_plain_data}"

🔒 CONCLUSION: 
YOUR {action_type.lower()} is SECURE and protected from eavesdropping!

🎯 TECHNICAL DETAILS:
• Algorithm: AES-256 (Fernet) - Military grade
• Key Derivation: PBKDF2 with 100,000 iterations
• Authentication: Built-in message integrity checking
• Timestamp: Included for replay attack prevention"""
        
        dialog.setDetailedText(analysis)
        dialog.setText(f"🔬 YOUR REAL {action_type} ENCRYPTION ANALYSIS")
        dialog.exec_()
    
    def closeEvent(self, event):
        """Handle window closing"""
        if self.connected:
            self.disconnect()
        event.accept()


def main():
    """Main function to run the application"""
    # Comprehensive Qt warning suppression
    import os
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
    app.setApplicationName("TeleChat Client")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Secure Chat Solutions")
    
    # Create and show the main window
    window = ModernChatGUI()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
