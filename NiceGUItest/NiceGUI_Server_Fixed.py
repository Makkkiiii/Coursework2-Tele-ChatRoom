"""
Fixed NiceGUI Chat Server with Clean UI
Clean, working desktop interface for the secure chat server
"""

import socket
import threading
import json
from datetime import datetime
from typing import Optional
from nicegui import ui, app
from core import (
    Message, MessageQueue, UserManager, 
    ChatHistory
)
from security import (
    AdvancedSecurityManager, SECURITY_CONFIG
)


class SecureChatServer:
    """Enhanced chat server with advanced security features (unchanged backend logic)"""
    
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
        
        # GUI reference
        self.gui = None
        
        # Session tracking
        self.user_sessions = {}  # {username: session_id}
        self.client_ips = {}     # {client_socket: ip_address}
        self.client_encryption_types = {}  # {client_socket: "basic" or "hybrid"}
        
        # GUI reference
        self.gui = None
        
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
                    # Final fallback to plain JSON (unencrypted)
                    username_data = json.loads(data)
                    username = username_data.get("username", "").strip()
                    client_encryption_type = "none"
                except:
                    return
            
            # Track client encryption type
            self.client_encryption_types[client_socket] = client_encryption_type
            print(f"Client {username} using {client_encryption_type} encryption")
            
            # Enhanced authentication
            auth_success, auth_message, session_id = self.security_manager.authenticate_user(
                username, client_ip
            )
            
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
                    
                    # Process secure message
                    self._process_secure_client_message(
                        username, data, session_id, client_socket
                    )
                    
                except socket.error:
                    break
                except Exception as e:
                    print(f"Error handling secure client {username}: {e}")
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
            
            client_socket.close()
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
    
    def _process_secure_client_message(self, username, data, session_id, client_socket):
        """Process client message with security validation"""
        try:
            # Decrypt message using basic encryption
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
                    return
                
                message = Message(sender=username, content=processed_content, msg_type="text")
                
            elif msg_type == "file":
                # Handle file sharing
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
                    return
                
                # Create message for relaying
                message = Message(
                    sender=username,
                    content=f"📎 Shared file: {filename}",
                    msg_type="file",
                    file_data=file_data
                )
            else:
                return
            
            # Add to history and queue for broadcast
            self.chat_history.add_message(message)
            self.message_queue.put(message)
            self.message_count += 1
            
            # Update GUI
            if self.gui:
                self.gui.update_message_display(message)
            
        except Exception as e:
            print(f"Error processing secure message from {username}: {e}")
    
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
        
        # Get list of users to avoid modification during iteration
        users = self.user_manager.get_users()
        
        for username in users:
            if username != message.sender:  # Don't send back to sender
                user_socket = self.user_manager.get_user_socket(username)
                if user_socket:
                    try:
                        self._send_message_to_client(user_socket, message_data)
                    except:
                        # User disconnected, will be cleaned up
                        pass
    
    def _send_message_to_client(self, client_socket, data):
        """Send message to client using appropriate encryption"""
        encryption_type = self.client_encryption_types.get(client_socket, "basic")
        use_basic = (encryption_type == "basic" or encryption_type == "none")
        self._send_secure_message(client_socket, data, use_basic_encryption=use_basic)
    
    def _send_secure_message(self, client_socket, data, use_basic_encryption=True):
        """Send encrypted message to client"""
        try:
            json_data = json.dumps(data)
            
            if use_basic_encryption:
                # Use Fernet encryption for standard clients
                from core import SecurityManager
                basic_security = SecurityManager()
                encrypted_data = basic_security.encrypt_message(json_data)
                client_socket.send(encrypted_data.encode())
            else:
                # Plain JSON (for compatibility)
                client_socket.send(json_data.encode())
            
        except Exception as e:
            print(f"Error sending secure message: {e}")
    
    def get_security_report(self):
        """Get comprehensive security report"""
        try:
            return self.security_manager.get_security_report()
        except:
            # Fallback if security manager fails
            return {
                'active_sessions': len(self.user_sessions),
                'metrics': {
                    'total_connections': len(self.user_manager.get_users()),
                    'successful_logins': 0,
                    'failed_logins': 0,
                    'messages_encrypted': self.message_count,
                    'file_uploads': 0,
                    'blocked_attempts': 0,
                    'security_violations': 0
                },
                'rate_limit_status': {
                    'currently_blocked_ips': [],
                    'total_tracked_ips': len(self.client_ips)
                }
            }
    
    def kick_user_secure(self, username):
        """Securely kick a user"""
        if not username or username.strip() == "":
            return False
            
        # Check if user exists
        if not self.user_manager.user_exists(username):
            return False
            
        user_socket = self.user_manager.get_user_socket(username)
        if not user_socket:
            return False
            
        try:
            kick_msg = {
                "type": "kicked",
                "content": "🚫 You have been kicked from the secure server."
            }
            
            # Send kick message
            self._send_message_to_client(user_socket, kick_msg)
            
            # Clean up user data
            if user_socket in self.client_encryption_types:
                del self.client_encryption_types[user_socket]
            if user_socket in self.client_ips:
                del self.client_ips[user_socket]
                
            # Close socket connection
            try:
                user_socket.close()
            except:
                pass
                
            # Remove from user manager
            self.user_manager.remove_user(username)
            
            # Invalidate session
            if username in self.user_sessions:
                session_id = self.user_sessions[username]
                try:
                    self.security_manager.session_manager.invalidate_session(session_id)
                except:
                    pass
                del self.user_sessions[username]
            
            return True
            
        except Exception as e:
            print(f"Error kicking user {username}: {e}")
            return False
    
    def stop_server(self):
        """Stop server securely"""
        self.running = False
        
        # Notify all users
        shutdown_msg = {
            "type": "server_shutdown",
            "content": "🔒 Secure server is shutting down."
        }
        
        users = self.user_manager.get_users()
        for username in users:
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket:
                try:
                    self._send_message_to_client(user_socket, shutdown_msg)
                    user_socket.close()
                except:
                    pass
        
        if self.server_socket:
            self.server_socket.close()
        
        print("🔒 Secure server stopped")


class CleanServerGUI:
    """Clean, working NiceGUI server interface"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup beautiful Telegram-style server interface"""
        ui.dark_mode(True)
        
        # Add stunning CSS for flashy but functional design
        ui.add_head_html("""
        <style>
            .server-bg {
                background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
                min-height: 100vh;
            }
            .glass-card {
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
            .header-gradient {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 8px;
                padding: 12px 20px;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            }
            .status-online {
                background: linear-gradient(45deg, #4ade80, #22c55e) !important;
                color: white !important;
                padding: 6px 12px !important;
                border-radius: 15px !important;
                font-size: 0.85rem !important;
                font-weight: 600 !important;
                box-shadow: 0 2px 10px rgba(34, 197, 94, 0.4) !important;
                border: none !important;
            }
            .status-offline {
                background: linear-gradient(45deg, #f87171, #ef4444) !important;
                color: white !important;
                padding: 6px 12px !important;
                border-radius: 15px !important;
                font-size: 0.85rem !important;
                font-weight: 600 !important;
                box-shadow: 0 2px 10px rgba(239, 68, 68, 0.4) !important;
                border: none !important;
            }
            .metric-item {
                background: rgba(59, 130, 246, 0.1);
                border: 1px solid rgba(59, 130, 246, 0.2);
                border-radius: 8px;
                padding: 8px 12px;
                margin: 3px 0;
                transition: all 0.3s ease;
            }
            .metric-item:hover {
                background: rgba(59, 130, 246, 0.15);
                transform: translateX(5px);
            }
            .user-badge {
                background: rgba(34, 197, 94, 0.15);
                border: 1px solid rgba(34, 197, 94, 0.3);
                border-radius: 8px;
                padding: 6px 10px;
                margin: 2px 0;
                transition: all 0.3s ease;
            }
            .user-badge:hover {
                background: rgba(34, 197, 94, 0.25);
            }
            .message-bubble {
                background: rgba(147, 51, 234, 0.1);
                border: 1px solid rgba(147, 51, 234, 0.2);
                border-radius: 10px;
                padding: 10px 14px;
                margin: 4px 0;
                transition: all 0.2s ease;
                animation: slideIn 0.3s ease-out;
            }
            .message-bubble:hover {
                background: rgba(147, 51, 234, 0.15);
            }
            @keyframes slideIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .security-alert {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 8px;
                padding: 6px 10px;
                margin: 2px 0;
                font-size: 0.8rem;
                animation: slideIn 0.3s ease-out;
            }
            .sidebar {
                background: rgba(0, 0, 0, 0.3);
                backdrop-filter: blur(10px);
                border-right: 1px solid rgba(255, 255, 255, 0.1);
                max-height: calc(100vh - 120px);
                overflow-y: auto;
            }
            .main-area {
                background: rgba(0, 0, 0, 0.2);
                backdrop-filter: blur(5px);
                height: calc(100vh - 120px);
                min-height: 600px;
            }
            .main-area > * {
                height: 100%;
            }
            .control-button {
                transition: all 0.3s ease;
                border-radius: 8px;
            }
            .control-button:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            .scroll-container {
                scrollbar-width: thin;
                scrollbar-color: rgba(255, 255, 255, 0.3) transparent;
            }
            .scroll-container::-webkit-scrollbar {
                width: 6px;
            }
            .scroll-container::-webkit-scrollbar-track {
                background: transparent;
            }
            .scroll-container::-webkit-scrollbar-thumb {
                background-color: rgba(255, 255, 255, 0.3);
                border-radius: 3px;
            }
            .scroll-container::-webkit-scrollbar-thumb:hover {
                background-color: rgba(255, 255, 255, 0.5);
            }
            
            /* Enhanced three-column layout styles */
            .three-column-header {
                background: linear-gradient(90deg, rgba(255,255,255,0.05) 0%, transparent 100%);
                transition: background 0.3s ease;
            }
            .three-column-header:hover {
                background: linear-gradient(90deg, rgba(255,255,255,0.08) 0%, transparent 100%);
            }
            .column-divider {
                border-right: 1px solid rgba(255,255,255,0.15);
            }
            .main-column {
                min-width: 0;
                display: flex;
                flex-direction: column;
                height: 100%;
            }
            .side-column {
                min-width: 250px;
                max-width: 350px;
            }
            .enhanced-card {
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid rgba(100, 116, 139, 0.3);
                border-radius: 8px;
                transition: all 0.3s ease;
            }
            .enhanced-card:hover {
                background: rgba(15, 23, 42, 0.8);
                border-color: rgba(100, 116, 139, 0.5);
            }
            .section-header {
                background: linear-gradient(90deg, rgba(59, 130, 246, 0.2), rgba(147, 51, 234, 0.2));
                border-radius: 6px;
                padding: 8px 12px;
                margin-bottom: 8px;
            }
        </style>
        """)
        
        with ui.column().classes('w-full h-screen server-bg'):
            # Compact header like Telegram
            with ui.row().classes('w-full glass-card m-2 p-3 items-center gap-4'):
                with ui.row().classes('header-gradient items-center gap-3'):
                    ui.icon('storage').classes('text-white text-xl')
                    ui.label('TeleChat Server').classes('text-white font-bold text-lg')
                
                ui.separator().props('vertical').classes('h-6')
                
                # Compact controls
                self.host_input = ui.input('Host', value='localhost').classes('w-28').props('dense outlined')
                self.port_input = ui.input('Port', value='12345').classes('w-20').props('dense outlined')
                
                self.start_button = ui.button('Start', on_click=self.start_server).classes('control-button').props('color=positive dense')
                self.stop_button = ui.button('Stop', on_click=self.stop_server).classes('control-button').props('color=negative dense')
                self.stop_button.disable()
                
                ui.space()
                
                # Status indicator
                self.server_status = ui.label('Offline').classes('status-offline')
            
            # Main interface - Telegram-style layout
            with ui.row().classes('w-full flex-1 gap-2 p-2'):
                # Left sidebar - wider for better content display
                with ui.column().classes('w-80 sidebar glass-card p-4 gap-4'):
                    # Server metrics
                    ui.label('Server Status').classes('text-white font-semibold mb-2')
                    self.server_info = ui.column().classes('gap-2')
                    
                    ui.separator().classes('my-3')
                    
                    # Users section
                    ui.label('Online Users').classes('text-white font-semibold mb-2')
                    with ui.scroll_area().classes('h-32 scroll-container'):
                        self.users_list = ui.column().classes('gap-1')
                    
                    ui.separator().classes('my-3')
                    
                    # Admin controls
                    ui.label('Admin Panel').classes('text-white font-semibold mb-2')
                    with ui.column().classes('gap-2 w-full'):
                        self.kick_input = ui.input('Username to kick').classes('w-full').props('outlined dense')
                        ui.button('🚫 Kick User', on_click=self.kick_user).classes('w-full').props('color=warning')
                    
                    ui.separator().classes('my-3')
                
                # Main area - three columns side by side with optimized proportions
                with ui.row().classes('flex-1 main-area glass-card gap-3 h-full'):
                    # Live Chat Monitor - left column, wider for main focus (50% width)
                    with ui.column().classes('flex-2 column-divider main-column'):
                        # Messages header - clean professional design
                        with ui.row().classes('p-3 border-b border-gray-600 items-center gap-3 three-column-header'):
                            ui.icon('forum').classes('text-purple-400 text-xl')
                            with ui.column().classes('gap-0 flex-1'):
                                ui.label('Live Chat Monitor').classes('text-white font-bold text-lg')
                                ui.label('Real-time message monitoring').classes('text-gray-400 text-xs')
                            self.message_count_label = ui.label('0 messages').classes('text-gray-300 text-xs font-medium px-2 py-1 bg-gray-700/50 rounded')
                        
                        # Messages area - full height with proper scrolling and styling
                        self.messages_scroll = ui.scroll_area().classes('flex-1 px-4 py-3 scroll-container')
                        with self.messages_scroll:
                            self.messages_area = ui.column().classes('gap-3')
                            
                            # Initial welcome message
                            with ui.row().classes('justify-center p-8'):
                                with ui.column().classes('items-center gap-3'):
                                    ui.icon('chat').classes('text-gray-500 text-4xl')
                                    ui.label('Chat Monitor Ready').classes('text-gray-400 text-lg font-medium')
                                    ui.label('Messages will appear here when users connect').classes('text-gray-500 text-sm')
                    
                    # Security Events - middle column (25% width)
                    with ui.column().classes('flex-1 column-divider side-column'):
                        with ui.row().classes('p-3 border-b border-gray-600 items-center gap-2 three-column-header'):
                            ui.icon('security').classes('text-red-400 text-lg')
                            with ui.column().classes('gap-0'):
                                ui.label('Security Events').classes('text-white font-semibold text-base')
                                ui.label('Real-time monitoring').classes('text-gray-400 text-xs')
                        with ui.scroll_area().classes('flex-1 px-3 py-2 scroll-container'):
                            self.security_events = ui.column().classes('gap-2')
                    
                    # Security Dashboard - right column (25% width)
                    with ui.column().classes('flex-1 side-column'):
                        with ui.row().classes('p-3 border-b border-gray-600 items-center gap-2 three-column-header'):
                            ui.icon('shield').classes('text-blue-400 text-lg')
                            with ui.column().classes('gap-0'):
                                ui.label('Security Dashboard').classes('text-white font-semibold text-base')
                                ui.label('Security metrics').classes('text-gray-400 text-xs')
                        with ui.scroll_area().classes('flex-1 px-3 py-2 scroll-container'):
                            self.metrics_display = ui.column().classes('gap-2')
        
        # Initialize
        self.update_server_info()
        self.add_security_event("Security system online")
        self.add_security_event("Server ready to start")
    
    def start_server(self):
        """Start the server"""
        try:
            host = self.host_input.value or 'localhost'
            port = int(self.port_input.value or '12345')
            
            self.server = SecureChatServer(host, port)
            self.server.gui = self # type: ignore
            
            self.server_thread = threading.Thread(target=self.server.start_server, daemon=True)
            self.server_thread.start()
            
            self.start_button.disable()
            self.stop_button.enable()
            self.host_input.disable()
            self.port_input.disable()
            
            ui.notify(f'Server started on {host}:{port}', type='positive')
            self.add_security_event(f"✅ Server started on {host}:{port}")
            
            # Start periodic updates
            ui.timer(3.0, self.update_displays)
            
        except Exception as e:
            ui.notify(f'Failed to start server: {e}', type='negative')
            self.add_security_event(f"❌ Server start failed: {e}")
    
    def stop_server(self):
        """Stop the server"""
        if self.server:
            self.server.stop_server()
            self.server = None
        
        self.start_button.enable()
        self.stop_button.disable()
        self.host_input.enable()
        self.port_input.enable()
        
        ui.notify('Server stopped', type='info')
        self.add_security_event("⏹️ Server stopped")
        self.update_server_info()
    
    def kick_user(self):
        """Kick a user"""
        username = self.kick_input.value
        if username and self.server:
            if self.server.kick_user_secure(username):
                ui.notify(f'User {username} kicked', type='info')
                self.add_security_event(f"🚫 Kicked user: {username}")
                self.kick_input.value = ""
                self.update_server_info()
            else:
                ui.notify(f'Failed to kick {username}', type='warning')
    
    def update_displays(self):
        """Update all displays"""
        self.update_server_info()
        self.update_security_metrics()
    
    def update_server_info(self):
        """Update server information - enhanced layout"""
        self.server_info.clear()
        self.users_list.clear()
        
        with self.server_info:
            if self.server and self.server.running:
                # Update status badge
                self.server_status.text = "Online"
                self.server_status.classes(replace='status-offline status-online')
                
                uptime = datetime.now() - self.server.start_time if self.server.start_time else None
                
                # Server status section
                with ui.card().classes('w-full enhanced-card p-3'):
                    ui.label("🌐 Server Status").classes('section-header font-bold text-blue-300 text-sm mb-2')
                    
                    with ui.row().classes('metric-item items-center gap-3'):
                        ui.icon('dns').classes('text-blue-400 text-lg')
                        with ui.column().classes('gap-0'):
                            ui.label("Address").classes('text-gray-400 text-xs')
                            ui.label(f"{self.server.host}:{self.server.port}").classes('text-white text-sm font-mono')
                    
                    if uptime:
                        with ui.row().classes('metric-item items-center gap-3'):
                            ui.icon('schedule').classes('text-green-400 text-lg')
                            with ui.column().classes('gap-0'):
                                ui.label("Uptime").classes('text-gray-400 text-xs')
                                ui.label(f"{str(uptime).split('.')[0]}").classes('text-white text-sm')
                
                # Statistics section
                with ui.card().classes('w-full enhanced-card p-3 mt-2'):
                    ui.label("📊 Statistics").classes('section-header font-bold text-purple-300 text-sm mb-2')
                    
                    with ui.row().classes('metric-item items-center gap-3'):
                        ui.icon('people').classes('text-cyan-400 text-lg')
                        with ui.column().classes('gap-0'):
                            ui.label("Connected Users").classes('text-gray-400 text-xs')
                            ui.label(f"{len(self.server.user_manager.get_users())}").classes('text-white text-sm font-bold')
                    
                    with ui.row().classes('metric-item items-center gap-3'):
                        ui.icon('message').classes('text-purple-400 text-lg')
                        with ui.column().classes('gap-0'):
                            ui.label("Messages Processed").classes('text-gray-400 text-xs')
                            ui.label(f"{self.server.message_count}").classes('text-white text-sm font-bold')
                    
                    with ui.row().classes('metric-item items-center gap-3'):
                        ui.icon('security').classes('text-orange-400 text-lg')
                        with ui.column().classes('gap-0'):
                            ui.label("Active Sessions").classes('text-gray-400 text-xs')
                            ui.label(f"{len(self.server.user_sessions)}").classes('text-white text-sm font-bold')
            else:
                # Update status badge
                self.server_status.text = "Offline"
                self.server_status.classes(replace='status-online status-offline')
                
                with ui.card().classes('w-full enhanced-card p-4'):
                    with ui.row().classes('items-center gap-3 justify-center'):
                        ui.icon('power_settings_new').classes('text-gray-500 text-2xl')
                        with ui.column().classes('gap-1'):
                            ui.label("Server Offline").classes('text-gray-400 text-lg font-bold')
                            ui.label("Click Start to begin").classes('text-gray-500 text-sm')
        
        # Enhanced users list
        with self.users_list:
            if self.server:
                users = self.server.user_manager.get_users()
                if users:
                    for i, user in enumerate(users):
                        with ui.row().classes('user-badge items-center gap-3 w-full'):
                            ui.icon('person').classes('text-green-500 text-lg')
                            with ui.column().classes('flex-1 gap-0'):
                                ui.label(user).classes('text-white text-sm font-medium')
                                ui.label(f"User #{i+1}").classes('text-gray-400 text-xs')
                            ui.icon('circle').classes('text-green-400 text-xs animate-pulse')
                else:
                    with ui.row().classes('items-center gap-3 justify-center p-4'):
                        ui.icon('people_outline').classes('text-gray-500 text-xl')
                        ui.label("No users connected").classes('text-gray-400 text-sm italic')
            else:
                with ui.row().classes('items-center gap-3 justify-center p-4'):
                    ui.icon('cloud_off').classes('text-gray-500 text-xl')
                    ui.label("Server not running").classes('text-gray-400 text-sm italic')
    
    def update_security_metrics(self):
        """Update security metrics - comprehensive dashboard in main area"""
        if not hasattr(self, 'metrics_display'):
            return
            
        if not self.server or not self.server.running:
            self.metrics_display.clear()
            with self.metrics_display:
                with ui.column().classes('items-center gap-4 p-8'):
                    ui.icon('security_update_warning').classes('text-gray-500 text-3xl')
                    ui.label("Security Dashboard Offline").classes('text-gray-400 text-lg font-bold')
                    ui.label("Start the server to view security metrics").classes('text-gray-500 text-sm italic')
            return
            
        self.metrics_display.clear()
        
        try:
            report = self.server.get_security_report()
            metrics = report.get('metrics', {})
            rate_limit = report.get('rate_limit_status', {})
            
            with self.metrics_display:
                # Connection Security Section
                with ui.card().classes('w-full enhanced-card p-3 mb-2'):
                    ui.label("🔐 Connection Security").classes('font-bold text-blue-400 text-sm mb-2')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('verified_user').classes('text-green-400 text-sm')
                        ui.label(f"Active Sessions: {report.get('active_sessions', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('group').classes('text-cyan-400 text-sm')
                        ui.label(f"Total Connections: {metrics.get('total_connections', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('login').classes('text-green-400 text-sm')
                        ui.label(f"Successful Logins: {metrics.get('successful_logins', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('error').classes('text-red-400 text-sm')
                        ui.label(f"Failed Logins: {metrics.get('failed_logins', 0)}").classes('text-white text-sm')
                
                # Message Security Section
                with ui.card().classes('w-full enhanced-card p-3 mb-2'):
                    ui.label("🔒 Message Security").classes('font-bold text-purple-400 text-sm mb-2')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('lock').classes('text-green-400 text-sm')
                        ui.label(f"Encrypted Messages: {metrics.get('messages_encrypted', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('attach_file').classes('text-blue-400 text-sm')
                        ui.label(f"File Uploads: {metrics.get('file_uploads', 0)}").classes('text-white text-sm')
                
                # Threat Protection Section
                with ui.card().classes('w-full enhanced-card p-3 mb-2'):
                    ui.label("🛡️ Threat Protection").classes('font-bold text-red-400 text-sm mb-2')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('block').classes('text-red-400 text-sm')
                        ui.label(f"Blocked Attempts: {metrics.get('blocked_attempts', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('warning').classes('text-yellow-400 text-sm')
                        ui.label(f"Security Violations: {metrics.get('security_violations', 0)}").classes('text-white text-sm')
                    
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('network_check').classes('text-orange-400 text-sm')
                        ui.label(f"Tracked IPs: {rate_limit.get('total_tracked_ips', 0)}").classes('text-white text-sm')
                    
                    blocked_ips = len(rate_limit.get('currently_blocked_ips', []))
                    with ui.row().classes('metric-item items-center gap-2'):
                        ui.icon('gpp_bad').classes('text-red-500 text-sm')
                        ui.label(f"Blocked IPs: {blocked_ips}").classes('text-white text-sm')
                
                # Status indicator
                with ui.row().classes('justify-center mt-2'):
                    ui.label(f"Last Updated: {datetime.now().strftime('%H:%M:%S')}").classes('text-xs text-gray-500')
                    
        except Exception as e:
            with self.metrics_display:
                with ui.card().classes('w-full enhanced-card p-4'):
                    with ui.row().classes('items-center gap-3'):
                        ui.icon('error_outline').classes('text-red-400 text-lg')
                        with ui.column().classes('gap-1'):
                            ui.label("Metrics Error").classes('text-red-300 text-base font-bold')
                            ui.label(f"Details: {str(e)[:60]}...").classes('text-red-300 text-xs')
    
    def add_security_event(self, event):
        """Add security event - enhanced styling with icons"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Determine event type and icon
        icon_name = 'warning'
        color_class = 'text-red-400'
        
        if "✅" in event or "started" in event.lower():
            icon_name = 'check_circle'
            color_class = 'text-green-400'
        elif "⏹️" in event or "stopped" in event.lower():
            icon_name = 'stop_circle'
            color_class = 'text-orange-400'
        elif "🚫" in event or "kicked" in event.lower():
            icon_name = 'block'
            color_class = 'text-red-500'
        elif "❌" in event or "failed" in event.lower():
            icon_name = 'error'
            color_class = 'text-red-600'
        elif "online" in event.lower() or "ready" in event.lower():
            icon_name = 'security'
            color_class = 'text-blue-400'
        
        with self.security_events:
            with ui.row().classes('security-alert items-start gap-3 w-full'):
                ui.icon(icon_name).classes(f'{color_class} text-sm mt-0.5')
                with ui.column().classes('flex-1 gap-0'):
                    with ui.row().classes('items-center gap-2'):
                        ui.label(f"[{timestamp}]").classes('text-gray-500 text-xs font-mono')
                        ui.label("SECURITY").classes('px-2 py-0.5 bg-red-900 text-red-200 text-xs rounded font-bold')
                    ui.label(event).classes('text-gray-200 text-sm leading-tight')
    
    def update_message_display(self, message):
        """Display new message - Enhanced Telegram style bubbles"""
        timestamp = message.timestamp.strftime("%H:%M:%S")
        
        # Update message counter
        if hasattr(self, 'message_count_label'):
            count = self.server.message_count if self.server else 0
            self.message_count_label.text = f"{count} messages"
        
        with self.messages_area:
            with ui.row().classes('message-bubble items-start gap-4 w-full'):
                # Enhanced message type icon with better styling
                icon_container = ui.column().classes('items-center gap-1')
                with icon_container:
                    if message.msg_type == "file":
                        ui.icon('attach_file').classes('text-blue-400 text-xl p-2 rounded-full bg-blue-900/30')
                        ui.label("FILE").classes('text-blue-300 text-xs font-bold')
                    elif message.msg_type == "system":
                        ui.icon('admin_panel_settings').classes('text-yellow-400 text-xl p-2 rounded-full bg-yellow-900/30')
                        ui.label("SYS").classes('text-yellow-300 text-xs font-bold')
                    else:
                        ui.icon('chat_bubble').classes('text-green-400 text-xl p-2 rounded-full bg-green-900/30')
                        ui.label("MSG").classes('text-green-300 text-xs font-bold')
                
                # Enhanced message content with better typography
                with ui.column().classes('flex-1 gap-2'):
                    # Message header with improved styling
                    with ui.row().classes('items-center gap-3'):
                        ui.label(message.sender).classes('font-bold text-white text-base')
                        ui.separator().props('vertical').classes('h-4')
                        ui.label(timestamp).classes('text-gray-400 text-sm font-mono')
                        
                        # Enhanced type badges
                        if message.msg_type == "file":
                            ui.chip("📎 FILE SHARE", color="blue").props('size=sm')
                        elif message.msg_type == "system":
                            ui.chip("⚙️ SYSTEM", color="orange").props('size=sm')
                        else:
                            ui.chip("💬 MESSAGE", color="green").props('size=sm')
                    
                    # Message content with better formatting
                    with ui.card().classes('w-full bg-gray-800/50 border border-gray-700'):
                        ui.label(message.content).classes('text-white text-sm leading-relaxed break-words p-3')
                    
                    # Additional file info if applicable
                    if message.msg_type == "file" and hasattr(message, 'file_data') and message.file_data:
                        file_data = message.file_data
                        with ui.row().classes('items-center gap-2 text-blue-300 text-xs'):
                            ui.icon('info').classes('text-blue-400')
                            ui.label(f"Size: {file_data.get('size', 'Unknown')} bytes")
                            ui.label(f"Type: {file_data.get('type', 'Unknown')}")
        
        # Auto-scroll to bottom for new messages with smooth animation
        if hasattr(self, 'messages_scroll'):
            ui.run_javascript('''
                setTimeout(() => { 
                    const scrollArea = document.querySelector(".q-scrollarea__container");
                    if (scrollArea) {
                        scrollArea.scrollTo({
                            top: scrollArea.scrollHeight,
                            behavior: 'smooth'
                        });
                    }
                }, 150);
            ''')


# Create and run the app
@ui.page('/')
def main():
    server_gui = CleanServerGUI()


if __name__ == "__main__":
    app.title = "TeleChat Secure Server"
    ui.run(
        title="TeleChat Secure Server",
        native=True,
        window_size=(1400, 900),
        reload=False,
        show=False
    )
