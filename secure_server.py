"""
Enhanced Chat Server with Advanced Security
Integrates all advanced security features into the main server
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from chat_core import (
    Message, MessageQueue, UserManager, 
    FileManager, ChatHistory
)
from advanced_security_fixed import (
    AdvancedSecurityManager, SECURITY_CONFIG
)

if TYPE_CHECKING:
    from __main__ import SecureServerGUI


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
        self.file_manager = FileManager("server_files")
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
        self.gui: Optional['SecureServerGUI'] = None
        
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
            
            client_encryption_type = "hybrid"  # Default to hybrid
            
            try:
                # Try hybrid encryption first (for advanced clients)
                decrypted_data = self.security_manager.hybrid_crypto.decrypt_message(
                    json.loads(data)
                )
                username_data = json.loads(decrypted_data)
                username = username_data.get("username", "").strip()
                client_encryption_type = "hybrid"
            except:
                try:
                    # Fallback to Fernet decryption for standard clients
                    from chat_core import SecurityManager
                    basic_security = SecurityManager()
                    decrypted_data = basic_security.decrypt_message(data)
                    username_data = json.loads(decrypted_data)
                    username = username_data.get("username", "").strip()
                    client_encryption_type = "basic"
                except:
                    # Final fallback to plain JSON (unencrypted)
                    username_data = json.loads(data)
                    username = username_data.get("username", "").strip()
                    client_encryption_type = "none"
            
            # Track client encryption type
            self.client_encryption_types[client_socket] = client_encryption_type
            print(f"Client {username} using {client_encryption_type} encryption")
            
            # Log detailed security info
            if self.gui:
                if client_encryption_type == "hybrid":
                    self.gui.add_security_event(f"🔐 {username}: HYBRID encryption (RSA+AES)", "INFO")
                elif client_encryption_type == "basic":
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
                self.gui.add_security_event(f"User {username} authenticated successfully")
            
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
            
            client_socket.close()
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
    
    def _process_secure_client_message(self, username, data, session_id, client_socket):
        """Process client message with security validation"""
        try:
            # Decrypt message
            try:
                # Try hybrid decryption first
                decrypted_data = self.security_manager.hybrid_crypto.decrypt_message(
                    json.loads(data.decode())
                )
            except:
                # Fallback to basic decryption for compatibility
                from chat_core import SecurityManager
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
                # Handle secure file sharing
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
                
                # Log successful file validation
                if self.gui:
                    self.gui.add_security_event(f"📁 {username}: File {filename} ({file_size} bytes) validated", "INFO")
                
                try:
                    # Save file on server
                    saved_path = self.file_manager.decode_file(file_data)
                    message = Message(
                        sender=username,
                        content=f"📎 Shared secure file: {filename}",
                        msg_type="file",
                        file_data=file_data
                    )
                except Exception as e:
                    error_msg = {
                        "type": "error",
                        "content": f"🚫 Secure file sharing failed: {str(e)}"
                    }
                    self._send_message_to_client(client_socket, error_msg)
                    return
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
        encryption_type = self.client_encryption_types.get(client_socket, "hybrid")
        use_basic = (encryption_type == "basic")
        self._send_secure_message(client_socket, data, use_basic_encryption=use_basic)
    
    def _send_secure_message(self, client_socket, data, use_basic_encryption=False):
        """Send encrypted message to client"""
        try:
            json_data = json.dumps(data)
            
            if use_basic_encryption:
                # Use Fernet encryption for standard clients
                from chat_core import SecurityManager
                basic_security = SecurityManager()
                encrypted_data = basic_security.encrypt_message(json_data)
                client_socket.send(encrypted_data.encode())
            else:
                # Use hybrid encryption for enhanced security
                encrypted_data = self.security_manager.hybrid_crypto.encrypt_message(json_data)
                # Send as JSON string
                client_socket.send(json.dumps(encrypted_data).encode())
            
        except Exception as e:
            print(f"Error sending secure message: {e}")
    
    def get_security_report(self):
        """Get comprehensive security report"""
        return self.security_manager.get_security_report()
    
    def kick_user_secure(self, username):
        """Securely kick a user with audit logging"""
        if not username or username.strip() == "":
            print("❌ Cannot kick: Empty username")
            return False
            
        # Debug: Show current users
        available_users = self.user_manager.get_users()
        print(f"🔍 Debug - Current users: {available_users}")
        print(f"🔍 Debug - Trying to kick: '{username}'")
        
        # Check if user exists
        if not self.user_manager.user_exists(username):
            print(f"❌ Cannot kick {username}: User not found in user manager")
            print(f"Available users: {available_users}")
            return False
            
        user_socket = self.user_manager.get_user_socket(username)
        if not user_socket:
            print(f"❌ Cannot kick {username}: User socket not found")
            return False
            
        try:
            # Log security action
            self.security_manager.audit_logger.log_security_event(
                "USER_KICKED", username, "Admin action", "WARNING"
            )
            
            kick_msg = {
                "type": "kicked",
                "content": "🚫 You have been kicked from the secure server."
            }
            
            # Send kick message
            self._send_message_to_client(user_socket, kick_msg)
            
            # Give a moment for the message to be sent
            import time
            time.sleep(0.1)
            
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
                self.security_manager.session_manager.invalidate_session(session_id)
                del self.user_sessions[username]
            
            # Notify other users
            kick_message = Message(
                sender="🔒 SecureSystem",
                content=f"{username} was kicked from the server",
                msg_type="system"
            )
            self.message_queue.put(kick_message)
            
            print(f"✅ Successfully kicked user: {username}")
            print(f"🔍 Users after kick: {self.user_manager.get_users()}")
            return True
            
        except Exception as e:
            print(f"❌ Error kicking user {username}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop_server(self):
        """Stop server securely"""
        self.running = False
        
        # Log server shutdown
        self.security_manager.audit_logger.log_security_event(
            "SERVER_SHUTDOWN", "Admin", "Manual shutdown", "INFO"
        )
        
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


class SecureServerGUI:
    """Enhanced GUI for secure server with security monitoring"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 Advanced Secure Chat Server")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1a1a1a")
        
        self.server = None
        self.server_thread = None
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup enhanced GUI with security monitoring"""
        # Title with security indicator
        title_label = tk.Label(
            self.root,
            text="🔒 Advanced Secure Chat Server",
            font=("Arial", 16, "bold"),
            bg="#1a1a1a",
            fg="#00ff00"
        )
        title_label.pack(pady=10)
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Left panel - Server controls and info
        left_panel = tk.Frame(main_frame, bg="#2d2d2d", width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 5))
        left_panel.pack_propagate(False)
        
        # Server controls
        self.setup_server_controls(left_panel)
        
        # Security monitoring
        self.setup_security_monitoring(left_panel)
        
        # Right panel - Messages and users
        right_panel = tk.Frame(main_frame, bg="#2d2d2d")
        right_panel.pack(side="right", fill="both", expand=True)
        
        self.setup_message_monitoring(right_panel)
    
    def setup_server_controls(self, parent):
        """Setup server control panel"""
        controls_frame = tk.LabelFrame(
            parent,
            text="🔧 Server Controls",
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Arial", 10, "bold")
        )
        controls_frame.pack(fill="x", padx=5, pady=5)
        
        # Configuration
        config_frame = tk.Frame(controls_frame, bg="#2d2d2d")
        config_frame.pack(fill="x", pady=5)
        
        tk.Label(config_frame, text="Host:", bg="#2d2d2d", fg="#ffffff").grid(row=0, column=0, sticky="w", padx=5)
        self.host_entry = tk.Entry(config_frame, width=15, bg="#404040", fg="#ffffff")
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(config_frame, text="Port:", bg="#2d2d2d", fg="#ffffff").grid(row=0, column=2, sticky="w", padx=5)
        self.port_entry = tk.Entry(config_frame, width=10, bg="#404040", fg="#ffffff")
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=0, column=3, padx=5)
        
        # Control buttons
        button_frame = tk.Frame(controls_frame, bg="#2d2d2d")
        button_frame.pack(fill="x", pady=5)
        
        self.start_button = tk.Button(
            button_frame,
            text="🚀 Start Secure Server",
            command=self.start_server,
            bg="#00aa00",
            fg="white",
            font=("Arial", 10, "bold")
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="🛑 Stop Server",
            command=self.stop_server,
            bg="#aa0000",
            fg="white",
            font=("Arial", 10, "bold"),
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        # Server info
        info_frame = tk.LabelFrame(
            parent,
            text="� Advanced Security Server Information",
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Arial", 10, "bold")
        )
        info_frame.pack(fill="x", padx=5, pady=5)
        
        self.info_text = tk.Text(
            info_frame,
            height=6,
            bg="#1a1a1a",
            fg="#00ff00",
            state="disabled",
            font=("Courier", 9)
        )
        self.info_text.pack(fill="x", padx=5, pady=5)
    
    def setup_security_monitoring(self, parent):
        """Setup security monitoring panel"""
        security_frame = tk.LabelFrame(
            parent,
            text="🔒 Security Monitor",
            bg="#2d2d2d",
            fg="#ff6600",
            font=("Arial", 10, "bold")
        )
        security_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Security metrics
        metrics_frame = tk.Frame(security_frame, bg="#2d2d2d")
        metrics_frame.pack(fill="x", padx=5, pady=5)
        
        self.metrics_text = tk.Text(
            metrics_frame,
            height=8,
            bg="#1a1a1a",
            fg="#ff6600",
            state="disabled",
            font=("Courier", 9)
        )
        self.metrics_text.pack(fill="x")
        
        # Security events log
        events_frame = tk.Frame(security_frame, bg="#2d2d2d")
        events_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        tk.Label(events_frame, text="🔒 Security Events & Threat Detection:", bg="#2d2d2d", fg="#ff6600").pack(anchor="w")
        
        self.security_events = scrolledtext.ScrolledText(
            events_frame,
            bg="#1a1a1a",
            fg="#ff6600",
            state="disabled",
            wrap="word",
            font=("Courier", 8)
        )
        self.security_events.pack(fill="both", expand=True)
        
        # Add initial security status
        self.add_security_event("🔒 Advanced Security System Initialized", "INFO")
        self.add_security_event("🛡️ Rate Limiting: ACTIVE (30 req/min)", "INFO")
        self.add_security_event("🔐 Hybrid Encryption: RSA-2048 + AES-256", "INFO")
        self.add_security_event("📝 Audit Logging: ENABLED", "INFO")
        self.add_security_event("🚫 DoS Protection: ACTIVE", "INFO")
        self.add_security_event("🔍 Input Validation: STRICT MODE", "INFO")
    
    def setup_message_monitoring(self, parent):
        """Setup message monitoring panel"""
        # Connected users
        users_frame = tk.LabelFrame(
            parent,
            text="👥 Connected Users",
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Arial", 10, "bold")
        )
        users_frame.pack(fill="x", padx=5, pady=5)
        
        users_container = tk.Frame(users_frame, bg="#2d2d2d")
        users_container.pack(fill="x", padx=5, pady=5)
        
        self.users_listbox = tk.Listbox(
            users_container,
            bg="#1a1a1a",
            fg="#00ff00",
            height=4,
            font=("Courier", 9)
        )
        self.users_listbox.pack(side="left", fill="both", expand=True)
        
        users_scrollbar = tk.Scrollbar(users_container)
        users_scrollbar.pack(side="right", fill="y")
        
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)
        users_scrollbar.config(command=self.users_listbox.yview)
        
        # User management
        user_mgmt_frame = tk.Frame(users_frame, bg="#2d2d2d")
        user_mgmt_frame.pack(fill="x", padx=5, pady=5)
        
        kick_button = tk.Button(
            user_mgmt_frame,
            text="🚫 Kick Selected User",
            command=self.kick_selected_user,
            bg="#ff6600",
            fg="white",
            font=("Arial", 9)
        )
        kick_button.pack(side="left", padx=5)
        
        # Messages monitoring
        messages_frame = tk.LabelFrame(
            parent,
            text="💬 Server Messages",
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Arial", 10, "bold")
        )
        messages_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.messages_text = scrolledtext.ScrolledText(
            messages_frame,
            bg="#1a1a1a",
            fg="#00ff00",
            state="disabled",
            wrap="word",
            font=("Courier", 9)
        )
        self.messages_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def start_server(self):
        """Start the secure server"""
        try:
            host = self.host_entry.get().strip()
            port = int(self.port_entry.get().strip())
            
            self.server = SecureChatServer(host, port)
            self.server.gui = self
            
            self.server_thread = threading.Thread(
                target=self.server.start_server,
                daemon=True
            )
            self.server_thread.start()
            
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.host_entry.config(state="disabled")
            self.port_entry.config(state="disabled")
            
            self.add_server_message(f"🔒 Secure server started on {host}:{port}")
            self.add_security_event("Server started with enhanced security", "INFO")
            
            # Start updating security metrics
            self.update_security_metrics()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start secure server: {e}")
    
    def stop_server(self):
        """Stop the secure server"""
        if self.server:
            self.server.stop_server()
            self.server = None
        
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.host_entry.config(state="normal")
        self.port_entry.config(state="normal")
        
        self.add_server_message("🔒 Secure server stopped")
        self.add_security_event("Server stopped", "INFO")
    
    def kick_selected_user(self):
        """Kick selected user securely"""
        selection = self.users_listbox.curselection()
        if selection and self.server:
            # Get the display text and extract username
            display_text = self.users_listbox.get(selection[0])
            # Remove the 🔐 prefix if present
            username = display_text.replace("🔐 ", "")
            
            print(f"🔍 Debug - Display text: '{display_text}', Extracted username: '{username}'")
            
            if self.server.kick_user_secure(username):
                self.add_server_message(f"🚫 Kicked user: {username}")
                self.add_security_event(f"User {username} kicked by admin", "WARNING")
                self.update_server_info()
            else:
                messagebox.showwarning("Warning", f"Failed to kick user: {username}")
        else:
            messagebox.showinfo("Info", "Please select a user to kick")
    
    def update_server_info(self):
        """Update server information display"""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        
        if self.server and self.server.running and self.server.start_time:
            uptime = datetime.now() - self.server.start_time
            hybrid_clients = sum(1 for enc_type in self.server.client_encryption_types.values() if enc_type == "hybrid")
            basic_clients = sum(1 for enc_type in self.server.client_encryption_types.values() if enc_type == "basic")
            
            info = f"""🔒 ADVANCED SECURE SERVER STATUS
Status: RUNNING WITH MAXIMUM SECURITY
Host: {self.server.host}:{self.server.port}
Uptime: {str(uptime).split('.')[0]}
Connected Users: {len(self.server.user_manager.get_users())}
Total Messages: {self.server.message_count}
Active Sessions: {len(self.server.user_sessions)}

🔐 ENCRYPTION STATUS:
Hybrid Clients (RSA+AES): {hybrid_clients}
Basic Clients (Fernet): {basic_clients}

🛡️ SECURITY FEATURES:
✅ Rate Limiting Active
✅ DoS Protection Enabled  
✅ Input Validation Strict
✅ Session Management Active
✅ Audit Logging Enabled
✅ Message Authentication"""
        else:
            info = "🔒 SECURE SERVER STATUS\nStatus: STOPPED"
        
        self.info_text.insert(1.0, info)
        self.info_text.config(state="disabled")
        
        # Update users list
        self.users_listbox.delete(0, tk.END)
        if self.server:
            users = self.server.user_manager.get_users()
            for user in users:
                self.users_listbox.insert(tk.END, f"🔐 {user}")
    
    def update_security_metrics(self):
        """Update security metrics display"""
        if self.server and self.server.running:
            try:
                report = self.server.get_security_report()
                
                self.metrics_text.config(state="normal")
                self.metrics_text.delete(1.0, tk.END)
                
                # Get metrics data
                metrics = report.get('metrics', {})
                rate_info = report.get('rate_limit_status', {})
                blocked_ips = rate_info.get('currently_blocked_ips', [])
                tracked_ips = rate_info.get('total_tracked_ips', 0)
                
                # Get security components status
                components = report.get('security_components', {})
                active_components = sum(1 for status in components.values() if status == 'operational')
                
                # Get uptime
                uptime_seconds = report.get('uptime_seconds', 0)
                uptime_str = f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m"
                
                metrics_display = f"""🔒 SECURITY METRICS
Active Sessions: {report.get('active_sessions', 0)}
Total Connections: {metrics.get('total_connections', 0)}
Successful Logins: {metrics.get('successful_logins', 0)}
Failed Logins: {metrics.get('failed_logins', 0)}
Blocked Attempts: {metrics.get('blocked_attempts', 0)}
Security Violations: {metrics.get('security_violations', 0)}

� ENCRYPTION STATS:
Messages Encrypted: {metrics.get('messages_encrypted', 0)}
Messages Decrypted: {metrics.get('messages_decrypted', 0)}
File Uploads: {metrics.get('file_uploads', 0)}
File Downloads: {metrics.get('file_downloads', 0)}

🌐 NETWORK SECURITY:
Tracked IPs: {tracked_ips}
Currently Blocked: {len(blocked_ips)}
Active Threats: {metrics.get('active_threats', 0)}

🛡️ SYSTEM STATUS:
Security Level: {report.get('system_status', 'unknown').upper()}
Components: {active_components}/{len(components)} operational
Uptime: {uptime_str}
Last Updated: {datetime.now().strftime('%H:%M:%S')}"""
                
                if blocked_ips:
                    metrics_display += f"\n\n🚫 BLOCKED IPs:\n" + "\n".join(f"• {ip}" for ip in blocked_ips[:3])
                    if len(blocked_ips) > 3:
                        metrics_display += f"\n... and {len(blocked_ips) - 3} more"
                
                # Add last attack info if available
                last_attack = metrics.get('last_attack_time')
                if last_attack:
                    try:
                        if isinstance(last_attack, str):
                            attack_time = datetime.fromisoformat(last_attack.replace('Z', '+00:00'))
                        else:
                            attack_time = last_attack
                        time_since = datetime.now() - attack_time.replace(tzinfo=None)
                        metrics_display += f"\n\n⚠️ Last Attack: {int(time_since.total_seconds() // 60)}m ago"
                    except:
                        pass
                
                self.metrics_text.insert(1.0, metrics_display)
                self.metrics_text.config(state="disabled")
                
                # Schedule next update
                self.root.after(5000, self.update_security_metrics)
                
            except Exception as e:
                print(f"Error updating security metrics: {e}")
                # Show error in GUI
                try:
                    self.metrics_text.config(state="normal")
                    self.metrics_text.delete(1.0, tk.END)
                    self.metrics_text.insert(1.0, f"❌ Error loading metrics:\n{str(e)}")
                    self.metrics_text.config(state="disabled")
                except:
                    pass
    
    def add_security_event(self, event, level="INFO"):
        """Add security event to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        if level == "ERROR":
            color = "#ff0000"
        elif level == "WARNING":
            color = "#ff6600"
        else:
            color = "#00ff00"
        
        event_text = f"[{timestamp}] {level}: {event}\n"
        
        self.security_events.config(state="normal")
        self.security_events.insert(tk.END, event_text)
        self.security_events.see(tk.END)
        self.security_events.config(state="disabled")
    
    def update_message_display(self, message):
        """Update message display with security info"""
        timestamp = message.timestamp.strftime("%H:%M:%S")
        
        # Add security indicator
        security_icon = "🔒" if message.msg_type != "system" else "🔐"
        display_text = f"[{timestamp}] {security_icon} {message.sender}: {message.content}\n"
        
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, display_text)
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def add_server_message(self, message):
        """Add server message to display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        display_text = f"[{timestamp}] 🔒 SECURE-SERVER: {message}\n"
        
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, display_text)
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def run(self):
        """Start the secure GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window closing"""
        if self.server and self.server.running:
            self.stop_server()
        self.root.destroy()


if __name__ == "__main__":
    # Run secure server GUI
    print("🔒 Starting Advanced Secure Chat Server...")
    gui = SecureServerGUI()
    gui.run()
