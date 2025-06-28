"""
Advanced TCP Chat Server with GUI
Features: Multi-client support, File sharing, Encryption, Admin controls
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from datetime import datetime
from typing import Optional
from chat_core import (
    SecurityManager, Message, MessageQueue, UserManager, 
    FileManager, ChatHistory
)


class ChatServer:
    """Main server class handling client connections and message routing"""
    
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Core components
        self.security_manager = SecurityManager()
        self.user_manager = UserManager()
        self.file_manager = FileManager("server_files")
        self.chat_history = ChatHistory()
        self.message_queue = MessageQueue()
        
        # Server stats
        self.start_time = None
        self.message_count = 0
        
        # GUI reference
        self.gui: Optional['ServerGUI'] = None
        
    def start_server(self):
        """Start the server and begin accepting connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            self.start_time = datetime.now()
            
            print(f"Server started on {self.host}:{self.port}")
            
            # Start message processing thread
            threading.Thread(target=self._process_messages, daemon=True).start()
            
            # Accept connections
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"Connection attempt from {client_address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("Socket error occurred")
                    break
                    
        except Exception as e:
            print(f"Server error: {e}")
            self.running = False
    
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        username = None
        try:
            # Get username from client
            welcome_msg = {
                "type": "server_message",
                "content": "Welcome! Please send your username."
            }
            self._send_to_client(client_socket, welcome_msg)
            
            # Receive username
            data = client_socket.recv(1024).decode()
            if not data:
                return
                
            username_data = json.loads(data)
            username = username_data.get("username", "").strip()
            
            if not username or not self.user_manager.add_user(username, client_socket):
                error_msg = {
                    "type": "error",
                    "content": "Username already taken or invalid."
                }
                self._send_to_client(client_socket, error_msg)
                return
            
            # Send confirmation and user list
            success_msg = {
                "type": "login_success",
                "content": f"Welcome {username}!",
                "users": self.user_manager.get_users()
            }
            self._send_to_client(client_socket, success_msg)
            
            # Notify other users
            join_message = Message(
                sender="System",
                content=f"{username} joined the chat",
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
                    
                    # Decrypt and process message
                    encrypted_data = data.decode()
                    decrypted_data = self.security_manager.decrypt_message(encrypted_data)
                    message_data = json.loads(decrypted_data)
                    
                    self._process_client_message(username, message_data)
                    
                except socket.error:
                    break
                except Exception as e:
                    print(f"Error handling client {username}: {e}")
                    break
        
        except Exception as e:
            print(f"Client handling error: {e}")
        
        finally:
            # Clean up
            if username:
                self.user_manager.remove_user(username)
                
                # Notify other users
                leave_message = Message(
                    sender="System",
                    content=f"{username} left the chat",
                    msg_type="system"
                )
                self.message_queue.put(leave_message)
                self.chat_history.add_message(leave_message)
            
            client_socket.close()
            
            # Update GUI
            if self.gui:
                self.gui.update_server_info()
    
    def _process_client_message(self, username, message_data):
        """Process message from client"""
        msg_type = message_data.get("type", "text")
        content = message_data.get("content", "")
        
        if msg_type == "text":
            message = Message(sender=username, content=content, msg_type="text")
        elif msg_type == "file":
            # Handle file sharing
            file_data = message_data.get("file_data", {})
            try:
                # Save file on server
                saved_path = self.file_manager.decode_file(file_data)
                message = Message(
                    sender=username,
                    content=f"Shared file: {file_data['name']}",
                    msg_type="file",
                    file_data=file_data
                )
            except Exception as e:
                # Send error back to sender only
                error_msg = {
                    "type": "error",
                    "content": f"File sharing failed: {str(e)}"
                }
                user_socket = self.user_manager.get_user_socket(username)
                if user_socket:
                    self._send_to_client(user_socket, error_msg)
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
    
    def _process_messages(self):
        """Process messages from queue and broadcast to clients"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=1.0)
                self._broadcast_message(message)
            except:
                continue
    
    def _broadcast_message(self, message: Message):
        """Broadcast message to all connected clients"""
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
                        self._send_to_client(user_socket, message_data)
                    except:
                        # User disconnected, will be cleaned up
                        pass
    
    def _send_to_client(self, client_socket, data):
        """Send encrypted data to client"""
        try:
            json_data = json.dumps(data)
            encrypted_data = self.security_manager.encrypt_message(json_data)
            client_socket.send(encrypted_data.encode())
        except:
            pass
    
    def kick_user(self, username):
        """Kick a user from the server"""
        user_socket = self.user_manager.get_user_socket(username)
        if user_socket:
            kick_msg = {
                "type": "kicked",
                "content": "You have been kicked from the server."
            }
            self._send_to_client(user_socket, kick_msg)
            user_socket.close()
            self.user_manager.remove_user(username)
            
            # Notify other users
            kick_message = Message(
                sender="System",
                content=f"{username} was kicked from the server",
                msg_type="system"
            )
            self.message_queue.put(kick_message)
            return True
        return False
    
    def stop_server(self):
        """Stop the server gracefully"""
        self.running = False
        
        # Notify all users
        shutdown_msg = {
            "type": "server_shutdown",
            "content": "Server is shutting down."
        }
        
        users = self.user_manager.get_users()
        for username in users:
            user_socket = self.user_manager.get_user_socket(username)
            if user_socket:
                try:
                    self._send_to_client(user_socket, shutdown_msg)
                    user_socket.close()
                except:
                    pass
        
        if self.server_socket:
            self.server_socket.close()
        
        print("Server stopped")


class ServerGUI:
    """GUI for server administration"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Chat Server")
        self.root.geometry("800x600")
        self.root.configure(bg="#2c3e50")
        
        self.server = None
        self.server_thread = None
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI components"""
        # Title
        title_label = tk.Label(
            self.root,
            text="Advanced Chat Server",
            font=("Arial", 16, "bold"),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        title_label.pack(pady=10)
        
        # Server controls frame
        controls_frame = tk.Frame(self.root, bg="#34495e")
        controls_frame.pack(fill="x", padx=10, pady=5)
        
        # Server configuration
        config_frame = tk.Frame(controls_frame, bg="#34495e")
        config_frame.pack(fill="x", pady=5)
        
        tk.Label(config_frame, text="Host:", bg="#34495e", fg="#ecf0f1").pack(side="left")
        self.host_entry = tk.Entry(config_frame, width=15)
        self.host_entry.insert(0, "localhost")
        self.host_entry.pack(side="left", padx=5)
        
        tk.Label(config_frame, text="Port:", bg="#34495e", fg="#ecf0f1").pack(side="left")
        self.port_entry = tk.Entry(config_frame, width=10)
        self.port_entry.insert(0, "12345")
        self.port_entry.pack(side="left", padx=5)
        
        # Control buttons
        button_frame = tk.Frame(controls_frame, bg="#34495e")
        button_frame.pack(fill="x", pady=5)
        
        self.start_button = tk.Button(
            button_frame,
            text="Start Server",
            command=self.start_server,
            bg="#27ae60",
            fg="white",
            font=("Arial", 10, "bold")
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="Stop Server",
            command=self.stop_server,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 10, "bold"),
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        # Server info frame
        info_frame = tk.LabelFrame(
            self.root,
            text="Server Information",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 10, "bold")
        )
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.info_text = tk.Text(
            info_frame,
            height=4,
            bg="#2c3e50",
            fg="#ecf0f1",
            state="disabled"
        )
        self.info_text.pack(fill="x", padx=5, pady=5)
        
        # Connected users frame
        users_frame = tk.LabelFrame(
            self.root,
            text="Connected Users",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 10, "bold")
        )
        users_frame.pack(fill="x", padx=10, pady=5)
        
        # Users listbox with scrollbar
        users_list_frame = tk.Frame(users_frame, bg="#34495e")
        users_list_frame.pack(fill="x", padx=5, pady=5)
        
        self.users_listbox = tk.Listbox(
            users_list_frame,
            bg="#2c3e50",
            fg="#ecf0f1",
            height=6
        )
        self.users_listbox.pack(side="left", fill="both", expand=True)
        
        users_scrollbar = tk.Scrollbar(users_list_frame)
        users_scrollbar.pack(side="right", fill="y")
        
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)
        users_scrollbar.config(command=self.users_listbox.yview)
        
        # User management buttons
        user_buttons_frame = tk.Frame(users_frame, bg="#34495e")
        user_buttons_frame.pack(fill="x", padx=5, pady=5)
        
        kick_button = tk.Button(
            user_buttons_frame,
            text="Kick Selected User",
            command=self.kick_selected_user,
            bg="#f39c12",
            fg="white"
        )
        kick_button.pack(side="left", padx=5)
        
        # Messages frame
        messages_frame = tk.LabelFrame(
            self.root,
            text="Server Messages",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 10, "bold")
        )
        messages_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.messages_text = scrolledtext.ScrolledText(
            messages_frame,
            bg="#2c3e50",
            fg="#ecf0f1",
            state="disabled",
            wrap="word"
        )
        self.messages_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Update server info initially
        self.update_server_info()
    
    def start_server(self):
        """Start the server"""
        try:
            host = self.host_entry.get().strip()
            port = int(self.port_entry.get().strip())
            
            self.server = ChatServer(host, port)
            self.server.gui = self  # Set GUI reference
            
            self.server_thread = threading.Thread(
                target=self.server.start_server,
                daemon=True
            )
            self.server_thread.start()
            
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.host_entry.config(state="disabled")
            self.port_entry.config(state="disabled")
            
            self.add_server_message(f"Server started on {host}:{port}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
    
    def stop_server(self):
        """Stop the server"""
        if self.server:
            self.server.stop_server()
            self.server = None
        
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.host_entry.config(state="normal")
        self.port_entry.config(state="normal")
        
        self.add_server_message("Server stopped")
        self.update_server_info()
    
    def kick_selected_user(self):
        """Kick the selected user"""
        selection = self.users_listbox.curselection()
        if selection and self.server:
            username = self.users_listbox.get(selection[0])
            if self.server.kick_user(username):
                self.add_server_message(f"Kicked user: {username}")
                self.update_server_info()
            else:
                messagebox.showwarning("Warning", "Failed to kick user")
    
    def update_server_info(self):
        """Update server information display"""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        
        if self.server and self.server.running and self.server.start_time:
            uptime = datetime.now() - self.server.start_time
            info = f"""Status: Running
Host: {self.server.host}:{self.server.port}
Uptime: {str(uptime).split('.')[0]}
Connected Users: {len(self.server.user_manager.get_users())}
Total Messages: {self.server.message_count}"""
        else:
            info = "Status: Stopped"
        
        self.info_text.insert(1.0, info)
        self.info_text.config(state="disabled")
        
        # Update users list
        self.users_listbox.delete(0, tk.END)
        if self.server:
            users = self.server.user_manager.get_users()
            for user in users:
                self.users_listbox.insert(tk.END, user)
    
    def update_message_display(self, message):
        """Update message display"""
        timestamp = message.timestamp.strftime("%H:%M:%S")
        display_text = f"[{timestamp}] {message.sender}: {message.content}\n"
        
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, display_text)
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def add_server_message(self, message):
        """Add server message to display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        display_text = f"[{timestamp}] SERVER: {message}\n"
        
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, display_text)
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def run(self):
        """Start the GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window closing"""
        if self.server and self.server.running:
            self.stop_server()
        self.root.destroy()


if __name__ == "__main__":
    # Run server GUI
    gui = ServerGUI()
    gui.run()