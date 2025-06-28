"""
Advanced GUI Chat Client with File Sharing and Encryption
Features: Modern UI, File transfer, Message encryption, User management
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import os
from datetime import datetime
from chat_core import (
    SecurityManager, Message, FileManager
)
from PIL import Image, ImageTk
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from __main__ import ModernChatGUI


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
        
        # GUI reference
        self.gui: Optional['ModernChatGUI'] = None
        
        # Message handlers
        self.message_handlers = {
            "server_message": self._handle_server_message,
            "login_success": self._handle_login_success,
            "message": self._handle_message,
            "error": self._handle_error,
            "kicked": self._handle_kicked,
            "server_shutdown": self._handle_server_shutdown
        }
    
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
            listen_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
            listen_thread.start()
            
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.show_error(f"Connection failed: {e}")
            return False
    
    def _listen_for_messages(self):
        """Listen for incoming messages from server"""
        while self.connected and self.socket:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                # Decrypt message
                encrypted_data = data.decode()
                decrypted_data = self.security_manager.decrypt_message(encrypted_data)
                message_data = json.loads(decrypted_data)
                
                # Handle message based on type
                msg_type = message_data.get("type", "")
                handler = self.message_handlers.get(msg_type)
                if handler:
                    handler(message_data)
                
            except socket.error:
                break
            except Exception as e:
                print(f"Message handling error: {e}")
        
        self.connected = False
        if self.gui:
            self.gui.on_disconnected()
    
    def _handle_server_message(self, data):
        """Handle server messages"""
        if self.gui:
            self.gui.add_system_message(data["content"])
    
    def _handle_login_success(self, data):
        """Handle successful login"""
        if self.gui:
            self.gui.add_system_message(data["content"])
            self.gui.update_user_list(data.get("users", []))
            self.gui.on_connected()
    
    def _handle_message(self, data):
        """Handle chat messages"""
        message_data = data["data"]
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
            self.gui.show_error(data["content"])
            self.gui.disconnect()
    
    def _handle_server_shutdown(self, data):
        """Handle server shutdown"""
        if self.gui:
            self.gui.add_system_message(data["content"])
            self.gui.disconnect()
    
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
            
            # Display message locally
            if self.gui:
                message = Message(self.username, content, "text")
                self.gui.display_message(message)
            
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
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None


class ModernChatGUI:
    """Modern GUI for the chat client"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Chat Client")
        self.root.geometry("900x700")
        self.root.configure(bg="#2c3e50")
        
        # Color scheme
        self.colors = {
            "primary": "#3498db",
            "secondary": "#2c3e50",
            "accent": "#e74c3c",
            "success": "#27ae60",
            "warning": "#f39c12",
            "text": "#ecf0f1",
            "background": "#34495e",
            "chat_bg": "#2c3e50",
            "my_message": "#3498db",
            "other_message": "#95a5a6"
        }
        
        self.client = ChatClient()
        self.client.gui = self
        
        self.connected = False
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the main GUI components"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors["secondary"])
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Top frame for connection
        self.connection_frame = tk.Frame(main_frame, bg=self.colors["background"])
        self.connection_frame.pack(fill="x", pady=(0, 10))
        
        self.setup_connection_panel()
        
        # Chat area frame
        self.chat_frame = tk.Frame(main_frame, bg=self.colors["secondary"])
        self.chat_frame.pack(fill="both", expand=True)
        
        self.setup_chat_area()
        
        # Input frame
        self.input_frame = tk.Frame(main_frame, bg=self.colors["background"])
        self.input_frame.pack(fill="x", pady=(10, 0))
        
        self.setup_input_area()
        
        # Initially disable chat components
        self.set_chat_state(False)
    
    def setup_connection_panel(self):
        """Setup connection controls"""
        tk.Label(
            self.connection_frame,
            text="Advanced Chat Client",
            font=("Arial", 14, "bold"),
            bg=self.colors["background"],
            fg=self.colors["text"]
        ).pack(pady=5)
        
        # Connection controls
        conn_controls = tk.Frame(self.connection_frame, bg=self.colors["background"])
        conn_controls.pack(fill="x", padx=10, pady=5)
        
        # Host
        tk.Label(conn_controls, text="Host:", bg=self.colors["background"], 
                fg=self.colors["text"]).grid(row=0, column=0, sticky="w", padx=5)
        self.host_entry = tk.Entry(conn_controls, width=15)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        # Port
        tk.Label(conn_controls, text="Port:", bg=self.colors["background"], 
                fg=self.colors["text"]).grid(row=0, column=2, sticky="w", padx=5)
        self.port_entry = tk.Entry(conn_controls, width=10)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=0, column=3, padx=5)
        
        # Username
        tk.Label(conn_controls, text="Username:", bg=self.colors["background"], 
                fg=self.colors["text"]).grid(row=0, column=4, sticky="w", padx=5)
        self.username_entry = tk.Entry(conn_controls, width=15)
        self.username_entry.grid(row=0, column=5, padx=5)
        
        # Connect button
        self.connect_button = tk.Button(
            conn_controls,
            text="Connect",
            command=self.connect_to_server,
            bg=self.colors["success"],
            fg="white",
            font=("Arial", 10, "bold")
        )
        self.connect_button.grid(row=0, column=6, padx=10)
        
        # Disconnect button
        self.disconnect_button = tk.Button(
            conn_controls,
            text="Disconnect",
            command=self.disconnect,
            bg=self.colors["accent"],
            fg="white",
            font=("Arial", 10, "bold"),
            state="disabled"
        )
        self.disconnect_button.grid(row=0, column=7, padx=5)
        
        # Status label
        self.status_label = tk.Label(
            self.connection_frame,
            text="Status: Disconnected",
            bg=self.colors["background"],
            fg=self.colors["warning"],
            font=("Arial", 10)
        )
        self.status_label.pack(pady=5)
    
    def setup_chat_area(self):
        """Setup the main chat area"""
        # Left panel for chat
        left_panel = tk.Frame(self.chat_frame, bg=self.colors["secondary"])
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        # Chat messages area
        messages_frame = tk.LabelFrame(
            left_panel,
            text="Messages",
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Arial", 10, "bold")
        )
        messages_frame.pack(fill="both", expand=True, pady=(0, 5))
        
        # Messages display with custom styling
        self.messages_text = scrolledtext.ScrolledText(
            messages_frame,
            bg=self.colors["chat_bg"],
            fg=self.colors["text"],
            font=("Consolas", 10),
            state="disabled",
            wrap="word",
            padx=10,
            pady=10
        )
        self.messages_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configure text tags for different message types
        self.messages_text.tag_configure("my_message", 
                                        foreground=self.colors["my_message"],
                                        font=("Consolas", 10, "bold"))
        self.messages_text.tag_configure("other_message", 
                                        foreground=self.colors["other_message"])
        self.messages_text.tag_configure("system_message", 
                                        foreground=self.colors["warning"],
                                        font=("Consolas", 10, "italic"))
        self.messages_text.tag_configure("file_message", 
                                        foreground=self.colors["success"],
                                        font=("Consolas", 10, "bold"))
        self.messages_text.tag_configure("timestamp", 
                                        foreground="#7f8c8d",
                                        font=("Consolas", 8))
        
        # Right panel for users and controls
        right_panel = tk.Frame(self.chat_frame, bg=self.colors["secondary"], width=200)
        right_panel.pack(side="right", fill="y")
        right_panel.pack_propagate(False)
        
        # Online users
        users_frame = tk.LabelFrame(
            right_panel,
            text="Online Users",
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Arial", 10, "bold")
        )
        users_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Users listbox
        self.users_listbox = tk.Listbox(
            users_frame,
            bg=self.colors["chat_bg"],
            fg=self.colors["text"],
            font=("Arial", 10),
            selectbackground=self.colors["primary"]
        )
        self.users_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        # File sharing controls
        file_frame = tk.LabelFrame(
            right_panel,
            text="File Sharing",
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Arial", 10, "bold")
        )
        file_frame.pack(fill="x", padx=5, pady=5)
        
        self.share_file_button = tk.Button(
            file_frame,
            text="Share File",
            command=self.share_file,
            bg=self.colors["primary"],
            fg="white",
            font=("Arial", 9, "bold")
        )
        self.share_file_button.pack(fill="x", padx=5, pady=5)
        
        self.open_folder_button = tk.Button(
            file_frame,
            text="Open Downloads",
            command=self.open_downloads_folder,
            bg=self.colors["secondary"],
            fg=self.colors["text"],
            font=("Arial", 9)
        )
        self.open_folder_button.pack(fill="x", padx=5, pady=(0, 5))
        
        # Chat controls
        controls_frame = tk.LabelFrame(
            right_panel,
            text="Chat Controls",
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Arial", 10, "bold")
        )
        controls_frame.pack(fill="x", padx=5, pady=5)
        
        self.clear_chat_button = tk.Button(
            controls_frame,
            text="Clear Chat",
            command=self.clear_chat,
            bg=self.colors["warning"],
            fg="white",
            font=("Arial", 9)
        )
        self.clear_chat_button.pack(fill="x", padx=5, pady=5)
    
    def setup_input_area(self):
        """Setup message input area"""
        # Message input
        input_label = tk.Label(
            self.input_frame,
            text="Type your message:",
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Arial", 10)
        )
        input_label.pack(anchor="w", padx=5, pady=(5, 2))
        
        # Input controls frame
        input_controls = tk.Frame(self.input_frame, bg=self.colors["background"])
        input_controls.pack(fill="x", padx=5, pady=(0, 5))
        
        # Message entry
        self.message_entry = tk.Entry(
            input_controls,
            font=("Arial", 11),
            bg="white",
            fg="black"
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        # Send button
        self.send_button = tk.Button(
            input_controls,
            text="Send",
            command=self.send_message,
            bg=self.colors["primary"],
            fg="white",
            font=("Arial", 10, "bold"),
            width=8
        )
        self.send_button.pack(side="right")
    
    def connect_to_server(self):
        """Connect to the chat server"""
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        username = self.username_entry.get().strip()
        
        if not all([host, port, username]):
            self.show_error("Please fill in all connection fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            self.show_error("Port must be a number")
            return
        
        if self.client.connect_to_server(host, port, username):
            self.status_label.config(text="Status: Connecting...", fg=self.colors["warning"])
        else:
            self.status_label.config(text="Status: Connection Failed", fg=self.colors["accent"])
    
    def disconnect(self):
        """Disconnect from server"""
        self.client.disconnect()
        self.on_disconnected()
    
    def on_connected(self):
        """Handle successful connection"""
        self.connected = True
        self.set_chat_state(True)
        self.status_label.config(text="Status: Connected", fg=self.colors["success"])
        
        self.connect_button.config(state="disabled")
        self.disconnect_button.config(state="normal")
        self.host_entry.config(state="disabled")
        self.port_entry.config(state="disabled")
        self.username_entry.config(state="disabled")
        
        # Focus on message entry
        self.message_entry.focus()
    
    def on_disconnected(self):
        """Handle disconnection"""
        self.connected = False
        self.set_chat_state(False)
        self.status_label.config(text="Status: Disconnected", fg=self.colors["accent"])
        
        self.connect_button.config(state="normal")
        self.disconnect_button.config(state="disabled")
        self.host_entry.config(state="normal")
        self.port_entry.config(state="normal")
        self.username_entry.config(state="normal")
        
        # Clear users list
        self.users_listbox.delete(0, tk.END)
        
        # Add disconnection message
        self.add_system_message("Disconnected from server")
    
    def set_chat_state(self, enabled):
        """Enable or disable chat components"""
        state = "normal" if enabled else "disabled"
        
        self.message_entry.config(state=state)
        self.send_button.config(state=state)
        self.share_file_button.config(state=state)
        self.clear_chat_button.config(state=state)
    
    def send_message(self):
        """Send a text message"""
        message = self.message_entry.get().strip()
        if message and self.connected:
            if self.client.send_message(message):
                self.message_entry.delete(0, tk.END)
    
    def share_file(self):
        """Share a file"""
        if not self.connected:
            return
        
        file_path = filedialog.askopenfilename(
            title="Select file to share",
            filetypes=[
                ("All files", "*.*"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Documents", "*.pdf *.doc *.docx *.txt"),
                ("Archives", "*.zip *.rar *.7z")
            ]
        )
        
        if file_path:
            self.client.send_file(file_path)
    
    def open_downloads_folder(self):
        """Open the downloads folder"""
        downloads_path = self.client.file_manager.base_dir
        if os.path.exists(downloads_path):
            os.startfile(downloads_path)  # Windows
        else:
            self.show_error("Downloads folder does not exist yet")
    
    def clear_chat(self):
        """Clear chat messages"""
        self.messages_text.config(state="normal")
        self.messages_text.delete(1.0, tk.END)
        self.messages_text.config(state="disabled")
    
    def display_message(self, message: Message):
        """Display a message in the chat"""
        timestamp = message.timestamp.strftime("%H:%M:%S")
        
        self.messages_text.config(state="normal")
        
        # Add timestamp
        self.messages_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        # Add sender and message based on type
        if message.sender == self.client.username:
            self.messages_text.insert(tk.END, f"You: ", "my_message")
        else:
            self.messages_text.insert(tk.END, f"{message.sender}: ", "other_message")
        
        # Handle different message types
        if message.msg_type == "file":
            self.messages_text.insert(tk.END, message.content, "file_message")
            
            # Add download link for files
            if message.sender != self.client.username and message.file_data:
                try:
                    saved_path = self.client.file_manager.decode_file(message.file_data)
                    self.messages_text.insert(tk.END, f" (Saved to: {saved_path})", "system_message")
                except Exception as e:
                    self.messages_text.insert(tk.END, f" (Download failed: {e})", "system_message")
        else:
            # Regular text message
            tag = "my_message" if message.sender == self.client.username else "other_message"
            self.messages_text.insert(tk.END, message.content, tag)
        
        self.messages_text.insert(tk.END, "\n")
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def add_system_message(self, message):
        """Add a system message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.messages_text.config(state="normal")
        self.messages_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.messages_text.insert(tk.END, f"SYSTEM: {message}\n", "system_message")
        self.messages_text.see(tk.END)
        self.messages_text.config(state="disabled")
    
    def update_user_list(self, users):
        """Update the online users list"""
        self.users_listbox.delete(0, tk.END)
        for user in users:
            self.users_listbox.insert(tk.END, user)
    
    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.add_system_message(f"Error: {message}")
    
    def run(self):
        """Start the GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window closing"""
        if self.connected:
            self.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    # Run client GUI
    client_gui = ModernChatGUI()
    client_gui.run()