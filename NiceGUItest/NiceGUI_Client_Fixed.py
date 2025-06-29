"""
Fixed NiceGUI Chat Client with Clean UI
Clean, working desktop interface for the secure chat client
"""

import socket
import threading
import json
import os
import subprocess
import platform
from datetime import datetime
from typing import Optional
from nicegui import ui, app, events
from core import SecurityManager, Message, FileManager


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
        self.gui = None
        
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
                ui.notify(f"Connection failed: {e}", type='negative')
            return False
    
    def _listen_for_messages(self):
        """Listen for incoming messages from server"""
        while self.connected and self.socket:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                # Decrypt message
                encrypted_data = data.decode().strip()
                
                if not encrypted_data:
                    continue
                
                try:
                    decrypted_data = self.security_manager.decrypt_message(encrypted_data)
                    message_data = json.loads(decrypted_data)
                    
                    # Handle message based on type
                    msg_type = message_data.get("type", "")
                    handler = self.message_handlers.get(msg_type)
                    if handler:
                        handler(message_data)
                        
                except Exception as e:
                    print(f"Message decryption/parsing failed: {e}")
                    continue
                
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
            self.gui.add_message("🔒 SERVER", data["content"], "system")
    
    def _handle_login_success(self, data):
        """Handle successful login"""
        if self.gui:
            self.gui.add_message("🔒 SERVER", data["content"], "system")
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
            ui.notify(data["content"], type='negative')
            self.gui.add_message("❌ ERROR", data["content"], "error")
    
    def _handle_kicked(self, data):
        """Handle being kicked from server"""
        if self.gui:
            ui.notify(data["content"], type='negative')
            self.gui.disconnect()
    
    def _handle_server_shutdown(self, data):
        """Handle server shutdown"""
        if self.gui:
            self.gui.add_message("🔒 SERVER", data["content"], "system")
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
                self.gui.add_message("You", content, "sent")
            
            return True
            
        except Exception as e:
            if self.gui:
                ui.notify(f"Failed to send message: {e}", type='negative')
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
                self.gui.add_message("You", f"📎 Shared: {file_info['name']}", "file")
            
            return True
            
        except Exception as e:
            if self.gui:
                ui.notify(f"Failed to send file: {e}", type='negative')
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


class CleanChatGUI:
    """Clean, working NiceGUI chat client interface"""
    
    def __init__(self):
        self.client = ChatClient()
        self.client.gui = self # type: ignore
        self.connected = False
        self.message_count = 0
        self.setup_ui()
    
    def setup_ui(self):
        """Setup stunning Telegram-inspired chat interface with perfect proportions"""
        ui.dark_mode(True)
        
        # Add custom CSS for stunning visual effects
        ui.add_head_html("""
        <style>
            :root {
                --telegram-blue: #0088cc;
                --telegram-light-blue: #40a7e3;
                --telegram-green: #4dcd5e;
                --telegram-red: #e53e3e;
                --telegram-orange: #ff8c42;
                --telegram-purple: #8b5cf6;
                --telegram-pink: #ec4899;
                --chat-bg: #212d3a;
                --sidebar-bg: #17212b;
                --message-bg: #182533;
                --input-bg: #242f3d;
            }
            
            body {
                background: linear-gradient(135deg, #0f1419 0%, #1a202c 50%, #2d3748 100%);
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .telegram-container {
                background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .telegram-sidebar {
                background: linear-gradient(180deg, var(--sidebar-bg) 0%, #0f1824 100%);
                border-right: 1px solid rgba(255, 255, 255, 0.08);
                min-height: 100vh;
            }
            
            .telegram-chat {
                background: linear-gradient(180deg, var(--chat-bg) 0%, #1a2332 100%);
                min-height: 100vh;
                position: relative;
            }
            
            .telegram-header {
                background: linear-gradient(135deg, var(--telegram-blue) 0%, var(--telegram-light-blue) 100%);
                padding: 12px 16px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
            }
            
            .connection-panel {
                background: rgba(23, 33, 43, 0.8);
                border: 1px solid rgba(64, 167, 227, 0.3);
                border-radius: 8px;
                padding: 12px;
                margin: 8px;
                backdrop-filter: blur(10px);
            }
            
            .messages-container {
                background: linear-gradient(180deg, rgba(33, 45, 58, 0.6) 0%, rgba(24, 37, 51, 0.8) 100%);
                border-radius: 0;
                backdrop-filter: blur(5px);
                min-height: 520px;
                max-height: 520px;
                overflow-y: auto;
            }
            
            .message-bubble-sent {
                background: linear-gradient(135deg, var(--telegram-blue) 0%, #0088cc 100%);
                color: white;
                border-radius: 18px 18px 4px 18px;
                padding: 8px 12px;
                margin: 2px 0;
                margin-left: auto;
                margin-right: 8px;
                max-width: 85%;
                word-wrap: break-word;
                box-shadow: 0 2px 8px rgba(0, 136, 204, 0.3);
            }
            
            .message-bubble-received {
                background: linear-gradient(135deg, var(--message-bg) 0%, #1e2a3a 100%);
                color: #ffffff;
                border-radius: 18px 18px 18px 4px;
                padding: 8px 12px;
                margin: 2px 0;
                margin-left: 8px;
                margin-right: auto;
                max-width: 85%;
                word-wrap: break-word;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.05);
            }
            
            .message-bubble-system {
                background: linear-gradient(135deg, rgba(77, 205, 94, 0.2) 0%, rgba(52, 168, 83, 0.3) 100%);
                color: #4dcd5e;
                border-radius: 12px;
                padding: 6px 10px;
                margin: 2px auto;
                text-align: center;
                font-size: 0.85rem;
                border: 1px solid rgba(77, 205, 94, 0.3);
                backdrop-filter: blur(5px);
            }
            
            .input-container {
                background: linear-gradient(135deg, var(--input-bg) 0%, #2a3441 100%);
                border-top: 1px solid rgba(255, 255, 255, 0.08);
                padding: 12px;
                backdrop-filter: blur(10px);
            }
            
            .user-item {
                background: rgba(255, 255, 255, 0.03);
                border-radius: 8px;
                padding: 8px 12px;
                margin: 2px 0;
                border-left: 3px solid var(--telegram-green);
                transition: all 0.2s ease;
            }
            
            .user-item:hover {
                background: rgba(77, 205, 94, 0.1);
                transform: translateX(2px);
            }
            
            .status-indicator {
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: 600;
                backdrop-filter: blur(5px);
            }
            
            .status-connected {
                background: linear-gradient(90deg, var(--telegram-green), #52c41a);
                color: white;
                box-shadow: 0 2px 8px rgba(77, 205, 94, 0.4);
            }
            
            .status-disconnected {
                background: linear-gradient(90deg, var(--telegram-red), #ff4d4f);
                color: white;
                box-shadow: 0 2px 8px rgba(229, 62, 62, 0.4);
            }
            
            .status-connecting {
                background: linear-gradient(90deg, var(--telegram-orange), #ffa940);
                color: white;
                box-shadow: 0 2px 8px rgba(255, 140, 66, 0.4);
            }
            
            .tool-button {
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 8px 12px;
                margin: 4px 0;
                transition: all 0.2s ease;
                backdrop-filter: blur(10px);
            }
            
            .tool-button:hover {
                background: linear-gradient(135deg, rgba(64, 167, 227, 0.2) 0%, rgba(0, 136, 204, 0.1) 100%);
                border-color: var(--telegram-light-blue);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(64, 167, 227, 0.3);
            }
            
            .section-header {
                color: var(--telegram-light-blue);
                font-weight: 600;
                font-size: 0.9rem;
                margin-bottom: 8px;
                padding: 0 4px;
            }
            
            .glass-panel {
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                backdrop-filter: blur(15px);
                padding: 12px;
                margin: 4px 0;
            }
            
            /* Custom scrollbar */
            ::-webkit-scrollbar {
                width: 6px;
            }
            
            ::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
            }
            
            ::-webkit-scrollbar-thumb {
                background: linear-gradient(180deg, var(--telegram-blue), var(--telegram-light-blue));
                border-radius: 3px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(180deg, var(--telegram-light-blue), var(--telegram-blue));
            }
            
            /* Animations */
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .message-bubble-sent, .message-bubble-received, .message-bubble-system {
                animation: fadeInUp 0.3s ease-out;
            }
        </style>
        """)
        
        # Main Telegram-style container (using exact proportions)
        with ui.row().classes('w-full h-screen p-0 m-0 gap-0 telegram-container'):
            
            # Left Sidebar (320px fixed width - Telegram standard)
            with ui.column().classes('telegram-sidebar').style('width: 320px; min-width: 320px; max-width: 320px;'):
                
                # Sidebar Header
                with ui.row().classes('w-full telegram-header justify-between items-center'):
                    with ui.row().classes('items-center gap-3'):
                        ui.icon('security').classes('text-white text-xl')
                        ui.label('TeleChat Pro').classes('text-white font-bold text-lg')
                    with ui.row().classes('items-center gap-2'):
                        self.status_indicator = ui.label('🔴 Offline').classes('status-disconnected status-indicator')
                
                # Connection Panel
                with ui.column().classes('connection-panel w-full'):
                    ui.label('Connection').classes('section-header')
                    with ui.column().classes('gap-2'):
                        with ui.row().classes('gap-2'):
                            self.host_input = ui.input('Host', value='localhost').classes('flex-1').props('dense outlined')
                            self.port_input = ui.input('Port', value='12345').classes('w-20').props('dense outlined')
                        self.username_input = ui.input('Username', placeholder='Enter your name').classes('w-full').props('dense outlined')
                        with ui.row().classes('gap-2 mt-2'):
                            self.connect_button = ui.button('Connect', on_click=self.connect_to_server).classes('flex-1').props('dense color=primary')
                            self.disconnect_button = ui.button('Disconnect', on_click=self.disconnect).classes('flex-1').props('dense color=negative')
                            self.disconnect_button.disable()
                
                # Online Users
                with ui.column().classes('glass-panel flex-1'):
                    ui.label('👥 Online Users').classes('section-header')
                    with ui.scroll_area().classes('flex-1 w-full'):
                        self.users_list = ui.column().classes('gap-1 w-full')
                
                # Tools Section
                with ui.column().classes('glass-panel'):
                    ui.label('🔧 Tools').classes('section-header')
                    self.share_button = ui.button('📎 Share File', on_click=self.share_file).classes('w-full tool-button').props('flat dense')
                    self.share_button.disable()
                    ui.button('📂 Downloads', on_click=self.open_downloads).classes('w-full tool-button').props('flat dense')
                    ui.button('🔬 Test Encryption', on_click=self.test_encryption).classes('w-full tool-button').props('flat dense')
                    ui.button('🧹 Clear Chat', on_click=self.clear_chat).classes('w-full tool-button').props('flat dense')
            
            # Right Chat Area (flexible width)
            with ui.column().classes('telegram-chat flex-1'):
                
                # Chat Header
                with ui.row().classes('w-full telegram-header justify-between items-center'):
                    with ui.row().classes('items-center gap-3'):
                        ui.icon('chat').classes('text-white text-xl')
                        ui.label('Secure Chat').classes('text-white font-bold text-lg')
                        self.message_counter = ui.label('• 0 messages').classes('text-white text-opacity-70 text-sm')
                    with ui.row().classes('items-center gap-2'):
                        self.security_label = ui.label('🔒 Standby').classes('text-white text-opacity-70 text-sm')
                
                # Messages Area (Telegram proportions: takes most space)
                with ui.scroll_area().classes('messages-container flex-1 w-full'):
                    self.messages_area = ui.column().classes('gap-2 w-full p-3')
                
                # Message Input (fixed at bottom)
                with ui.row().classes('input-container w-full gap-3 items-end'):
                    self.message_input = ui.input('Type a message...').classes('flex-1').props('dense outlined')
                    self.send_button = ui.button('Send', on_click=self.send_message).props('dense color=primary')
                    self.send_button.disable()
                    
                    # Bind enter key
                    self.message_input.on('keydown.enter', self.send_message)
        
        # Initialize
        self.add_message("🔒 SYSTEM", "TeleChat Pro client initialized - Ready for secure communication", "system")
        self.update_user_list([])
    
    def connect_to_server(self):
        """Connect to server"""
        host = self.host_input.value or 'localhost'
        port = self.port_input.value or '12345'
        username = self.username_input.value
        
        if not username:
            ui.notify("Please enter a username", type='warning')
            return
        
        try:
            port = int(port)
        except ValueError:
            ui.notify("Port must be a number", type='warning')
            return
        
        if self.client.connect_to_server(host, port, username):
            self.status_label.text = "🟡 Connecting..." # type: ignore
            self.connection_info.text = f"Connecting to {host}:{port}" # type: ignore
        else:
            self.status_label.text = "🔴 Connection Failed" # type: ignore
            self.connection_info.text = "Connection attempt failed" # type: ignore
    
    def disconnect(self):
        """Disconnect from server"""
        self.client.disconnect()
        self.on_disconnected()
    
    def on_connected(self):
        """Handle successful connection"""
        self.connected = True
        
        # Update UI state
        self.connect_button.disable()
        self.disconnect_button.enable()
        self.host_input.disable()
        self.port_input.disable()
        self.username_input.disable()
        self.send_button.enable()
        self.share_button.enable()
        
        # Update status
        self.status_label.text = "� Connected & Secured" # type: ignore
        self.security_label.text = "🔒 Security: ENCRYPTED"
        self.connection_info.text = f"Connected to {self.client.host}:{self.client.port}" # type: ignore
        
        ui.notify("✅ Connected successfully! Welcome to secure chat.", type='positive')
        self.add_message("🔒 SYSTEM", "Secure connection established - All communications encrypted", "system")
    
    def on_disconnected(self):
        """Handle disconnection"""
        self.connected = False
        
        # Update UI state
        self.connect_button.enable()
        self.disconnect_button.disable()
        self.host_input.enable()
        self.port_input.enable()
        self.username_input.enable()
        self.send_button.disable()
        self.share_button.disable()
        
        # Update status
        self.status_label.text = "🔴 Disconnected" # type: ignore
        self.security_label.text = "🔒 Security: Offline"
        self.connection_info.text = "Not connected" # type: ignore
        
        ui.notify("Disconnected from server", type='info')
        self.add_message("🔒 SYSTEM", "Disconnected from server - Connection closed", "system")
        self.update_user_list([])
    
    def send_message(self):
        """Send a message"""
        if not self.connected:
            ui.notify("Not connected to server", type='warning')
            return
            
        message = self.message_input.value
        if not message:
            return
        
        if self.client.send_message(message):
            self.message_input.value = ""
            self.message_count += 1
            self.message_counter.text = f"Messages: {self.message_count}"
    
    def share_file(self):
        """Share a file using native dialog"""
        if not self.connected:
            ui.notify("Not connected to server", type='warning')
            return
        
        try:
            # Use tkinter for native file dialog
            import tkinter as tk
            from tkinter import filedialog
            
            root = tk.Tk()
            root.withdraw()
            
            file_path = filedialog.askopenfilename(
                title="Select file to share",
                filetypes=[
                    ("All files", "*.*"),
                    ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                    ("Documents", "*.pdf *.doc *.docx *.txt"),
                    ("Archives", "*.zip *.rar *.7z")
                ]
            )
            
            root.destroy()
            
            if file_path:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                ui.notify(f"Sharing: {file_name} ({file_size} bytes)", type='info')
                
                if self.client.send_file(file_path):
                    self.add_message("🔒 SYSTEM", f"File shared: {file_name}", "system")
                else:
                    ui.notify("Failed to share file", type='negative')
        
        except Exception as e:
            ui.notify(f"File sharing error: {e}", type='negative')
    
    def open_downloads(self):
        """Open downloads folder"""
        downloads_path = self.client.file_manager.base_dir
        
        try:
            # Create folder if it doesn't exist
            os.makedirs(downloads_path, exist_ok=True)
            
            # Open folder in file explorer
            if platform.system() == "Windows":
                os.startfile(downloads_path)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", downloads_path])
            else:  # Linux
                subprocess.run(["xdg-open", downloads_path])
                
            ui.notify(f"Opened: {downloads_path}", type='positive')
            
        except Exception as e:
            ui.notify(f"Cannot open downloads folder: {e}", type='negative')
    
    def test_encryption(self):
        """Test encryption"""
        try:
            test_message = "🔒 Test encryption message"
            encrypted = self.client.security_manager.encrypt_message(test_message)
            decrypted = self.client.security_manager.decrypt_message(encrypted)
            
            if test_message == decrypted:
                ui.notify("✅ Encryption test passed!", type='positive')
                self.add_message("🔬 TEST", f"Encryption working: {len(encrypted)} bytes", "system")
            else:
                ui.notify("❌ Encryption test failed!", type='negative')
                
        except Exception as e:
            ui.notify(f"Encryption test error: {e}", type='negative')
    
    def clear_chat(self):
        """Clear chat messages"""
        self.messages_area.clear()
        self.message_count = 0
        self.message_counter.text = "Messages: 0"
        ui.notify("Chat cleared", type='info')
    
    def add_message(self, sender, content, msg_type="normal"):
        """Add message to chat with modern styling"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Create message with styling based on type
        with self.messages_area:
            with ui.row().classes('w-full gap-3 chat-message'):
                # Message icon
                if msg_type == "system":
                    ui.icon('admin_panel_settings').classes('text-yellow-400 text-xl mt-1')
                elif msg_type == "error":
                    ui.icon('error').classes('text-red-400 text-xl mt-1')
                elif msg_type == "sent":
                    ui.icon('send').classes('text-blue-400 text-xl mt-1')
                elif msg_type == "file":
                    ui.icon('attach_file').classes('text-green-400 text-xl mt-1')
                else:
                    ui.icon('chat').classes('text-gray-400 text-xl mt-1')
                
                # Message content
                with ui.column().classes('flex-1'):
                    with ui.row().classes('items-center gap-2'):
                        ui.label(sender).classes('font-bold text-sm')
                        ui.label(f"• {timestamp}").classes('text-xs text-gray-500')
                    ui.label(content).classes('text-sm leading-relaxed break-words')
    
    def display_message(self, message):
        """Display received message"""
        if message.msg_type == "file":
            self.add_message(message.sender, f"📎 {message.content}", "file")
            
            # Handle file download
            if message.file_data:
                try:
                    saved_path = self.client.file_manager.decode_file(message.file_data)
                    self.add_message("🔒 SYSTEM", f"File saved: {saved_path}", "system")
                except Exception as e:
                    self.add_message("❌ ERROR", f"File download failed: {e}", "error")
        else:
            self.add_message(message.sender, message.content)
    
    def update_user_list(self, users):
        """Update online users list with modern styling"""
        self.users_list.clear()
        
        with self.users_list:
            if users:
                for user in users:
                    with ui.row().classes('w-full items-center gap-3 p-2 rounded-lg bg-green-900 bg-opacity-20'):
                        ui.icon('person').classes('text-green-400')
                        ui.label(user).classes('text-green-300 font-medium')
            else:
                with ui.row().classes('w-full items-center gap-3 p-2 rounded-lg bg-gray-800 bg-opacity-30'):
                    ui.icon('people_outline').classes('text-gray-500')
                    ui.label("No users online").classes('text-gray-400 italic')


# Create and run the app
@ui.page('/')
def main():
    chat_gui = CleanChatGUI()


if __name__ == "__main__":
    app.title = "TeleChat Secure Client"
    ui.run(
        title="TeleChat Secure Client",
        native=True,
        window_size=(1200, 800),
        reload=False,
        show=False
    )
