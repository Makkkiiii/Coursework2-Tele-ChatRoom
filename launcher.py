"""
Chat Application Launcher
Choose to run as Server or Client
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os


class ChatLauncher:
    """Launcher GUI for the chat application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Chat Application")
        self.root.geometry("400x300")
        self.root.configure(bg="#2c3e50")
        self.root.resizable(False, False)
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the launcher GUI"""
        # Title
        title_label = tk.Label(
            self.root,
            text="Advanced Chat Application",
            font=("Arial", 16, "bold"),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        title_label.pack(pady=20)
        
        # Subtitle
        subtitle_label = tk.Label(
            self.root,
            text="with Encryption, File Sharing & Modern GUI",
            font=("Arial", 10),
            bg="#2c3e50",
            fg="#95a5a6"
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Features list
        features_frame = tk.Frame(self.root, bg="#34495e")
        features_frame.pack(fill="x", padx=20, pady=10)
        
        features_title = tk.Label(
            features_frame,
            text="Features:",
            font=("Arial", 12, "bold"),
            bg="#34495e",
            fg="#ecf0f1"
        )
        features_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        features = [
            "✓ End-to-end encryption",
            "✓ File sharing (images, documents, etc.)",
            "✓ Modern GUI interface",
            "✓ Multi-user support",
            "✓ OOP & Data Structures implementation"
        ]
        
        for feature in features:
            feature_label = tk.Label(
                features_frame,
                text=feature,
                font=("Arial", 9),
                bg="#34495e",
                fg="#27ae60",
                anchor="w"
            )
            feature_label.pack(anchor="w", padx=20, pady=2)
        
        features_frame.pack_configure(pady=(10, 20))
        
        # Buttons frame
        buttons_frame = tk.Frame(self.root, bg="#2c3e50")
        buttons_frame.pack(pady=20)
        
        # Server button
        server_button = tk.Button(
            buttons_frame,
            text="Start Server",
            command=self.run_server,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 12, "bold"),
            width=12,
            height=2
        )
        server_button.pack(side="left", padx=10)
        
        # Client button
        client_button = tk.Button(
            buttons_frame,
            text="Start Client",
            command=self.run_client,
            bg="#3498db",
            fg="white",
            font=("Arial", 12, "bold"),
            width=12,
            height=2
        )
        client_button.pack(side="left", padx=10)
        
        # Info label
        info_label = tk.Label(
            self.root,
            text="Start the server first, then connect clients",
            font=("Arial", 9),
            bg="#2c3e50",
            fg="#f39c12"
        )
        info_label.pack(pady=(20, 10))
    
    def run_server(self):
        """Launch the server application"""
        try:
            script_path = os.path.join(os.path.dirname(__file__), "TCPServer.py")
            subprocess.Popen([sys.executable, script_path])
            messagebox.showinfo("Server", "Server application started!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
    
    def run_client(self):
        """Launch the client application"""
        try:
            script_path = os.path.join(os.path.dirname(__file__), "ClientServer.py")
            subprocess.Popen([sys.executable, script_path])
            messagebox.showinfo("Client", "Client application started!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start client: {e}")
    
    def run(self):
        """Start the launcher"""
        self.root.mainloop()


if __name__ == "__main__":
    launcher = ChatLauncher()
    launcher.run()
