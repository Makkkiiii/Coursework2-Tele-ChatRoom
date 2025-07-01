"""
TeleChat Launcher - Choose Client or Server
"""

import sys
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap


class TeleChatLauncher(QWidget):
    """Simple launcher for TeleChat Client or Server"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_styles()
    
    def setup_ui(self):
        """Setup the launcher UI"""
        self.setWindowTitle("🔒 TeleChat Launcher")
        self.setGeometry(300, 300, 400, 300)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("🔒 TeleChat")
        title.setAlignment(Qt.AlignCenter) # type: ignore
        title.setStyleSheet("""
            QLabel {
                font-size: 32px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Modern Secure Messaging")
        subtitle.setAlignment(Qt.AlignCenter) # type: ignore
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #7f8c8d;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(subtitle)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("color: #bdc3c7;")
        layout.addWidget(separator)
        
        # Buttons frame
        buttons_frame = QFrame()
        buttons_layout = QVBoxLayout(buttons_frame)
        buttons_layout.setSpacing(15)
        
        # Server button
        server_btn = QPushButton("🖥️ Start Server")
        server_btn.clicked.connect(self.launch_server)
        server_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                font-weight: bold;
                padding: 15px 30px;
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 10px;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
        """)
        buttons_layout.addWidget(server_btn)
        
        # Client button
        client_btn = QPushButton("💬 Start Client")
        client_btn.clicked.connect(self.launch_client)
        client_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                font-weight: bold;
                padding: 15px 30px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 10px;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        buttons_layout.addWidget(client_btn)
        
        layout.addWidget(buttons_frame)
        
        # Footer
        footer = QLabel("Choose Server to host or Client to connect")
        footer.setAlignment(Qt.AlignCenter) # type: ignore
        footer.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #95a5a6;
                margin-top: 20px;
            }
        """)
        layout.addWidget(footer)
        
        layout.addStretch()
    
    def setup_styles(self):
        """Setup the launcher styles"""
        self.setStyleSheet("""
            QWidget {
                background-color: #ecf0f1;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
        """)
    
    def launch_server(self):
        """Launch the server application"""
        try:
            server_path = "c:/Users/deven/Desktop/Works/ProgrammingAlgo2/Main-PyQT-GUI/Main_Server.py"
            subprocess.Popen([sys.executable, server_path])
            self.close()
        except Exception as e:
            print(f"Failed to launch server: {e}")
    
    def launch_client(self):
        """Launch the client application"""
        try:
            client_path = "c:/Users/deven/Desktop/Works/ProgrammingAlgo2/Main-PyQT-GUI/Main_Client.py"
            subprocess.Popen([sys.executable, client_path])
            self.close()
        except Exception as e:
            print(f"Failed to launch client: {e}")


def main():
    """Main function"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("TeleChat Launcher")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Secure Chat Solutions")
    
    # Create and show launcher
    launcher = TeleChatLauncher()
    launcher.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
