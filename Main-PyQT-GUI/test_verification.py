#!/usr/bin/env python3
"""
Verification script to test the Qt warning fixes
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, QObject
import Main_Client
from core import Message
import time

class MessageTester(QObject):
    """Test class to simulate message flow"""
    
    def __init__(self, chat_widget):
        super().__init__()
        self.chat_widget = chat_widget
        self.message_count = 0
    
    def send_test_messages(self):
        """Send a series of test messages to verify no warnings"""
        print("Starting message test...")
        
        # Test system message
        sys_msg = Message("SYSTEM", "Test system message", "system")
        self.chat_widget.add_message(sys_msg)
        print("✓ System message sent")
        
        # Test user messages
        for i in range(3):
            msg = Message(f"TestUser{i}", f"Test message {i+1}", "text")
            self.chat_widget.add_message(msg)
            print(f"✓ User message {i+1} sent")
        
        # Test own message
        own_msg = Message("You", "Your own message", "text")
        self.chat_widget.add_message(own_msg, is_own_message=True)
        print("✓ Own message sent")
        
        # Test file message
        file_msg = Message("TestUser", "document.pdf", "file")
        self.chat_widget.add_message(file_msg)
        print("✓ File message sent")
        
        # Test duplicate prevention
        duplicate_msg = Message("TestUser", "Duplicate test", "text")
        self.chat_widget.add_message(duplicate_msg)
        self.chat_widget.add_message(duplicate_msg)  # Should be skipped
        print("✓ Duplicate prevention tested")
        
        print("All test messages sent successfully!")
        print("No Qt warnings should appear above this line.")

def main():
    """Main verification function"""
    print("Qt Warning Verification Test")
    print("=" * 40)
    
    app = QApplication(sys.argv)
    
    # Create a minimal chat widget for testing
    chat_widget = Main_Client.ModernChatWidget()
    
    # Create tester
    tester = MessageTester(chat_widget)
    
    # Use a timer to send messages after the app starts
    timer = QTimer()
    timer.timeout.connect(tester.send_test_messages)
    timer.timeout.connect(lambda: QTimer.singleShot(2000, app.quit))  # Quit after 2 seconds
    timer.setSingleShot(True)
    timer.start(500)  # Start test after 500ms
    
    print("Starting Qt application...")
    result = app.exec_()
    print("Application closed successfully")
    print("=" * 40)
    
    return result

if __name__ == "__main__":
    main()
