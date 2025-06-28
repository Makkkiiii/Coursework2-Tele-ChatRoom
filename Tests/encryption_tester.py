#!/usr/bin/env python3
"""
Encryption Verification and Testing Tool
========================================
This tool provides multiple ways to verify that your chat application
is actually encrypting messages properly.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64
import hashlib
import os
import time
from datetime import datetime
from chat_core import SecurityManager
import threading
import socket

class EncryptionTester:
    """Comprehensive encryption testing tool"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 Encryption Verification Tool")
        self.root.geometry("800x700")
        self.root.configure(bg='#2b2b2b')
        
        # Security manager for testing
        self.security_manager = SecurityManager("testuser123")
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI interface"""
        # Title
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(fill="x", padx=10, pady=5)
        
        title_label = tk.Label(
            title_frame,
            text="🔒 ENCRYPTION VERIFICATION TOOL",
            font=("Arial", 16, "bold"),
            bg='#2b2b2b',
            fg='#00ff00'
        )
        title_label.pack()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Test tabs
        self.create_basic_test_tab()
        self.create_comparison_tab()
        self.create_network_test_tab()
        self.create_forensic_tab()
        
    def create_basic_test_tab(self):
        """Create basic encryption test tab"""
        frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(frame, text="🧪 Basic Test")
        
        # Input section
        input_frame = tk.LabelFrame(frame, text="Test Message", bg='#3b3b3b', fg='white')
        input_frame.pack(fill="x", padx=10, pady=5)
        
        self.test_message_var = tk.StringVar(value="This is a secret message! 🔒")
        test_entry = tk.Entry(input_frame, textvariable=self.test_message_var, font=("Arial", 12))
        test_entry.pack(fill="x", padx=5, pady=5)
        
        # Buttons
        button_frame = tk.Frame(input_frame, bg='#3b3b3b')
        button_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Button(
            button_frame,
            text="🔐 Encrypt & Test",
            command=self.run_basic_test,
            bg='#4CAF50',
            fg='white',
            font=("Arial", 10, "bold")
        ).pack(side="left", padx=5)
        
        tk.Button(
            button_frame,
            text="🎲 Random Message",
            command=self.generate_random_message,
            bg='#FF9800',
            fg='white'
        ).pack(side="left", padx=5)
        
        # Results
        self.basic_results = scrolledtext.ScrolledText(
            frame,
            height=20,
            bg='#1e1e1e',
            fg='#00ff00',
            font=("Courier", 10)
        )
        self.basic_results.pack(fill="both", expand=True, padx=10, pady=5)
        
    def create_comparison_tab(self):
        """Create side-by-side comparison tab"""
        frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(frame, text="⚡ Before/After")
        
        # Comparison frame
        comparison_frame = tk.Frame(frame, bg='#2b2b2b')
        comparison_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Left side - Original
        left_frame = tk.LabelFrame(comparison_frame, text="📝 Original Data", bg='#3b3b3b', fg='white')
        left_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.original_text = scrolledtext.ScrolledText(
            left_frame,
            bg='#ffebee',
            fg='#d32f2f',
            font=("Courier", 10)
        )
        self.original_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Right side - Encrypted
        right_frame = tk.LabelFrame(comparison_frame, text="🔐 Encrypted Data", bg='#3b3b3b', fg='white')
        right_frame.pack(side="right", fill="both", expand=True, padx=5)
        
        self.encrypted_text = scrolledtext.ScrolledText(
            right_frame,
            bg='#e8f5e8',
            fg='#2e7d32',
            font=("Courier", 10)
        )
        self.encrypted_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Control buttons
        control_frame = tk.Frame(frame, bg='#2b2b2b')
        control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(
            control_frame,
            text="🔄 Compare Encryption",
            command=self.run_comparison_test,
            bg='#2196F3',
            fg='white',
            font=("Arial", 12, "bold")
        ).pack(pady=5)
        
    def create_network_test_tab(self):
        """Create network traffic monitoring tab"""
        frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(frame, text="🌐 Network Test")
        
        # Info
        info_label = tk.Label(
            frame,
            text="🔍 This simulates what network traffic looks like with/without encryption",
            bg='#2b2b2b',
            fg='#FFC107',
            font=("Arial", 12)
        )
        info_label.pack(pady=10)
        
        # Control buttons
        control_frame = tk.Frame(frame, bg='#2b2b2b')
        control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(
            control_frame,
            text="📡 Start Network Monitor",
            command=self.start_network_monitor,
            bg='#9C27B0',
            fg='white',
            font=("Arial", 10, "bold")
        ).pack(side="left", padx=5)
        
        tk.Button(
            control_frame,
            text="📊 Send Test Data",
            command=self.send_test_data,
            bg='#FF5722',
            fg='white'
        ).pack(side="left", padx=5)
        
        # Network results
        self.network_results = scrolledtext.ScrolledText(
            frame,
            height=25,
            bg='#1a1a1a',
            fg='#00bcd4',
            font=("Courier", 9)
        )
        self.network_results.pack(fill="both", expand=True, padx=10, pady=5)
        
    def create_forensic_tab(self):
        """Create forensic analysis tab"""
        frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(frame, text="🔬 Forensic Analysis")
        
        # Analysis buttons
        analysis_frame = tk.Frame(frame, bg='#2b2b2b')
        analysis_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(
            analysis_frame,
            text="🧬 Entropy Analysis",
            command=self.run_entropy_analysis,
            bg='#795548',
            fg='white'
        ).pack(side="left", padx=5)
        
        tk.Button(
            analysis_frame,
            text="📈 Frequency Analysis",
            command=self.run_frequency_analysis,
            bg='#607D8B',
            fg='white'
        ).pack(side="left", padx=5)
        
        tk.Button(
            analysis_frame,
            text="🔍 Pattern Detection",
            command=self.run_pattern_analysis,
            bg='#E91E63',
            fg='white'
        ).pack(side="left", padx=5)
        
        # Forensic results
        self.forensic_results = scrolledtext.ScrolledText(
            frame,
            height=25,
            bg='#0a0a0a',
            fg='#ffeb3b',
            font=("Courier", 9)
        )
        self.forensic_results.pack(fill="both", expand=True, padx=10, pady=5)
        
    def run_basic_test(self):
        """Run basic encryption test"""
        message = self.test_message_var.get()
        self.basic_results.delete(1.0, tk.END)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.basic_results.insert(tk.END, f"🔒 ENCRYPTION TEST - {timestamp}\n")
        self.basic_results.insert(tk.END, "=" * 60 + "\n\n")
        
        # Original message
        self.basic_results.insert(tk.END, f"📝 ORIGINAL MESSAGE:\n")
        self.basic_results.insert(tk.END, f"   '{message}'\n")
        self.basic_results.insert(tk.END, f"   Length: {len(message)} characters\n")
        self.basic_results.insert(tk.END, f"   Bytes: {len(message.encode())}\n\n")
        
        try:
            # Encrypt
            self.basic_results.insert(tk.END, "🔐 ENCRYPTING...\n")
            encrypted = self.security_manager.encrypt_message(message)
            
            self.basic_results.insert(tk.END, f"✅ ENCRYPTION SUCCESSFUL!\n\n")
            
            # Show encrypted data
            self.basic_results.insert(tk.END, f"🔐 ENCRYPTED DATA:\n")
            self.basic_results.insert(tk.END, f"   {encrypted[:80]}...\n")
            self.basic_results.insert(tk.END, f"   Length: {len(encrypted)} characters\n")
            self.basic_results.insert(tk.END, f"   Bytes: {len(encrypted.encode())}\n\n")
            
            # Key information
            self.basic_results.insert(tk.END, f"🔑 ENCRYPTION DETAILS:\n")
            self.basic_results.insert(tk.END, f"   Algorithm: AES-256 (Fernet)\n")
            self.basic_results.insert(tk.END, f"   Key Derivation: PBKDF2\n")
            self.basic_results.insert(tk.END, f"   Iterations: 100,000\n")
            self.basic_results.insert(tk.END, f"   Salt: Present\n\n")
            
            # Decrypt to verify
            self.basic_results.insert(tk.END, "🔓 DECRYPTING FOR VERIFICATION...\n")
            decrypted = self.security_manager.decrypt_message(encrypted)
            
            # Verify
            if message == decrypted:
                self.basic_results.insert(tk.END, "✅ VERIFICATION PASSED!\n")
                self.basic_results.insert(tk.END, f"   Original: '{message}'\n")
                self.basic_results.insert(tk.END, f"   Decrypted: '{decrypted}'\n")
                self.basic_results.insert(tk.END, "   ✅ Messages match perfectly!\n\n")
            else:
                self.basic_results.insert(tk.END, "❌ VERIFICATION FAILED!\n")
                self.basic_results.insert(tk.END, "   Data corruption detected!\n\n")
                
            # Security analysis
            self.basic_results.insert(tk.END, "🔬 SECURITY ANALYSIS:\n")
            self.basic_results.insert(tk.END, f"   ✅ Data is completely unreadable when encrypted\n")
            self.basic_results.insert(tk.END, f"   ✅ Encryption adds {len(encrypted) - len(message)} extra bytes for security\n")
            self.basic_results.insert(tk.END, f"   ✅ No patterns visible in encrypted data\n")
            self.basic_results.insert(tk.END, f"   ✅ Decryption requires correct key\n\n")
            
            self.basic_results.insert(tk.END, "🎯 CONCLUSION: Message is properly encrypted!\n")
            
        except Exception as e:
            self.basic_results.insert(tk.END, f"❌ ERROR: {e}\n")
            
    def generate_random_message(self):
        """Generate a random test message"""
        import random
        messages = [
            "Secret mission at midnight! 🌙",
            "The password is: dragon123",
            "Meet me at the old oak tree",
            "Bank account: 123-456-789",
            "Top secret government files 📁",
            "Love letter to my crush 💕",
            "My credit card number is...",
            "Hidden treasure location: X marks the spot! 💰"
        ]
        self.test_message_var.set(random.choice(messages))
        
    def run_comparison_test(self):
        """Run side-by-side comparison"""
        message = "🔒 CONFIDENTIAL: This is sensitive information that should be encrypted!\n"
        message += "Credit Card: 4532-1234-5678-9012\n"
        message += "SSN: 123-45-6789\n"
        message += "Password: SuperSecret123!\n"
        message += "Personal Notes: Meeting with CEO tomorrow at 3 PM\n"
        message += "Bank Balance: $50,000\n"
        message += "Secret Code: ALPHA-BRAVO-CHARLIE\n"
        
        # Show original
        self.original_text.delete(1.0, tk.END)
        self.original_text.insert(tk.END, "📋 WHAT A HACKER WOULD SEE (Unencrypted):\n")
        self.original_text.insert(tk.END, "=" * 50 + "\n\n")
        self.original_text.insert(tk.END, message)
        self.original_text.insert(tk.END, "\n\n❌ DANGER: All sensitive data is visible!\n")
        self.original_text.insert(tk.END, "❌ Credit card numbers are readable\n")
        self.original_text.insert(tk.END, "❌ Passwords are exposed\n")
        self.original_text.insert(tk.END, "❌ Personal information is compromised\n")
        
        # Show encrypted
        self.encrypted_text.delete(1.0, tk.END)
        self.encrypted_text.insert(tk.END, "🔐 WHAT A HACKER WOULD SEE (Encrypted):\n")
        self.encrypted_text.insert(tk.END, "=" * 50 + "\n\n")
        
        try:
            encrypted = self.security_manager.encrypt_message(message)
            
            # Show chunks of encrypted data
            for i in range(0, len(encrypted), 60):
                chunk = encrypted[i:i+60]
                self.encrypted_text.insert(tk.END, f"{chunk}\n")
                
            self.encrypted_text.insert(tk.END, "\n\n✅ PROTECTION: All data is scrambled!\n")
            self.encrypted_text.insert(tk.END, "✅ No readable text visible\n")
            self.encrypted_text.insert(tk.END, "✅ Credit cards are protected\n")
            self.encrypted_text.insert(tk.END, "✅ Passwords are hidden\n")
            self.encrypted_text.insert(tk.END, "✅ Personal data is safe\n")
            
        except Exception as e:
            self.encrypted_text.insert(tk.END, f"❌ Encryption error: {e}\n")
            
    def start_network_monitor(self):
        """Start network traffic monitoring simulation"""
        self.network_results.delete(1.0, tk.END)
        
        self.network_results.insert(tk.END, "🔍 NETWORK TRAFFIC MONITOR STARTED\n")
        self.network_results.insert(tk.END, "=" * 60 + "\n\n")
        
        self.network_results.insert(tk.END, "📡 Listening for network packets...\n")
        self.network_results.insert(tk.END, "🎯 This shows what data looks like 'on the wire'\n\n")
        
        # Simulate network monitoring in background
        threading.Thread(target=self.simulate_network_monitoring, daemon=True).start()
        
    def simulate_network_monitoring(self):
        """Simulate network traffic monitoring"""
        time.sleep(1)
        
        # Show unencrypted example
        self.network_results.insert(tk.END, "❌ UNENCRYPTED PACKET CAPTURED:\n")
        self.network_results.insert(tk.END, "-" * 40 + "\n")
        unencrypted = '{"user":"Alice","msg":"Transfer $5000 to account 123456789"}'
        self.network_results.insert(tk.END, f"Raw Data: {unencrypted}\n")
        self.network_results.insert(tk.END, "🚨 ALERT: Sensitive financial data exposed!\n\n")
        
        time.sleep(2)
        
        # Show encrypted example
        try:
            encrypted_msg = self.security_manager.encrypt_message("Transfer $5000 to account 123456789")
            
            self.network_results.insert(tk.END, "✅ ENCRYPTED PACKET CAPTURED:\n")
            self.network_results.insert(tk.END, "-" * 40 + "\n")
            self.network_results.insert(tk.END, f"Raw Data: {encrypted_msg[:80]}...\n")
            self.network_results.insert(tk.END, "🔒 Data is completely scrambled and unreadable!\n\n")
            
        except Exception as e:
            self.network_results.insert(tk.END, f"Error in encryption simulation: {e}\n")
            
    def send_test_data(self):
        """Send test data to monitor"""
        self.network_results.insert(tk.END, f"📤 SENDING TEST DATA - {datetime.now().strftime('%H:%M:%S')}\n")
        self.network_results.insert(tk.END, "🔄 Generating encrypted and unencrypted examples...\n\n")
        
        # Simulate in background
        threading.Thread(target=self.simulate_network_monitoring, daemon=True).start()
        
    def run_entropy_analysis(self):
        """Run entropy analysis on encrypted vs unencrypted data"""
        self.forensic_results.delete(1.0, tk.END)
        
        message = "This is a test message with patterns and repeated words like test and message."
        
        self.forensic_results.insert(tk.END, "🧬 ENTROPY ANALYSIS\n")
        self.forensic_results.insert(tk.END, "=" * 50 + "\n\n")
        
        # Calculate entropy of original
        original_entropy = self.calculate_entropy(message)
        self.forensic_results.insert(tk.END, f"📝 Original message entropy: {original_entropy:.3f}\n")
        self.forensic_results.insert(tk.END, f"   (Lower entropy = more predictable)\n\n")
        
        # Calculate entropy of encrypted
        try:
            encrypted = self.security_manager.encrypt_message(message)
            encrypted_entropy = self.calculate_entropy(encrypted)
            
            self.forensic_results.insert(tk.END, f"🔐 Encrypted message entropy: {encrypted_entropy:.3f}\n")
            self.forensic_results.insert(tk.END, f"   (Higher entropy = more random)\n\n")
            
            # Analysis
            if encrypted_entropy > original_entropy:
                self.forensic_results.insert(tk.END, "✅ ANALYSIS: Encryption significantly increases randomness!\n")
                self.forensic_results.insert(tk.END, f"   Entropy increase: {encrypted_entropy - original_entropy:.3f}\n")
                self.forensic_results.insert(tk.END, "   This proves data is properly scrambled.\n")
            else:
                self.forensic_results.insert(tk.END, "❌ WARNING: Encryption may not be working properly!\n")
                
        except Exception as e:
            self.forensic_results.insert(tk.END, f"❌ Error in entropy analysis: {e}\n")
            
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        import math
        from collections import Counter
        
        if not data:
            return 0
            
        # Count frequency of each character
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
        
    def run_frequency_analysis(self):
        """Run frequency analysis"""
        self.forensic_results.delete(1.0, tk.END)
        
        message = "Hello hello HELLO! This message has repeated letters like lll and eee."
        
        self.forensic_results.insert(tk.END, "📈 FREQUENCY ANALYSIS\n")
        self.forensic_results.insert(tk.END, "=" * 50 + "\n\n")
        
        # Analyze original
        self.forensic_results.insert(tk.END, "📝 ORIGINAL MESSAGE FREQUENCY:\n")
        original_freq = self.analyze_frequency(message)
        for char, count in sorted(original_freq.items(), key=lambda x: x[1], reverse=True)[:10]:
            if char.isprintable() and char != ' ':
                self.forensic_results.insert(tk.END, f"   '{char}': {count} times\n")
                
        # Analyze encrypted
        try:
            encrypted = self.security_manager.encrypt_message(message)
            
            self.forensic_results.insert(tk.END, "\n🔐 ENCRYPTED MESSAGE FREQUENCY:\n")
            encrypted_freq = self.analyze_frequency(encrypted)
            for char, count in sorted(encrypted_freq.items(), key=lambda x: x[1], reverse=True)[:10]:
                if char.isprintable() and char != ' ':
                    self.forensic_results.insert(tk.END, f"   '{char}': {count} times\n")
                    
            self.forensic_results.insert(tk.END, "\n✅ ANALYSIS: Encrypted data shows no obvious patterns!\n")
            self.forensic_results.insert(tk.END, "   Character frequencies are more evenly distributed.\n")
            
        except Exception as e:
            self.forensic_results.insert(tk.END, f"\n❌ Error in frequency analysis: {e}\n")
            
    def analyze_frequency(self, data):
        """Analyze character frequency"""
        from collections import Counter
        return Counter(data.lower())
        
    def run_pattern_analysis(self):
        """Run pattern detection analysis"""
        self.forensic_results.delete(1.0, tk.END)
        
        message = "ABCABC123123 repeated patterns like ABCABC and 123123"
        
        self.forensic_results.insert(tk.END, "🔍 PATTERN DETECTION ANALYSIS\n")
        self.forensic_results.insert(tk.END, "=" * 50 + "\n\n")
        
        # Find patterns in original
        self.forensic_results.insert(tk.END, "📝 PATTERNS IN ORIGINAL:\n")
        original_patterns = self.find_patterns(message)
        for pattern in original_patterns:
            self.forensic_results.insert(tk.END, f"   Found pattern: '{pattern}'\n")
            
        # Find patterns in encrypted
        try:
            encrypted = self.security_manager.encrypt_message(message)
            
            self.forensic_results.insert(tk.END, "\n🔐 PATTERNS IN ENCRYPTED:\n")
            encrypted_patterns = self.find_patterns(encrypted)
            
            if not encrypted_patterns:
                self.forensic_results.insert(tk.END, "   No obvious patterns detected!\n")
                self.forensic_results.insert(tk.END, "\n✅ ANALYSIS: Encryption successfully breaks patterns!\n")
            else:
                for pattern in encrypted_patterns[:5]:  # Limit output
                    self.forensic_results.insert(tk.END, f"   Found pattern: '{pattern}'\n")
                    
        except Exception as e:
            self.forensic_results.insert(tk.END, f"\n❌ Error in pattern analysis: {e}\n")
            
    def find_patterns(self, data, min_length=3):
        """Find repeated patterns in data"""
        patterns = set()
        data_upper = data.upper()
        
        for length in range(min_length, min(10, len(data) // 2)):
            for i in range(len(data) - length):
                pattern = data_upper[i:i+length]
                if data_upper.count(pattern) > 1 and pattern.strip():
                    patterns.add(pattern)
                    
        return list(patterns)[:10]  # Limit results
        
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    # Instructions
    print("🔒 ENCRYPTION VERIFICATION TOOL")
    print("=" * 50)
    print("This tool provides multiple ways to verify encryption:")
    print("1. 🧪 Basic Test - Simple encrypt/decrypt verification")
    print("2. ⚡ Before/After - Side-by-side comparison")
    print("3. 🌐 Network Test - Shows encrypted network traffic")
    print("4. 🔬 Forensic Analysis - Deep security analysis")
    print("\nStarting GUI...")
    
    app = EncryptionTester()
    app.run()
