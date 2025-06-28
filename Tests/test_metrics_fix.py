#!/usr/bin/env python3
"""
Test script to verify the metrics error is fixed
"""

import sys
import traceback

def test_metrics_fix():
    """Test that the metrics error is fixed"""
    
    print("🔧 Testing metrics error fix...")
    
    try:
        # Test 1: Import AdvancedSecurityManager
        print("1. Testing AdvancedSecurityManager import...")
        from advanced_security_fixed import AdvancedSecurityManager
        print("   ✅ Import successful")
        
        # Test 2: Create security manager
        print("2. Testing security manager creation...")
        security_manager = AdvancedSecurityManager()
        print("   ✅ Security manager created")
        
        # Test 3: Generate security report
        print("3. Testing security report generation...")
        report = security_manager.get_security_report()
        print("   ✅ Security report generated")
        
        # Test 4: Check metrics structure
        print("4. Testing metrics structure...")
        if 'metrics' not in report:
            print("   ❌ No 'metrics' key in report")
            return False
            
        metrics = report['metrics']
        expected_metrics = [
            'failed_logins', 'successful_logins', 'blocked_attempts',
            'malicious_requests', 'file_uploads', 'file_downloads',
            'messages_encrypted', 'messages_decrypted', 'security_violations',
            'total_connections', 'active_threats', 'last_attack_time',
            'system_uptime'
        ]
        
        for metric in expected_metrics:
            if metric not in metrics:
                print(f"   ❌ Missing metric: {metric}")
                return False
                
        print(f"   ✅ All {len(expected_metrics)} metrics present")
        
        # Test 5: Test metric access (simulating secure server usage)
        print("5. Testing metric access pattern...")
        
        # This is the pattern used in secure_server.py
        active_sessions = report.get('active_sessions', 0)
        system_status = report.get('system_status', 'unknown')
        failed_logins = metrics.get('failed_logins', 0)
        successful_logins = metrics.get('successful_logins', 0)
        messages_encrypted = metrics.get('messages_encrypted', 0)
        
        print(f"   ✅ Active sessions: {active_sessions}")
        print(f"   ✅ System status: {system_status}")
        print(f"   ✅ Failed logins: {failed_logins}")
        print(f"   ✅ Successful logins: {successful_logins}")
        print(f"   ✅ Messages encrypted: {messages_encrypted}")
        
        # Test 6: Test metric update methods
        print("6. Testing metric update methods...")
        
        original_failed = metrics['failed_logins']
        security_manager.record_failed_login("test_user")
        updated_report = security_manager.get_security_report()
        new_failed = updated_report['metrics']['failed_logins']
        
        if new_failed == original_failed + 1:
            print("   ✅ Metric update working correctly")
        else:
            print(f"   ❌ Metric update failed: {original_failed} -> {new_failed}")
            return False
            
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ The metrics error has been fixed!")
        print("✅ SecureServer should now work without 'metrics' errors")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_metrics_fix()
    if success:
        print("\n🚀 You can now run the secure server without errors!")
        print("   python secure_server.py")
    else:
        print("\n💔 There are still issues that need to be fixed.")
    
    sys.exit(0 if success else 1)
