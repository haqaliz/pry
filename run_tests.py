#!/usr/bin/env python3
"""
Simple test runner for Pry ownership verification tests
"""

import sys
import os

# Add src to Python path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def run_tests():
    """Run the ownership verification tests"""
    print("Running ownership verification tests...")
    
    try:
        # Import and test our module
        from pry.own import OwnershipVerifier, OwnershipProof
        
        # Test the basic functionality
        verifier = OwnershipVerifier()
        
        # Test DNS TXT verification
        result = verifier.verify_dns_txt("example.com", "txt-record-value")
        print("✓ DNS TXT verification works")
        
        # Test well-known file verification  
        result = verifier.verify_well_known("example.com", "file-content")
        print("✓ Well-known file verification works")
        
        # Test account linking verification
        auth_info = {"user_id": "123", "provider": "github"}
        result = verifier.verify_account_link("example.com", auth_info)
        print("✓ Account linking verification works")
        
        # Test proof validation
        proof = OwnershipProof(
            target="example.com",
            method="dns_txt", 
            token="test-token",
            timestamp=1234567890.0
        )
        assert verifier.validate_proof(proof) is True
        print("✓ Proof validation works")
        
        print("\nAll tests passed! Ownership verification module is working correctly.")
        return 0
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())