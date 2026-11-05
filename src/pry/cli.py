"""
CLI interface for Pry security scanner.
"""

import argparse
import sys
from typing import Optional

def setup_parser() -> argparse.ArgumentParser:
    """Set up the argument parser."""
    parser = argparse.ArgumentParser(
        description="Pry - Proves an app you own is exposed by actually trying the exploit"
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # verify-ownership command
    verify_parser = subparsers.add_parser(
        'verify-ownership', 
        help='Verify ownership of a target before scanning'
    )
    verify_parser.add_argument(
        'target', 
        help='Target to verify ownership of (URL or domain)'
    )
    verify_parser.add_argument(
        '--dns-txt',
        help='Expected DNS TXT record value for verification'
    )
    verify_parser.add_argument(
        '--well-known-content',
        help='Expected content for well-known file verification'
    )
    verify_parser.add_argument(
        '--account-provider',
        help='OAuth provider for account linking verification (github, gitlab, etc.)'
    )
    verify_parser.add_argument(
        '--auth-token',
        help='Authentication token for account linking'
    )
    
    # scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan a target for security issues'
    )
    scan_parser.add_argument(
        'target',
        help='Target to scan (must be verified first)'
    )
    scan_parser.add_argument(
        '--token',
        help='Ownership token for the target'
    )
    scan_parser.add_argument(
        '--level',
        type=int,
        default=0,
        choices=[0, 1, 2],
        help='Scan intensity level (default: 0 - read-only floor checks)'
    )
    scan_parser.add_argument(
        '--confirm',
        action='store_true',
        help='Confirm destructive actions at level 2'
    )
    
    return parser

async def verify_ownership(args) -> int:
    """Verify ownership of a target."""
    from src.pry.own.verification import OwnershipVerifier
    
    try:
        verifier = OwnershipVerifier()
        
        # Prepare verification methods
        verification_methods = {}
        if args.dns_txt:
            verification_methods['dns_txt'] = {'record': args.dns_txt}
        if args.well_known_content:
            verification_methods['well_known'] = {'content': args.well_known_content}
        if args.account_provider and args.auth_token:
            verification_methods['account_link'] = {
                'provider': args.account_provider,
                'token': args.auth_token
            }
        
        # Verify ownership
        is_verified, error, token = await verifier.verify_target(
            args.target, 
            verification_methods
        )
        
        if is_verified and token:
            print(f"✅ Ownership verified for {args.target}")
            print(f"   Token: {token.token}")
            print(f"   Proof type: {token.proof_type}")
            print("   This token can be used to scan this target.")
            return 0
        else:
            print(f"❌ Ownership verification failed: {error}")
            return 1
            
    except Exception as e:
        print(f"Error during ownership verification: {e}")
        return 2

async def scan_target(args) -> int:
    """Scan a target for security issues."""
    # This would check if the target has been verified
    if args.token is None:
        print("❌ Error: This target requires a valid ownership token. Run 'pry verify-ownership' first.")
        return 2
        
    if not args.token.strip():
        print("❌ Error: Invalid or missing token")
        return 2
        
    try:
        # In a real implementation, this would do the actual scanning
        print(f"🚀 Scanning {args.target} with intensity level {args.level}")
        print("   (This is a simulation - full implementation coming soon)")
        
        # Check for basic checks that are always on
        if args.level >= 0:
            print("   ✓ Read-only floor checks: missing auth, broken access control, exposed secrets")
            
        if args.level >= 1:
            print("   ✓ Expanded checks: non-mutating SSRF probes, rate-limit probing")
            
        if args.level >= 2:
            confirm_text = "CONFIRMED" if args.confirm else "NOT CONFIRMED"
            print(f"   ✓ Write-based confirmation checks ({confirm_text})")
            
        print("   (Scan results would appear here in a real implementation)")
        return 0
        
    except Exception as e:
        print(f"Error during scan: {e}")
        return 2

async def main() -> int:
    """Main entry point."""
    parser = setup_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == 'verify-ownership':
        return await verify_ownership(args)
    elif args.command == 'scan':
        return await scan_target(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1

if __name__ == "__main__":
    # Running the main function with asyncio
    import asyncio
    sys.exit(asyncio.run(main()))