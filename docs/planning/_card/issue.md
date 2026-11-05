# Ownership Verification Feature

## Goal
Implement the ownership verification capability (P1) that verifies users control a target before any other probe operations can proceed.

## Requirements
- DNS TXT verification method
- Well-known file verification method  
- Account-linking verification method (optional)
- All methods must create signed proof tokens
- The verification must be gated before any probe code runs
- Must follow the security constraints in CLAUDE.md

## Key Constraints
As per CLAUDE.md:
1. Ownership is proven before anything runs, at every intensity level
2. No scan of a target the user has not proven they control
3. Read-only by default - verification should not touch the target beyond checking ownership
4. Never claim "secure" - only EXPOSED/NOT_REPRODUCED/UNVERIFIED verdicts exist

## Implementation Plan
1. Create verification methods (DNS TXT, well-known file)
2. Implement proof token creation and validation
3. Create core verification logic that gates all downstream functionality
4. Add tests for verification flow