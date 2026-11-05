# Ownership Verification PRD

## Overview

The ownership verification capability (P1) implements methods to verify that a user controls a target before any scanning or probing can proceed. This is the structural foundation for all downstream capabilities in Pry.

## Purpose and Goals

Verify that users have legitimate control over targets they want to scan before allowing access to any probe functionality.

## Requirements

### Core Requirements
- Support multiple verification methods (DNS TXT, well-known file, account linking)
- Generate signed proof tokens upon successful verification
- Gate all downstream functionality with ownership verification
- Read-only by default - no writing or modification of target resources during verification
- Never claim "secure" - only EXPOSED/NOT_REPRODUCED/UNVERIFIED verdicts exist

### Technical Requirements 
- Implement DNS TXT record verification
- Implement well-known file verification  
- Implement account-linking verification (optional but preferred)
- Create proof token generation and validation logic
- Integrate with main CLI flow for verification commands

## Acceptance Criteria

1. **Method Support**: All three verification methods work correctly
2. **Proof Generation**: Each successful verification produces a verifiable proof token
3. **Gating**: Verification must be required before any probing can occur  
4. **Security**: Read-only verification with no modification of target systems
5. **CLI Integration**: Verify-ownership command works through CLI

## Implementation Approach

### Module Structure
- `src/pry/own/` - Core ownership verification functionality
- `src/pry/cli.py` - CLI commands for verification and scanning

### Verification Methods  
1. **DNS TXT**: Check DNS TXT records for expected value
2. **Well-known file**: Fetch and verify content of .well-known file  
3. **Account linking**: OAuth-style authentication verification

## Testing Approach

All functionality will be test-driven with comprehensive unit tests covering:
- Each verification method
- Proof token generation and validation 
- CLI command integration
- Error handling scenarios

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| **Ownership bypass** (R1) | Structurally gate all functionality through verification |
| **False positive verification** | Use robust validation techniques for each method |
| **Missing methods** | Support all three primary methods as per roadmap |

## Dependencies

- None - this is the first capability that gates all others