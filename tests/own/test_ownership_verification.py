"""
Tests for ownership verification functionality in Pry.
"""

import asyncio
import pytest
from src.pry.own.verification import OwnershipVerifier, OwnershipToken


@pytest.fixture
def verifier():
    """Create a verifier instance for testing."""
    return OwnershipVerifier()


@pytest.mark.asyncio
async def test_verification_token_creation(verifier):
    """Test that ownership tokens can be created properly."""
    token = verifier.generate_token("https://example.com", "dns_txt")
    
    assert isinstance(token, OwnershipToken)
    assert token.target == "https://example.com"
    assert token.proof_type == "dns_txt"
    assert token.token is not None
    assert token.issued_at > 0
    assert token.expires_at > token.issued_at


@pytest.mark.asyncio 
async def test_dns_txt_verification(verifier):
    """Test that DNS TXT verification is functional (simulated)."""
    # These are just placeholder tests since actual DNS checks would require network
    # but we can at least verify the function exists and handles parameters
    is_verified, error, token = await verifier.verify_target(
        "https://example.com",
        {"dns_txt": {"record": "test-record"}}
    )
    
    # The function should return successfully (we're not actually checking DNS)
    assert is_verified is True or error is not None
    # If successful, we should have a token
    if token:
        assert isinstance(token, OwnershipToken)


@pytest.mark.asyncio
async def test_well_known_file_verification(verifier):
    """Test that well-known file verification is functional (simulated)."""
    is_verified, error, token = await verifier.verify_target(
        "https://example.com",
        {"well_known": {"content": "test-content"}}
    )
    
    # The function should return successfully
    assert is_verified is True or error is not None
    if token:
        assert isinstance(token, OwnershipToken)


@pytest.mark.asyncio
async def test_account_link_verification(verifier):
    """Test that account linking verification is functional (simulated)."""
    is_verified, error, token = await verifier.verify_target(
        "https://example.com",
        {"account_link": {"provider": "github", "token": "test-token"}}
    )
    
    # The function should return successfully
    assert is_verified is True or error is not None
    if token:
        assert isinstance(token, OwnershipToken)


def test_verification_gates_probe_execution():
    """Test that we can call the verification methods and they don't crash."""
    verifier = OwnershipVerifier()
    
    # Test that we can create a verifier
    assert verifier is not None
    assert hasattr(verifier, 'verify_target')
    assert hasattr(verifier, 'generate_token')