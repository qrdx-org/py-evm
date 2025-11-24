"""
Quantum-Resistant Key Management for QRDX Chain

This module provides high-level key management functionality,
wrapping the lower-level Dilithium implementation.
"""

from typing import Tuple
from .dilithium import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    generate_dilithium_keypair,
)
from .addresses import address_from_public_key
from eth_typing import Address


# Type aliases for clarity
PrivateKey = DilithiumPrivateKey
PublicKey = DilithiumPublicKey


def generate_keypair() -> Tuple[PrivateKey, PublicKey]:
    """
    Generate a new quantum-resistant key pair.
    
    This is the primary function for creating new QRDX Chain accounts.
    Uses CRYSTALS-Dilithium for post-quantum security.
    
    Returns:
        A tuple of (private_key, public_key)
    
    Example:
        >>> from eth.crypto import generate_keypair, derive_address
        >>> private_key, public_key = generate_keypair()
        >>> address = derive_address(public_key)
        >>> print(f"New QRDX address: {address.hex()}")
    """
    return generate_dilithium_keypair()


def derive_address(public_key: PublicKey) -> Address:
    """
    Derive a QRDX Chain address from a public key.
    
    Uses BLAKE3 hash of the public key, taking the last 20 bytes
    to create an Ethereum-compatible address format.
    
    Args:
        public_key: The Dilithium public key
    
    Returns:
        A 20-byte Address
    
    Example:
        >>> private_key, public_key = generate_keypair()
        >>> address = derive_address(public_key)
        >>> assert len(address) == 20
    """
    return address_from_public_key(public_key.to_bytes())


def private_key_to_address(private_key: PrivateKey) -> Address:
    """
    Derive address directly from a private key (convenience function).
    
    Args:
        private_key: The Dilithium private key
    
    Returns:
        A 20-byte Address
    """
    public_key = private_key.public_key()
    return derive_address(public_key)


def sign_message(private_key: PrivateKey, message: bytes) -> bytes:
    """
    Sign a message with a private key (convenience function).
    
    Args:
        private_key: The signing private key
        message: The message to sign
    
    Returns:
        The Dilithium signature (3,293 bytes)
    """
    return private_key.sign(message)


def verify_message(public_key: PublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verify a message signature (convenience function).
    
    Args:
        public_key: The public key to verify with
        message: The message that was signed
        signature: The signature to verify
    
    Returns:
        True if signature is valid, False otherwise
    """
    return public_key.verify(message, signature)
