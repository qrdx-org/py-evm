"""
QRDX Chain - Quantum-Resistant Cryptography Module

This module provides post-quantum cryptographic primitives for QRDX Chain:
- CRYSTALS-Dilithium: Digital signatures (NIST FIPS 204)
- CRYSTALS-Kyber: Key encapsulation (NIST FIPS 203)
- BLAKE3: Quantum-resistant hashing

All implementations use NIST-standardized algorithms to ensure long-term security
against quantum computer attacks.
"""

from .dilithium import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    generate_dilithium_keypair,
    verify_dilithium_signature,
)
from .kyber import (
    KyberPrivateKey,
    KyberPublicKey,
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)
from .blake3_hash import (
    blake3_hash,
    blake3_hash_bytes,
    blake3_hash_to_address,
)
from .keys import (
    generate_keypair,
    derive_address,
    PrivateKey,
    PublicKey,
    sign_message,
    verify_message,
    private_key_to_address,
)
from .addresses import (
    address_from_public_key,
    is_valid_qrdx_address,
)

__all__ = [
    # Dilithium (signatures)
    "DilithiumPrivateKey",
    "DilithiumPublicKey",
    "generate_dilithium_keypair",
    "verify_dilithium_signature",
    # Kyber (key encapsulation)
    "KyberPrivateKey",
    "KyberPublicKey",
    "generate_kyber_keypair",
    "kyber_encapsulate",
    "kyber_decapsulate",
    # BLAKE3 (hashing)
    "blake3_hash",
    "blake3_hash_bytes",
    "blake3_hash_to_address",
    # Key management
    "generate_keypair",
    "derive_address",
    "PrivateKey",
    "PublicKey",
    "sign_message",
    "verify_message",
    "private_key_to_address",
    # Addresses
    "address_from_public_key",
    "is_valid_qrdx_address",
]
